import Foundation

/// The last TOTP window used per MFA device. AWS accepts each code once, so two sessions inside
/// one 30-second window would see the second refused: the second waits for the next window.
struct MFACounters {
    let paths: Paths

    func load() -> [String: UInt64] {
        (try? Data(contentsOf: paths.mfaCountersFile)).flatMap { try? JSONDecoder().decode([String: UInt64].self, from: $0) } ?? [:]
    }

    func save(_ used: [String: UInt64]) throws {
        try writeAtomically(String(decoding: try JSONEncoder().encode(used), as: UTF8.self), to: paths.mfaCountersFile)
    }

    /// A window no code has been sent from yet, waiting for it when needed.
    func fresh(_ serial: String, now: () -> Date, pause: (TimeInterval) -> Void) throws -> UInt64 {
        try withFileLock(paths.lock("mfa")) {
            var used = load()
            var c = TOTP.counter(at: now())
            if let last = used[serial], c <= last {
                pause(TimeInterval(last + 1) * TOTP.period - now().timeIntervalSince1970 + 0.5)
                c = max(last + 1, TOTP.counter(at: now()))
            }
            used[serial] = c
            try save(used)
            return c
        }
    }

    /// Records codes sent some other way (the two that enable a new device).
    func markUsed(_ serial: String, through counter: UInt64) throws {
        try withFileLock(paths.lock("mfa")) {
            var used = load()
            used[serial] = counter
            try save(used)
        }
    }
}

extension Vault {
    public static let requireMFAPolicyName = "aws-cli-zsp-require-mfa"

    /// Everything except what getting an MFA session needs is denied without MFA. And since an
    /// MFA session may call IAM, the calls that would mint a new key, MFA device or policy need
    /// MFA from the last 5 minutes: zsp's own 15-minute admin sessions are used at once, while
    /// an hour-long CLI session that leaked cannot make itself permanent.
    public static let requireMFAPolicy = "{\"Version\":\"2012-10-17\",\"Statement\":["
        + "{\"Sid\":\"AwsCliZspRequireMfa\",\"Effect\":\"Deny\",\"NotAction\":[\"sts:GetSessionToken\",\"sts:GetCallerIdentity\"],\"Resource\":\"*\",\"Condition\":{\"BoolIfExists\":{\"aws:MultiFactorAuthPresent\":\"false\"}}},"
        + "{\"Sid\":\"AwsCliZspFreshMfaForCredentials\",\"Effect\":\"Deny\",\"Action\":[" + selfManagementActions.map { "\"\($0)\"" }.joined(separator: ",")
        + "],\"Resource\":\"*\",\"Condition\":{\"NumericGreaterThanIfExists\":{\"aws:MultiFactorAuthAge\":\"300\"}}}]}"

    static let selfManagementActions = [
        "iam:CreateAccessKey", "iam:UpdateAccessKey", "iam:DeleteAccessKey",
        "iam:CreateVirtualMFADevice", "iam:EnableMFADevice", "iam:DeactivateMFADevice", "iam:DeleteVirtualMFADevice", "iam:ResyncMFADevice",
        "iam:PutUserPolicy", "iam:DeleteUserPolicy", "iam:AttachUserPolicy", "iam:DetachUserPolicy",
        "iam:CreateLoginProfile", "iam:UpdateLoginProfile",
    ]

    var mfaCounters: MFACounters { MFACounters(paths: paths) }

    /// A code from this Mac's own MFA device, when the key has one.
    func ownMFACode(_ master: MasterKey) throws -> MFACode? {
        guard let serial = master.mfaSerial, let seed = master.mfaSeed else { return nil }
        guard let secret = TOTP.base32Decode(seed) else { throw ZSPError.invalid("the MFA seed for \(serial) is damaged; run aws-cli-zsp mfa setup again") }
        return MFACode(serial: serial, code: TOTP.code(secret: secret, counter: try mfaCounters.fresh(serial, now: now, pause: pause)))
    }

    /// What IAM calls are made with: the key itself, or, once it has an MFA device here, a
    /// short MFA session (which IAM requires once `mfa enforce` has run).
    func adminCredentials(_ master: MasterKey) throws -> AWSCredentials {
        guard let mfa = try ownMFACode(master) else { return master.credentials }
        return try aws.getSessionToken(master.credentials, durationSeconds: 900, mfa: mfa)
    }

    /// The key after Touch ID, and what to call IAM with: the steps every IAM change starts with.
    func unlockForIAM(_ profile: String, reason: String) throws -> (master: MasterKey, admin: AWSCredentials) {
        let master = try unlock(profile, reason: reason)
        return (master, try adminCredentials(master))
    }

    func iamUser(_ c: AWSCredentials) throws -> (user: String, identity: CallerIdentity) {
        let identity = try aws.getCallerIdentity(c)
        guard let user = Self.userName(fromArn: identity.arn) else {
            throw ZSPError.invalid("\(identity.arn) is not an IAM user, so it has no MFA devices or user policies")
        }
        return (user, identity)
    }

    func requireLongLived(_ master: MasterKey, _ profile: String, _ why: String) throws {
        guard master.sessionToken == nil else { throw ZSPError.invalid("“\(profile)” holds temporary credentials: \(why)") }
    }

    /// Gives this Mac its own virtual MFA device for the key's IAM user. Its seed is sealed with
    /// the key, so local use stays one Touch ID while every session carries MFA.
    public func setupMFA(_ profile: String, deviceName: String) throws -> String {
        try guarded(profile, .mfa) {
            let master = try unlock(profile, reason: "add an MFA device for this Mac to AWS profile “\(profile)”")
            try requireLongLived(master, profile, "there is no IAM user to add MFA to")
            // Setting up again once MFA is enforced needs the current device's MFA session.
            let c = try adminCredentials(master)
            let (user, identity) = try iamUser(c)
            let device = try aws.createVirtualMFADevice(c, name: deviceName)
            guard let secret = TOTP.base32Decode(device.seed) else { throw ZSPError.aws(code: "BadResponse", message: "the MFA seed is not base32") }
            let c1 = TOTP.counter(at: now())
            do {
                try aws.enableMFADevice(c, userName: user, serial: device.serial,
                                        code1: TOTP.code(secret: secret, counter: c1), code2: TOTP.code(secret: secret, counter: c1 + 1))
            } catch {
                bestEffort("delete the MFA device that did not enable") { try aws.deleteVirtualMFADevice(c, serial: device.serial) }
                throw error
            }
            var updated = master
            updated.mfaSerial = device.serial
            updated.mfaSeed = device.seed
            try writeMaster(updated, profile)
            // Both codes are spent: the first session waits for the window after them.
            try mfaCounters.markUsed(device.serial, through: c1 + 1)
            try dropSession(profile)
            try meta.update(profile) { $0?.mfaSerial = device.serial; $0?.account = identity.account; $0?.arn = identity.arn }
            try audit.append(.mfaSetup, profile: profile, detail: ["device": device.serial, "user": user])
            return device.serial
        }
    }

    /// Attaches a policy that refuses everything the key does without MFA, so the key alone,
    /// copied or stolen, is worth nothing. Checked first: an MFA session from this Mac must work.
    public func enforceMFA(_ profile: String) throws {
        try guarded(profile, .mfa) {
            let master = try unlock(profile, reason: "make AWS refuse the “\(profile)” key without MFA")
            guard master.mfaSeed != nil else {
                throw ZSPError.invalid("Run aws-cli-zsp mfa setup --profile \(profile) first: without an MFA device on this Mac, enforcing MFA would lock this Mac out")
            }
            let session = try adminCredentials(master)
            let (user, _) = try iamUser(session)
            try aws.putUserPolicy(session, userName: user, policyName: Self.requireMFAPolicyName, document: Self.requireMFAPolicy)
            try dropSession(profile)
            try meta.update(profile) { $0?.mfaEnforced = true }
            try audit.append(.mfaEnforced, profile: profile, detail: ["user": user, "policy": Self.requireMFAPolicyName])
        }
    }

    /// Undoes `mfa enforce`: the key works without MFA again, everywhere. Phone approval goes
    /// with it, because its copy of the key is safe only while AWS demands a code.
    public func unenforceMFA(_ profile: String) throws {
        let (master, admin) = try unlockForIAM(profile, reason: "let the “\(profile)” key work without MFA again")
        try removeEnforcement(profile, master, admin)
    }

    func removeEnforcement(_ profile: String, _ master: MasterKey, _ session: AWSCredentials) throws {
        let (user, _) = try iamUser(session)
        do {
            try ignoringMissing { try aws.deleteUserPolicy(session, userName: user, policyName: Self.requireMFAPolicyName) }
        } catch {
            throw ZSPError.invalid("AWS refused to remove \(Self.requireMFAPolicyName) (\(error.localizedDescription)). "
                + "Delete that inline policy from IAM user \(user) in the IAM console instead.")
        }
        if meta.all()[profile]?.remoteSerial != nil { try disableRemote(profile) }
        try dropSession(profile)
        try meta.update(profile) { $0?.mfaEnforced = nil }
        try audit.append(.mfaUnenforced, profile: profile, detail: ["user": user, "policy": Self.requireMFAPolicyName])
    }

    /// Undoes `mfa setup`, and enforcement first if it is on (from the MFA session, while this
    /// Mac's device still exists): this Mac stops being an MFA device for the key's IAM user.
    public func removeMFA(_ profile: String) throws {
        let master = try unlock(profile, reason: "remove this Mac's MFA device from AWS profile “\(profile)”")
        guard let serial = master.mfaSerial else {
            try meta.update(profile) { $0?.mfaSerial = nil; $0?.mfaEnforced = nil }
            return
        }
        let session = try adminCredentials(master)
        if meta.all()[profile]?.mfaEnforced == true { try removeEnforcement(profile, master, session) }
        let (user, _) = try iamUser(session)
        try ignoringMissing { try aws.deactivateMFADevice(session, userName: user, serial: serial) }
        try ignoringMissing { try aws.deleteVirtualMFADevice(session, serial: serial) }
        var updated = master
        updated.mfaSerial = nil
        updated.mfaSeed = nil
        try writeMaster(updated, profile)
        try dropSession(profile)
        try meta.update(profile) { $0?.mfaSerial = nil; $0?.mfaEnforced = nil }
        try audit.append(.mfaRemoved, profile: profile, detail: ["device": serial, "user": user])
    }

    /// An IAM delete whose target is already gone (removed in the console) has nothing left to do.
    func ignoringMissing(_ body: () throws -> Void) throws {
        do { try body() } catch ZSPError.aws(code: "NoSuchEntity", _) {
            Log.info("iam", "already gone in AWS (NoSuchEntity)")
        }
    }
}
