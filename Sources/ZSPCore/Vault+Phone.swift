import Foundation

/// Approval by an MFA code from your phone, for when nobody is at the Mac.
extension Vault {
    /// A phone authenticator, added from here instead of the IAM console: AWS creates the
    /// device, the QR code from `uri` is scanned, and `confirmPhone` enables it with two codes.
    public struct PhoneDevice: Codable, Equatable, Sendable {
        public var serial: String
        public var seed: String
        /// otpauth://, what the QR code holds.
        public var uri: String

        public init(serial: String, seed: String, uri: String) {
            self.serial = serial
            self.seed = seed
            self.uri = uri
        }
    }

    public func addPhone(_ profile: String, deviceName: String) throws -> PhoneDevice {
        try guarded(profile, .mfa) {
            let master = try unlock(profile, reason: "add your phone as an MFA device for AWS profile “\(profile)”")
            try requireEnforced(profile, master)
            let session = try adminCredentials(master)
            let (user, identity) = try iamUser(session)
            try requireEnforcedInAWS(session, user: user, profile)
            let device = try aws.createVirtualMFADevice(session, name: deviceName)
            let label = "\(user)@\(identity.account) (\(profile))".addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? user
            try audit.append(.phoneCreated, profile: profile, detail: ["device": device.serial])
            return PhoneDevice(serial: device.serial, seed: device.seed,
                               uri: "otpauth://totp/AWS:\(label)?secret=\(device.seed)&issuer=AWS")
        }
    }

    /// Enables the phone with two consecutive codes from it, then turns on approval by code.
    public func confirmPhone(_ profile: String, serial: String, code1: String, code2: String) throws {
        try guarded(profile, .mfa) {
            guard TOTP.isCode(code1), TOTP.isCode(code2), code1 != code2 else {
                throw ZSPError.invalid("two different 6-digit codes, one after the other, from your authenticator app")
            }
            let master = try unlock(profile, reason: "turn on approval by your phone's code for AWS profile “\(profile)”")
            try requireEnforced(profile, master)
            let session = try adminCredentials(master)
            let (user, _) = try iamUser(session)
            try requireEnforcedInAWS(session, user: user, profile)
            try aws.enableMFADevice(session, userName: user, serial: serial, code1: code1, code2: code2)
            try keepRemoteCopy(profile, master, serial)
        }
    }

    /// Deletes a phone device that was never enabled (the QR code was not scanned after all).
    public func cancelPhone(_ profile: String, serial: String) throws {
        let (_, admin) = try unlockForIAM(profile, reason: "remove the unused phone MFA device from AWS profile “\(profile)”")
        try ignoringMissing { try aws.deleteVirtualMFADevice(admin, serial: serial) }
        try audit.append(.phoneCancelled, profile: profile, detail: ["device": serial])
    }

    func requireEnforced(_ profile: String, _ master: MasterKey) throws {
        guard meta.all()[profile]?.mfaEnforced == true, master.mfaSerial != nil else {
            throw ZSPError.invalid("Run aws-cli-zsp mfa setup and mfa enforce for \(profile) first. Without them, the copy remote approval keeps would work with no code at all.")
        }
    }

    /// profiles.json only says enforcement was turned on here; the remote copy is safe only
    /// while AWS still has the policy (nobody deleted it in the console).
    func requireEnforcedInAWS(_ session: AWSCredentials, user: String, _ profile: String) throws {
        let document = try aws.getUserPolicy(session, userName: user, policyName: Self.requireMFAPolicyName)
        guard let document, Self.demandsMFA(document) else {
            throw ZSPError.invalid("""
                IAM user \(user) does not have the \(Self.requireMFAPolicyName) policy that makes AWS demand MFA \
                (it was removed or changed in AWS). Run aws-cli-zsp mfa enforce --profile \(profile) again first.
                """)
        }
    }

    /// Whether `document` holds the statement that denies everything without MFA, as written by `mfa enforce`.
    static func demandsMFA(_ document: String) -> Bool {
        func statement(_ json: String) -> NSDictionary? {
            let doc = try? JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any]
            let statements = doc?["Statement"] as? [[String: Any]] ?? []
            return statements.first { $0["Sid"] as? String == "AwsCliZspRequireMfa" }.map { $0 as NSDictionary }
        }
        guard let found = statement(document), let wanted = statement(requireMFAPolicy) else { return false }
        return found.isEqual(wanted)
    }

    /// After a session approved by phone code: if AWS no longer demands MFA, the copy that
    /// opens without Touch ID is a working key, so it and the session are dropped.
    func confirmStillEnforced(_ profile: String, _ session: AWSCredentials, requester: String) throws {
        do {
            try requireEnforcedInAWS(session, user: try iamUser(session).user, profile)
        } catch let ZSPError.aws(code, _) where Self.deniedCodes.contains(code) {
            Log.warning("mfa", "\(profile) may not read its own policies (\(code)); approval by code goes ahead unchecked")
        } catch {
            bestEffort("drop the session of \(profile)") { try dropSession(profile) }
            bestEffort("turn off approval by code for \(profile)") { try disableRemote(profile) }
            recordFailure(.authDenied, profile: profile, detail: ["for": "approval by MFA code", "why": "MFA no longer enforced in AWS"],
                          requester: requester, error: error)
            throw error
        }
    }

    func keepRemoteCopy(_ profile: String, _ master: MasterKey, _ serial: String) throws {
        try store.write(.remote, profile, try ZSPJSON.encoder.encode(master.withoutMFASeed))
        try meta.update(profile) { $0?.remoteSerial = serial }
        try audit.append(.remoteEnabled, profile: profile, detail: ["device": serial])
    }

    /// Keeps a copy of the key that opens without Touch ID, for `approve`. It is safe only
    /// because AWS refuses that key without a code from your phone, so this needs `mfa enforce`
    /// first and an MFA device that is not this Mac's.
    public func enableRemote(_ profile: String, serial: String?) throws -> String {
        try guarded(profile, .mfa) {
            let master = try unlock(profile, reason: "let a code from your phone approve AWS profile “\(profile)” when you are away from the Mac")
            try requireEnforced(profile, master)
            let session = try adminCredentials(master)
            try requireEnforcedInAWS(session, user: try iamUser(session).user, profile)
            let devices = try aws.listMFADevices(session).filter { $0 != master.mfaSerial }
            let chosen = try choosePhone(profile, devices, serial)
            try keepRemoteCopy(profile, master, chosen)
            return chosen
        }
    }

    func choosePhone(_ profile: String, _ devices: [String], _ serial: String?) throws -> String {
        if let serial {
            guard devices.contains(serial) else { throw ZSPError.invalid("\(serial) is not an MFA device of this IAM user. Its devices: \(devices.joined(separator: ", "))") }
            return serial
        }
        switch devices.count {
        case 1: return devices[0]
        case 0: throw ZSPError.invalid("This IAM user has no MFA device besides this Mac's. Add your phone: aws-cli-zsp mfa add-phone --profile \(profile) (or Add phone… in the MFA & phone tab).")
        default: throw ZSPError.invalid("This IAM user has several MFA devices; choose one with --serial: \(devices.joined(separator: ", "))")
        }
    }

    public func disableRemote(_ profile: String) throws {
        try store.delete(.remote, profile)
        try meta.update(profile) { $0?.remoteSerial = nil }
        try audit.append(.remoteDisabled, profile: profile)
    }
}
