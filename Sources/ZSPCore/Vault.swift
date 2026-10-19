import Foundation

/// A plaintext key found in an AWS file.
public struct Finding: Codable, Equatable, Sendable {
    public var file: String
    public var profile: String
    public var accessKeyId: String
    /// Both the key id and the secret are there. An incomplete pair is mid-write
    /// (`aws configure set` writes one line at a time) and is picked up on the next pass.
    public var complete: Bool
}

public struct ImportReport: Codable, Equatable, Sendable {
    public var imported: [String] = []
    public var replaced: [String] = []
    public var incomplete: [Finding] = []

    public init() {}
}

public struct RotateResult: Codable, Equatable, Sendable {
    public var profile: String
    public var oldKeyId: String
    public var newKeyId: String
    public var oldKey: String
}

public struct KeyReport: Codable, Equatable, Sendable {
    public var accessKeyId: String
    public var status: String
    public var createDate: Date?
    public var lastUsed: AccessKeyLastUsed?
    public var thisProfile: Bool
}

public struct InspectReport: Codable, Equatable, Sendable {
    public var profile: String
    public var identity: CallerIdentity
    public var keys: [KeyReport]
}

/// Reads the AWS files for plaintext keys. Needs no Keychain access, so the menu bar app
/// runs it itself.
public enum Scanner {
    public static func scan(_ paths: Paths) -> [Finding] {
        var out: [Finding] = []
        for (url, isConfig) in [(paths.configFile, true), (paths.credentialsFile, false)] {
            guard let text = try? String(contentsOf: url, encoding: .utf8) else { continue }
            let doc = INIDocument(text)
            for s in doc.sectionNames {
                guard let profile = isConfig ? AWSFiles.profileName(configSection: s) : s else { continue }
                let id = doc.value("aws_access_key_id", in: s) ?? ""
                let secret = doc.value("aws_secret_access_key", in: s) ?? ""
                let token = doc.value("aws_session_token", in: s) ?? doc.value("aws_security_token", in: s) ?? ""
                if id.isEmpty && secret.isEmpty && token.isEmpty { continue }
                out.append(Finding(file: url.path, profile: profile, accessKeyId: id, complete: !id.isEmpty && !secret.isEmpty))
            }
        }
        return out
    }
}

public final class Vault {
    public static let revokePolicyName = "aws-cli-zsp-revoke-older-sessions"

    public let paths: Paths
    let store: SecretStore
    let auth: UserPresence
    let aws: AWSService
    public let audit: AuditLog
    public let meta: MetadataStore
    /// The zsp binary that credential_process lines point at.
    public let commandPath: String
    var now: () -> Date = Date.init
    var pause: (TimeInterval) -> Void = { Thread.sleep(forTimeInterval: $0) }
    /// Whether someone is at the Mac to answer Touch ID. When nobody is (the screen is locked,
    /// or no keyboard or mouse for a while, as under Claude Code Remote Control), a new session
    /// fails at once with what to do instead, rather than waiting on a prompt nobody can see.
    public var someoneAtMac: () -> Bool = { true }

    public init(paths: Paths, store: SecretStore, auth: UserPresence, aws: AWSService, commandPath: String) {
        self.paths = paths
        self.store = store
        self.auth = auth
        self.aws = aws
        self.commandPath = commandPath
        self.audit = AuditLog(paths: paths, anchor: store)
        self.meta = MetadataStore(paths: paths)
    }

    public func credentialProcess(for profile: String) -> String {
        "\(shellQuote(commandPath)) credential-process --profile \(shellQuote(profile))"
    }

    func isOurs(_ credentialProcess: String) -> Bool {
        credentialProcess.contains(" credential-process --profile ") && credentialProcess.lowercased().contains("zsp")
    }

    // MARK: Moving keys in

    /// Moves every complete key pair out of both AWS files into the Keychain and points the
    /// profile at zsp. The Keychain write is read back before a line is removed from a file,
    /// so a failure leaves the key where it was, never nowhere.
    /// `only` limits the move to those profiles; `skip` leaves those where they are.
    public func importPlaintext(origin: String, only: Set<String>? = nil, skip: Set<String> = []) throws -> ImportReport {
        try paths.ensureSupportDir()
        return try withFileLock(paths.lock("import")) {
            var report = ImportReport()
            let credsText = (try? String(contentsOf: paths.credentialsFile, encoding: .utf8)) ?? ""
            let configText = (try? String(contentsOf: paths.configFile, encoding: .utf8)) ?? ""
            var creds = INIDocument(credsText)
            var config = INIDocument(configText)

            // Config first: when both files hold a key, the credentials file wins in the AWS
            // CLI, so it must win here too.
            let wanted: (String) -> Bool = { p in !skip.contains(p) && (only?.contains(p) ?? true) }
            let fromConfig = try extract(&config, isConfig: true, file: paths.configFile, origin: origin, wanted: wanted, report: &report)
            let fromCreds = try extract(&creds, isConfig: false, file: paths.credentialsFile, origin: origin, wanted: wanted, report: &report)
            for profile in fromConfig + fromCreds {
                config.set("credential_process", credentialProcess(for: profile), in: AWSFiles.configSection(for: profile))
            }
            if config.text != configText {
                try writeAtomically(config.text, to: paths.configFile)
            }
            if creds.text != credsText {
                if !creds.text.contains(AWSFiles.managedMarker) {
                    creds.prepend(comments: [
                        "\(AWSFiles.managedMarker): access keys written here are moved into the Secure Enclave vault within seconds.",
                        "# Add keys with `aws-cli-zsp add --profile NAME` (or keep using `aws configure`); see `aws-cli-zsp list`.",
                    ])
                }
                try writeAtomically(creds.text, to: paths.credentialsFile)
            }
            return report
        }
    }

    func extract(_ doc: inout INIDocument, isConfig: Bool, file: URL, origin: String, wanted: (String) -> Bool,
                 report: inout ImportReport) throws -> [String] {
        var moved: [String] = []
        for section in doc.sectionNames {
            guard let profile = isConfig ? AWSFiles.profileName(configSection: section) : section, wanted(profile) else { continue }
            let id = doc.value("aws_access_key_id", in: section) ?? ""
            let secret = doc.value("aws_secret_access_key", in: section) ?? ""
            let token = doc.value("aws_session_token", in: section) ?? doc.value("aws_security_token", in: section) ?? ""
            if id.isEmpty && secret.isEmpty && token.isEmpty { continue }
            guard !id.isEmpty, !secret.isEmpty else {
                report.incomplete.append(Finding(file: file.path, profile: profile, accessKeyId: id, complete: false))
                continue
            }
            let replaced = try adopt(MasterKey(accessKeyId: id, secretAccessKey: secret, sessionToken: token.isEmpty ? nil : token,
                                               importedAt: now(), source: file.lastPathComponent),
                                     profile: profile, event: "key.imported", origin: origin)
            doc.remove(keys: AWSFiles.secretKeys, in: section)
            if !isConfig { doc.removeHeaderIfEmpty(section) }
            moved.append(profile)
            report.imported.append(profile)
            if replaced { report.replaced.append(profile) }
        }
        return moved
    }

    /// Stores a key for `profile`, verified by reading it back. Returns whether it replaced a
    /// different key.
    @discardableResult
    func adopt(_ key: MasterKey, profile: String, event: String, origin: String) throws -> Bool {
        let previous = meta.all()[profile]
        let changed = previous.map { $0.accessKeyId != key.accessKeyId } ?? false
        // The same key again (pasted twice) keeps the sealed copy, and with it this Mac's MFA
        // seed. A different key drops the MFA set-up and the remote copy: they belonged to the old one.
        if changed || previous == nil || !hasMaster(profile) { try store.write(.master, profile, try ZSPJSON.encoder.encode(key)) }
        if changed {
            try store.delete(.remote, profile)
        }
        if changed || previous == nil { try store.delete(.session, profile) }
        try meta.update(profile) { m in
            var e = m ?? ProfileMeta(profile: profile, accessKeyId: key.accessKeyId, importedAt: key.importedAt,
                                     source: key.source, temporary: key.sessionToken != nil)
            if changed {
                e = ProfileMeta(profile: profile, accessKeyId: key.accessKeyId, importedAt: key.importedAt, source: key.source,
                                temporary: key.sessionToken != nil, previousKeyId: previous?.accessKeyId)
            }
            e.importedAt = key.importedAt
            e.source = key.source
            e.temporary = key.sessionToken != nil
            if changed || previous == nil { e.sessionExpiresAt = nil }
            if changed { e.mfaSerial = nil; e.mfaEnforced = nil; e.remoteSerial = nil }
            m = e
        }
        var detail = ["keyId": maskKeyId(key.accessKeyId), "from": key.source, "by": origin]
        if changed, let p = previous { detail["replaced"] = maskKeyId(p.accessKeyId) }
        if key.sessionToken != nil { detail["temporary"] = "true" }
        try audit.append(event, profile: profile, detail: detail)
        return changed
    }

    func writeMaster(_ key: MasterKey, _ profile: String) throws {
        // The store confirms the write itself (the enclave store reads its sealed file back):
        // decrypting it here would cost a Touch ID prompt for every key moved in.
        try store.write(.master, profile, try ZSPJSON.encoder.encode(key))
        // Remote approval keeps its copy in step (a rotation, a new MFA device).
        if (try? store.accounts(.remote).contains(profile)) == true {
            try store.write(.remote, profile, try ZSPJSON.encoder.encode(key.withoutMFASeed))
        }
    }

    /// Stores a key exactly as an older store held it (the migration from 0.1.x).
    public func hasMaster(_ profile: String) -> Bool {
        (try? store.accounts(.master).contains(profile)) ?? false
    }

    public func storeMaster(raw: Data, profile: String) throws {
        _ = try ZSPJSON.decoder.decode(MasterKey.self, from: raw)
        try store.write(.master, profile, raw)
    }

    /// Adds a key typed at the prompt, so it never touches a file at all.
    public func add(profile: String, accessKeyId: String, secretAccessKey: String, sessionToken: String? = nil) throws {
        try withFileLock(paths.lock("import")) {
            try adopt(MasterKey(accessKeyId: accessKeyId, secretAccessKey: secretAccessKey, sessionToken: sessionToken,
                                importedAt: now(), source: "aws-cli-zsp add"),
                      profile: profile, event: "key.added", origin: "aws-cli-zsp add")
            let text = (try? String(contentsOf: paths.configFile, encoding: .utf8)) ?? ""
            var config = INIDocument(text)
            config.set("credential_process", credentialProcess(for: profile), in: AWSFiles.configSection(for: profile))
            if config.text != text { try writeAtomically(config.text, to: paths.configFile) }
        }
    }

    // MARK: Handing out sessions

    /// What credential_process returns. A cached session is served without a prompt while it
    /// has five minutes left; otherwise Touch ID unlocks the long-lived key for one
    /// GetSessionToken call and the key goes straight back out of memory.
    /// `asker` is the short "who wants it" for the Touch ID dialog; `requester` is the full chain
    /// the audit log keeps.
    public func credentials(for profile: String, requester: String, asker: String? = nil) throws -> AWSCredentials {
        try paths.ensureSupportDir()
        return try withFileLock(paths.lock("session-\(profile)")) {
            let t = now()
            if let data = try store.read(.session, profile),
               let s = try? ZSPJSON.decoder.decode(AWSCredentials.self, from: data),
               let exp = s.expiration, exp > t.addingTimeInterval(300) {
                try audit.append("session.served", profile: profile, detail: ["expires": iso8601(exp)], requester: requester)
                try? meta.update(profile) { $0?.lastUsedAt = t; $0?.lastRequester = requester; $0?.sessionExpiresAt = exp }
                return s
            }
            let seconds = Settings.load(paths).duration(for: profile)
            guard someoneAtMac() else {
                _ = try? audit.append("session.away", profile: profile, ok: false, requester: requester)
                throw awayError(profile)
            }
            let reason = "unlock your “\(profile)” AWS key for a \(durationText(seconds)) session, for \(asker ?? requester)"
            let master = try unlock(profile, reason: reason, requester: requester)
            if master.sessionToken != nil {
                try audit.append("session.served", profile: profile, detail: ["temporary": "true"], requester: requester)
                try? meta.update(profile) { $0?.lastUsedAt = t; $0?.lastRequester = requester }
                return master.credentials
            }
            return try issue(profile, master, seconds: seconds, mfa: try ownMFACode(master), approvedBy: "touch-id",
                             requester: requester)
        }
    }

    /// GetSessionToken, then the session is sealed, logged and remembered.
    func issue(_ profile: String, _ master: MasterKey, seconds: Int, mfa: MFACode?, approvedBy: String,
               requester: String) throws -> AWSCredentials {
        let session: AWSCredentials
        do {
            session = try aws.getSessionToken(master.credentials, durationSeconds: seconds, mfa: mfa)
        } catch {
            _ = try? audit.append("session.failed", profile: profile, ok: false, detail: ["error": error.localizedDescription],
                              requester: requester)
            throw error
        }
        try store.write(.session, profile, try ZSPJSON.encoder.encode(session))
        var detail = ["keyId": maskKeyId(master.accessKeyId), "seconds": String(seconds),
                      "expires": session.expiration.map(iso8601) ?? "?", "approved": approvedBy]
        if let mfa { detail["mfa"] = mfa.serial.split(separator: "/").last.map(String.init) ?? mfa.serial }
        try audit.append("session.issued", profile: profile, detail: detail, requester: requester)
        try? meta.update(profile) {
            $0?.lastUsedAt = self.now()
            $0?.lastRequester = requester
            $0?.sessionExpiresAt = session.expiration
        }
        return session
    }

    func awayError(_ profile: String) -> ZSPError {
        let m = meta.all()[profile]
        if m?.remoteSerial != nil {
            return .auth("Nobody is at the Mac to approve Touch ID for AWS profile “\(profile)”. "
                + "Ask the user for the 6-digit code from their MFA app, then run: aws-cli-zsp approve --profile \(profile) CODE "
                + "(and retry). Or approve at the Mac and retry.")
        }
        return .auth("Nobody is at the Mac to approve Touch ID for AWS profile “\(profile)”, and approval by MFA code is not set up "
            + "for it. Approve at the Mac and retry; to approve from a phone next time, run at the Mac: "
            + "aws-cli-zsp remote enable --profile \(profile)")
    }

    // MARK: MFA

    public static let requireMFAPolicyName = "aws-cli-zsp-require-mfa"

    /// A code from this Mac's own MFA device, when the key has one.
    func ownMFACode(_ master: MasterKey) throws -> MFACode? {
        guard let serial = master.mfaSerial, let seed = master.mfaSeed else { return nil }
        guard let secret = TOTP.base32Decode(seed) else { throw ZSPError.invalid("the MFA seed for \(serial) is damaged; run aws-cli-zsp mfa setup again") }
        return MFACode(serial: serial, code: TOTP.code(secret: secret, counter: try freshCounter(serial)))
    }

    /// AWS accepts each code once, so two sessions inside one 30-second window would see the
    /// second refused: the second waits for the next window.
    func freshCounter(_ serial: String) throws -> UInt64 {
        let file = paths.supportDir.appendingPathComponent("mfa-counters.json")
        return try withFileLock(paths.lock("mfa")) {
            var used = (try? Data(contentsOf: file)).flatMap { try? JSONDecoder().decode([String: UInt64].self, from: $0) } ?? [:]
            var c = TOTP.counter(at: now())
            if let last = used[serial], c <= last {
                pause(TimeInterval(last + 1) * TOTP.period - now().timeIntervalSince1970 + 0.5)
                c = max(last + 1, TOTP.counter(at: now()))
            }
            used[serial] = c
            try writeAtomically(String(decoding: try JSONEncoder().encode(used), as: UTF8.self), to: file)
            return c
        }
    }

    /// What IAM calls are made with: the key itself, or, once it has an MFA device here, a
    /// short MFA session (which IAM requires once `mfa enforce` has run).
    func adminCredentials(_ master: MasterKey) throws -> AWSCredentials {
        guard let mfa = try ownMFACode(master) else { return master.credentials }
        return try aws.getSessionToken(master.credentials, durationSeconds: 900, mfa: mfa)
    }

    func iamUser(_ c: AWSCredentials) throws -> (user: String, identity: CallerIdentity) {
        let identity = try aws.getCallerIdentity(c)
        guard let user = Self.userName(fromArn: identity.arn) else {
            throw ZSPError.invalid("\(identity.arn) is not an IAM user, so it has no MFA devices or user policies")
        }
        return (user, identity)
    }

    /// Gives this Mac its own virtual MFA device for the key's IAM user. Its seed is sealed with
    /// the key, so local use stays one Touch ID while every session carries MFA.
    public func setupMFA(_ profile: String, deviceName: String) throws -> String {
        let master = try unlock(profile, reason: "add an MFA device for this Mac to AWS profile “\(profile)”")
        guard master.sessionToken == nil else { throw ZSPError.invalid("“\(profile)” holds temporary credentials: there is no IAM user to add MFA to") }
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
            try? aws.deleteVirtualMFADevice(c, serial: device.serial)
            throw error
        }
        var updated = master
        updated.mfaSerial = device.serial
        updated.mfaSeed = device.seed
        try writeMaster(updated, profile)
        // Both codes are spent: the first session waits for the window after them.
        let file = paths.supportDir.appendingPathComponent("mfa-counters.json")
        try withFileLock(paths.lock("mfa")) {
            var used = (try? Data(contentsOf: file)).flatMap { try? JSONDecoder().decode([String: UInt64].self, from: $0) } ?? [:]
            used[device.serial] = c1 + 1
            try writeAtomically(String(decoding: try JSONEncoder().encode(used), as: UTF8.self), to: file)
        }
        try store.delete(.session, profile)
        try meta.update(profile) { $0?.mfaSerial = device.serial; $0?.account = identity.account; $0?.arn = identity.arn; $0?.sessionExpiresAt = nil }
        try audit.append("mfa.setup", profile: profile, detail: ["device": device.serial, "user": user])
        return device.serial
    }

    /// Attaches a policy that refuses everything the key does without MFA, so the key alone,
    /// copied or stolen, is worth nothing. Checked first: an MFA session from this Mac must work.
    public func enforceMFA(_ profile: String) throws {
        let master = try unlock(profile, reason: "make AWS refuse the “\(profile)” key without MFA")
        guard master.mfaSeed != nil else {
            throw ZSPError.invalid("Run aws-cli-zsp mfa setup --profile \(profile) first: without an MFA device on this Mac, enforcing MFA would lock this Mac out")
        }
        let session = try adminCredentials(master)
        let (user, _) = try iamUser(session)
        try aws.putUserPolicy(session, userName: user, policyName: Self.requireMFAPolicyName, document: Self.requireMFAPolicy)
        try store.delete(.session, profile)
        try meta.update(profile) { $0?.mfaEnforced = true; $0?.sessionExpiresAt = nil }
        try audit.append("mfa.enforced", profile: profile, detail: ["user": user, "policy": Self.requireMFAPolicyName])
    }

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

    // MARK: Approval by MFA code, for when nobody is at the Mac

    /// Keeps a copy of the key that opens without Touch ID, for `approve`. It is safe only
    /// because AWS refuses that key without a code from your phone, so this needs `mfa enforce`
    /// first and an MFA device that is not this Mac's.
    public func enableRemote(_ profile: String, serial: String?) throws -> String {
        let master = try unlock(profile, reason: "let a code from your phone approve AWS profile “\(profile)” when you are away from the Mac")
        guard meta.all()[profile]?.mfaEnforced == true, master.mfaSerial != nil else {
            throw ZSPError.invalid("Run aws-cli-zsp mfa setup and mfa enforce for \(profile) first. Without them, the copy remote approval keeps would work with no code at all.")
        }
        let session = try adminCredentials(master)
        let devices = try aws.listMFADevices(session).filter { $0 != master.mfaSerial }
        let chosen: String
        if let serial {
            guard devices.contains(serial) else { throw ZSPError.invalid("\(serial) is not an MFA device of this IAM user. Its devices: \(devices.joined(separator: ", "))") }
            chosen = serial
        } else if devices.count == 1 {
            chosen = devices[0]
        } else if devices.isEmpty {
            throw ZSPError.invalid("This IAM user has no MFA device besides this Mac's. Add your phone in the IAM console (Security credentials, Assign MFA device), then run this again.")
        } else {
            throw ZSPError.invalid("This IAM user has several MFA devices; choose one with --serial: \(devices.joined(separator: ", "))")
        }
        try store.write(.remote, profile, try ZSPJSON.encoder.encode(master.withoutMFASeed))
        try meta.update(profile) { $0?.remoteSerial = chosen }
        try audit.append("remote.enabled", profile: profile, detail: ["device": chosen])
        return chosen
    }

    public func disableRemote(_ profile: String) throws {
        try store.delete(.remote, profile)
        try meta.update(profile) { $0?.remoteSerial = nil }
        try audit.append("remote.disabled", profile: profile)
    }

    /// Issues a session approved by a code from your phone, with no Touch ID: what Claude Code
    /// runs over Remote Control after asking you for the code. AWS checks the code.
    public func approve(_ profile: String, code: String, requester: String) throws -> AWSCredentials {
        guard TOTP.isCode(code) else { throw ZSPError.invalid("an MFA code is 6 digits") }
        guard let serial = meta.all()[profile]?.remoteSerial, let data = try store.read(.remote, profile) else {
            throw ZSPError.invalid("Approval by MFA code is not set up for “\(profile)”. At the Mac: aws-cli-zsp remote enable --profile \(profile)")
        }
        let key = try ZSPJSON.decoder.decode(MasterKey.self, from: data)
        try paths.ensureSupportDir()
        return try withFileLock(paths.lock("session-\(profile)")) {
            do {
                return try issue(profile, key, seconds: Settings.load(paths).duration(for: profile),
                                 mfa: MFACode(serial: serial, code: code), approvedBy: "mfa-code", requester: requester)
            } catch {
                _ = try? audit.append("auth.denied", profile: profile, ok: false, detail: ["for": "approval by MFA code"], requester: requester)
                throw error
            }
        }
    }

    /// The long-lived key, after the person at the Mac has approved `reason`.
    func unlock(_ profile: String, reason: String, requester: String? = nil) throws -> MasterKey {
        guard try store.accounts(.master).contains(profile) else {
            throw ZSPError.notFound("No key for profile “\(profile)” in the vault. Add one with: aws-cli-zsp add --profile \(profile)")
        }
        do {
            try auth.confirm(reason)
        } catch {
            _ = try? audit.append("auth.denied", profile: profile, ok: false, detail: ["for": reason], requester: requester)
            throw error
        }
        let data: Data?
        do {
            data = try store.read(.master, profile)
        } catch {
            _ = try? audit.append("auth.denied", profile: profile, ok: false, detail: ["for": reason], requester: requester)
            throw error
        }
        guard let data else { throw ZSPError.notFound("The key for “\(profile)” vanished from the Keychain") }
        return try ZSPJSON.decoder.decode(MasterKey.self, from: data)
    }

    // MARK: What is in use

    public func list() -> [ProfileMeta] {
        Self.statuses(meta: meta.all(), keychain: (try? store.accounts(.master)).map(Set.init))
    }

    /// Profiles known to zsp. `keychain` is nil for a reader that cannot ask the Keychain.
    public static func statuses(meta: [String: ProfileMeta], keychain: Set<String>?) -> [ProfileMeta] {
        let names = Set(meta.keys).union(keychain ?? [])
        return names.sorted().map { name in
            var m = meta[name] ?? ProfileMeta(profile: name, accessKeyId: "?", importedAt: .distantPast, source: "?", temporary: false)
            m.inKeychain = keychain.map { $0.contains(name) }
            return m
        }
    }

    /// Who the key belongs to and when AWS last saw each of the user's keys used: the way to
    /// tell whether a leaked key was used by someone else.
    public func inspect(_ profile: String) throws -> InspectReport {
        let master = try unlock(profile, reason: "look up the AWS key for profile “\(profile)”")
        let c = try adminCredentials(master)
        let identity = try aws.getCallerIdentity(c)
        var keys: [KeyReport] = []
        if master.sessionToken == nil {
            for k in try aws.listAccessKeys(c) {
                keys.append(KeyReport(accessKeyId: k.accessKeyId, status: k.status, createDate: k.createDate,
                                      lastUsed: try? aws.getAccessKeyLastUsed(c, keyId: k.accessKeyId),
                                      thisProfile: k.accessKeyId == master.accessKeyId))
            }
        }
        let status = keys.first { $0.thisProfile }?.status
        try? meta.update(profile) {
            $0?.account = identity.account
            $0?.arn = identity.arn
            if let status { $0?.keyStatus = status }
        }
        try audit.append("key.inspected", profile: profile, detail: ["arn": identity.arn, "keys": String(keys.count)])
        return InspectReport(profile: profile, identity: identity, keys: keys)
    }

    // MARK: Rotate and revoke

    /// Creates a new key, stores it, waits for AWS to accept it, then deletes (or with
    /// `keepOld`, deactivates) the old one.
    public func rotate(_ profile: String, keepOld: Bool = false) throws -> RotateResult {
        let master = try unlock(profile, reason: "rotate the AWS access key for profile “\(profile)”")
        guard master.sessionToken == nil else { throw ZSPError.invalid("“\(profile)” holds temporary credentials: there is no key to rotate") }
        let old = master.credentials
        // IAM calls go through an MFA session when the key has MFA here: required once MFA is enforced.
        let admin = try adminCredentials(master)
        let keys = try aws.listAccessKeys(admin)
        if keys.count >= 2 {
            let other = keys.first { $0.accessKeyId != old.accessKeyId }.map { maskKeyId($0.accessKeyId) } ?? "another key"
            throw ZSPError.invalid("This IAM user already has two access keys (the other is \(other)). AWS allows two at most: delete the one you no longer use, then rotate again.")
        }
        let fresh = try aws.createAccessKey(admin)
        // Stored before anything else happens: the new secret is never only in memory. The
        // MFA device belongs to the user, not the key, so it carries over.
        try writeMaster(MasterKey(accessKeyId: fresh.accessKeyId, secretAccessKey: fresh.secretAccessKey, sessionToken: nil,
                                  importedAt: now(), source: "rotated", mfaSerial: master.mfaSerial, mfaSeed: master.mfaSeed), profile)
        _ = try? audit.append("key.created", profile: profile, detail: ["keyId": maskKeyId(fresh.accessKeyId)])
        try meta.update(profile) {
            $0?.previousKeyId = old.accessKeyId
            $0?.accessKeyId = fresh.accessKeyId
            $0?.source = "rotated"
            $0?.temporary = false
        }
        do {
            _ = try retryingNewKey { try aws.getCallerIdentity(fresh) }
            // Without MFA the new key retires the old one; with it, the MFA session from the old key
            // does (the new key alone is refused once MFA is enforced).
            let retirer = master.mfaSeed == nil ? fresh : admin
            try retryingNewKey {
                if keepOld { try aws.updateAccessKey(retirer, keyId: old.accessKeyId, active: false) }
                else { try aws.deleteAccessKey(retirer, keyId: old.accessKeyId) }
            }
        } catch {
            _ = try? audit.append("key.rotate.failed", profile: profile, ok: false,
                              detail: ["old": maskKeyId(old.accessKeyId), "new": maskKeyId(fresh.accessKeyId), "error": error.localizedDescription])
            throw ZSPError.aws(code: "RotateIncomplete", message: "The new key \(maskKeyId(fresh.accessKeyId)) is stored and in use, but the old key \(maskKeyId(old.accessKeyId)) could not be retired (\(error.localizedDescription)). Delete it in the IAM console.")
        }
        try store.delete(.session, profile)
        let t = now()
        try meta.update(profile) {
            $0?.rotatedAt = t
            $0?.importedAt = t
            $0?.sessionExpiresAt = nil
            $0?.keyStatus = "Active"
        }
        let action = keepOld ? "deactivated" : "deleted"
        try audit.append("key.rotated", profile: profile,
                         detail: ["old": maskKeyId(old.accessKeyId), "new": maskKeyId(fresh.accessKeyId), "oldKey": action])
        return RotateResult(profile: profile, oldKeyId: old.accessKeyId, newKeyId: fresh.accessKeyId, oldKey: action)
    }

    /// A new IAM key takes a few seconds to be accepted everywhere.
    func retryingNewKey<T>(_ body: () throws -> T) throws -> T {
        var attempt = 0
        while true {
            do { return try body() } catch let ZSPError.aws(code, _) where code == "InvalidClientTokenId" && attempt < 15 {
                attempt += 1
                pause(2)
            }
        }
    }

    /// Cuts off every session issued from this key until now, including any a thief minted,
    /// by attaching a deny-all policy conditioned on aws:TokenIssueTime. The long-lived key
    /// keeps working and new sessions are unaffected.
    public func revokeSessions(_ profile: String) throws -> Date {
        let master = try unlock(profile, reason: "revoke every session issued for AWS profile “\(profile)”")
        guard master.sessionToken == nil else { throw ZSPError.invalid("“\(profile)” holds temporary credentials: they cannot revoke themselves") }
        let admin = try adminCredentials(master)
        let identity = try aws.getCallerIdentity(admin)
        guard let user = Self.userName(fromArn: identity.arn) else {
            throw ZSPError.invalid("\(identity.arn) is not an IAM user, so its sessions cannot be revoked with a user policy")
        }
        // The MFA session above is cut off with the rest; this is its last call.
        let cutoff = now()
        try aws.putUserPolicy(admin, userName: user, policyName: Self.revokePolicyName, document: Self.revokePolicy(before: cutoff))
        try store.delete(.session, profile)
        try meta.update(profile) {
            $0?.sessionsRevokedAt = cutoff
            $0?.sessionExpiresAt = nil
            $0?.account = identity.account
            $0?.arn = identity.arn
        }
        try audit.append("sessions.revoked", profile: profile, detail: ["user": user, "before": iso8601(cutoff)])
        return cutoff
    }

    public static func userName(fromArn arn: String) -> String? {
        let parts = arn.split(separator: ":", maxSplits: 5, omittingEmptySubsequences: false)
        guard parts.count == 6, parts[2] == "iam", parts[5].hasPrefix("user/") else { return nil }
        return parts[5].split(separator: "/").last.map(String.init)
    }

    public static func revokePolicy(before cutoff: Date) -> String {
        "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"AwsCliZspRevokeOlderSessions\",\"Effect\":\"Deny\",\"Action\":\"*\",\"Resource\":\"*\",\"Condition\":{\"DateLessThan\":{\"aws:TokenIssueTime\":\"\(iso8601(cutoff))\"}}}]}"
    }

    /// Deactivates the key in AWS. It cannot be reactivated from here, because the key was
    /// the only credential zsp had: use the IAM console.
    public func disableKey(_ profile: String) throws {
        let master = try unlock(profile, reason: "deactivate the AWS access key for profile “\(profile)”")
        try aws.updateAccessKey(try adminCredentials(master), keyId: master.accessKeyId, active: false)
        try store.delete(.session, profile)
        try meta.update(profile) { $0?.keyStatus = "Inactive"; $0?.sessionExpiresAt = nil }
        try audit.append("key.disabled", profile: profile, detail: ["keyId": maskKeyId(master.accessKeyId)])
    }

    /// Deletes the key in AWS, then everywhere locally.
    public func deleteKey(_ profile: String) throws {
        let master = try unlock(profile, reason: "delete the AWS access key for profile “\(profile)”")
        try aws.deleteAccessKey(try adminCredentials(master), keyId: master.accessKeyId)
        try audit.append("key.deleted", profile: profile, detail: ["keyId": maskKeyId(master.accessKeyId)])
        try removeLocal(profile)
    }

    /// Removes the key from this Mac only. AWS still has it.
    public func forget(_ profile: String) throws {
        let master = try unlock(profile, reason: "remove the AWS key for profile “\(profile)” from this Mac")
        try audit.append("key.forgotten", profile: profile, detail: ["keyId": maskKeyId(master.accessKeyId)])
        try removeLocal(profile)
    }

    func removeLocal(_ profile: String) throws {
        try store.delete(.master, profile)
        try store.delete(.session, profile)
        try store.delete(.remote, profile)
        try meta.update(profile) { $0 = nil }
        try unwireConfig(profile)
    }

    /// Points every profile in the Keychain at this binary, and refreshes the hint at the top of
    /// the credentials file. For when the binary moves (a rename, a new install location).
    public func rewire() throws -> [String] {
        let profiles = Set(try store.accounts(.master)).union(meta.all().keys).sorted()
        let text = (try? String(contentsOf: paths.configFile, encoding: .utf8)) ?? ""
        var config = INIDocument(text)
        for p in profiles { config.set("credential_process", credentialProcess(for: p), in: AWSFiles.configSection(for: p)) }
        if config.text != text { try writeAtomically(config.text, to: paths.configFile) }
        if let creds = try? String(contentsOf: paths.credentialsFile, encoding: .utf8), creds.contains("`zsp add") {
            try writeAtomically(creds.replacingOccurrences(of: "`zsp add", with: "`aws-cli-zsp add")
                .replacingOccurrences(of: "`zsp list`", with: "`aws-cli-zsp list`"), to: paths.credentialsFile)
        }
        return profiles
    }

    func unwireConfig(_ profile: String) throws {
        let text = (try? String(contentsOf: paths.configFile, encoding: .utf8)) ?? ""
        var config = INIDocument(text)
        let section = AWSFiles.configSection(for: profile)
        if let cp = config.value("credential_process", in: section), isOurs(cp) {
            config.remove(keys: ["credential_process"], in: section)
            config.removeHeaderIfEmpty(section)
            if config.text != text { try writeAtomically(config.text, to: paths.configFile) }
        }
    }

    /// The watcher self-test's profile: a documented AWS example key, never a real one.
    public static let selfTestProfile = "aws-cli-zsp-selftest"

    /// Removes the self-test profile without Touch ID: its key is AWS's published example.
    public func removeSelfTest() throws {
        guard let m = meta.all()[Self.selfTestProfile], m.accessKeyId == "AKIAIOSFODNN7EXAMPLE" else { return }
        try removeLocal(Self.selfTestProfile)
    }

    /// Drops cached sessions so the next command needs Touch ID again. Local only: the
    /// sessions stay valid in AWS until they expire (revoke for that).
    public func clearSessions(_ profile: String? = nil) throws -> [String] {
        let names = try profile.map { [$0] } ?? store.accounts(.session)
        for name in names {
            try store.delete(.session, name)
            try? meta.update(name) { $0?.sessionExpiresAt = nil }
        }
        try audit.append("sessions.cleared", profile: profile, detail: ["profiles": names.joined(separator: ",")])
        return names
    }

    /// Writes every key back into the credentials file and drops zsp's wiring: the way out
    /// before uninstalling. The watcher must be stopped first or it moves them straight back.
    public func restorePlaintext() throws -> [String] {
        let profiles = try store.accounts(.master)
        guard !profiles.isEmpty else { return [] }
        try auth.confirm("write \(profiles.count) AWS key(s) back to \(paths.credentialsFile.lastPathComponent) in plain text")
        let credsText = (try? String(contentsOf: paths.credentialsFile, encoding: .utf8)) ?? ""
        var creds = INIDocument(credsText)
        for profile in profiles {
            guard let data = try store.read(.master, profile) else { continue }
            let key = try ZSPJSON.decoder.decode(MasterKey.self, from: data)
            creds.set("aws_access_key_id", key.accessKeyId, in: profile)
            creds.set("aws_secret_access_key", key.secretAccessKey, in: profile)
            if let token = key.sessionToken { creds.set("aws_session_token", token, in: profile) }
        }
        try writeAtomically(creds.text, to: paths.credentialsFile)
        for profile in profiles {
            try audit.append("key.restored", profile: profile)
            try removeLocal(profile)
        }
        return profiles
    }
}

/// 3600 is "1-hour", 900 is "15-minute", 5400 is "90-minute": the form a dialog reads naturally.
func durationText(_ seconds: Int) -> String {
    if seconds % 3600 == 0 { return "\(seconds / 3600)-hour" }
    return "\(seconds / 60)-minute"
}
