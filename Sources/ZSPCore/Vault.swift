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
    public func importPlaintext(origin: String) throws -> ImportReport {
        try paths.ensureSupportDir()
        return try withFileLock(paths.lock("import")) {
            var report = ImportReport()
            let credsText = (try? String(contentsOf: paths.credentialsFile, encoding: .utf8)) ?? ""
            let configText = (try? String(contentsOf: paths.configFile, encoding: .utf8)) ?? ""
            var creds = INIDocument(credsText)
            var config = INIDocument(configText)

            // Config first: when both files hold a key, the credentials file wins in the AWS
            // CLI, so it must win here too.
            let fromConfig = try extract(&config, isConfig: true, file: paths.configFile, origin: origin, report: &report)
            let fromCreds = try extract(&creds, isConfig: false, file: paths.credentialsFile, origin: origin, report: &report)
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

    func extract(_ doc: inout INIDocument, isConfig: Bool, file: URL, origin: String, report: inout ImportReport) throws -> [String] {
        var moved: [String] = []
        for section in doc.sectionNames {
            guard let profile = isConfig ? AWSFiles.profileName(configSection: section) : section else { continue }
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
        try writeMaster(key, profile)
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
    }

    /// Stores a key exactly as an older store held it (the migration from 0.1.x).
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
    public func credentials(for profile: String, requester: String) throws -> AWSCredentials {
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
            let master = try unlock(profile, reason: "issue AWS credentials for profile “\(profile)” to \(requester)", requester: requester)
            if master.sessionToken != nil {
                try audit.append("session.served", profile: profile, detail: ["temporary": "true"], requester: requester)
                try? meta.update(profile) { $0?.lastUsedAt = t; $0?.lastRequester = requester }
                return master.credentials
            }
            let seconds = Settings.load(paths).duration(for: profile)
            let session: AWSCredentials
            do {
                session = try aws.getSessionToken(master.credentials, durationSeconds: seconds)
            } catch {
                _ = try? audit.append("session.failed", profile: profile, ok: false, detail: ["error": error.localizedDescription],
                                  requester: requester)
                throw error
            }
            try store.write(.session, profile, try ZSPJSON.encoder.encode(session))
            try audit.append("session.issued", profile: profile,
                             detail: ["keyId": maskKeyId(master.accessKeyId), "seconds": String(seconds),
                                      "expires": session.expiration.map(iso8601) ?? "?"],
                             requester: requester)
            try? meta.update(profile) {
                $0?.lastUsedAt = t
                $0?.lastRequester = requester
                $0?.sessionExpiresAt = session.expiration
            }
            return session
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
        let c = master.credentials
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
        let keys = try aws.listAccessKeys(old)
        if keys.count >= 2 {
            let other = keys.first { $0.accessKeyId != old.accessKeyId }.map { maskKeyId($0.accessKeyId) } ?? "another key"
            throw ZSPError.invalid("This IAM user already has two access keys (the other is \(other)). AWS allows two at most: delete the one you no longer use, then rotate again.")
        }
        let fresh = try aws.createAccessKey(old)
        // Stored before anything else happens: the new secret is never only in memory.
        try writeMaster(MasterKey(accessKeyId: fresh.accessKeyId, secretAccessKey: fresh.secretAccessKey, sessionToken: nil,
                                  importedAt: now(), source: "rotated"), profile)
        _ = try? audit.append("key.created", profile: profile, detail: ["keyId": maskKeyId(fresh.accessKeyId)])
        try meta.update(profile) {
            $0?.previousKeyId = old.accessKeyId
            $0?.accessKeyId = fresh.accessKeyId
            $0?.source = "rotated"
            $0?.temporary = false
        }
        do {
            _ = try retryingNewKey { try aws.getCallerIdentity(fresh) }
            try retryingNewKey {
                if keepOld { try aws.updateAccessKey(fresh, keyId: old.accessKeyId, active: false) }
                else { try aws.deleteAccessKey(fresh, keyId: old.accessKeyId) }
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
        let identity = try aws.getCallerIdentity(master.credentials)
        guard let user = Self.userName(fromArn: identity.arn) else {
            throw ZSPError.invalid("\(identity.arn) is not an IAM user, so its sessions cannot be revoked with a user policy")
        }
        let cutoff = now()
        try aws.putUserPolicy(master.credentials, userName: user, policyName: Self.revokePolicyName, document: Self.revokePolicy(before: cutoff))
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
        try aws.updateAccessKey(master.credentials, keyId: master.accessKeyId, active: false)
        try store.delete(.session, profile)
        try meta.update(profile) { $0?.keyStatus = "Inactive"; $0?.sessionExpiresAt = nil }
        try audit.append("key.disabled", profile: profile, detail: ["keyId": maskKeyId(master.accessKeyId)])
    }

    /// Deletes the key in AWS, then everywhere locally.
    public func deleteKey(_ profile: String) throws {
        let master = try unlock(profile, reason: "delete the AWS access key for profile “\(profile)”")
        try aws.deleteAccessKey(master.credentials, keyId: master.accessKeyId)
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
