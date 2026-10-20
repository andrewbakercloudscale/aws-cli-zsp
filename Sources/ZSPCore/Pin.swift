import Foundation

/// Which AWS account and IAM user a profile belongs to, and which session aws-cli-zsp last
/// issued for it. Kept in the login Keychain, where an item trusts only the program that made
/// it: anything else running as you can read the vault folder and profiles.json, but changing
/// this needs a macOS prompt. Sealing a key needs only a public key, so without the pin a
/// program could swap in a key to its own account under your profile name.
public struct AccountPin: Codable, Equatable, Sendable {
    public var account: String
    public var arn: String
    /// The access key id of the session last issued, so a session sealed in by something else
    /// is not served.
    public var sessionKeyId: String?
    public var pinnedAt: Date
}

extension Vault {
    public func pin(_ profile: String) throws -> AccountPin? {
        guard let pins else { return nil }
        let data: Data?
        do {
            data = try pins.read(.pin, profile)
        } catch {
            throw ZSPError.keychain(-1, "Could not read the account pin for “\(profile)” from the login Keychain (\(error.localizedDescription)). Unlock the Mac and try again.")
        }
        return try data.map { try ZSPJSON.decoder.decode(AccountPin.self, from: $0) }
    }

    func writePin(_ profile: String, _ p: AccountPin) throws {
        try pins?.write(.pin, profile, try ZSPJSON.encoder.encode(p))
    }

    /// Checks that `creds` (a new session, or a temporary key) belong to the account and user the
    /// profile is pinned to, pinning them the first time. On a mismatch the session is dropped
    /// and nothing is handed out.
    func checkPin(_ profile: String, _ creds: AWSCredentials, requester: String) throws {
        guard pins != nil else { return }
        let id = try aws.getCallerIdentity(creds)
        guard var p = try pin(profile) else {
            try writePin(profile, AccountPin(account: id.account, arn: id.arn, sessionKeyId: creds.sessionToken == nil ? nil : creds.accessKeyId,
                                             pinnedAt: now()))
            try audit.append(.pinSet, profile: profile, detail: ["account": id.account, "arn": id.arn], requester: requester)
            Log.info("pin", "pinned \(profile) to account \(id.account)")
            bestEffort("show the pin of \(profile)") {
                try meta.update(profile) { $0?.pinnedAccount = id.account; $0?.account = id.account; $0?.arn = id.arn }
            }
            return
        }
        guard p.account == id.account, p.arn == id.arn else {
            bestEffort("drop the session of \(profile)") { try store.delete(.session, profile) }
            recordFailure(.keySwapped, profile: profile, detail: ["pinned": p.arn, "found": id.arn], requester: requester)
            throw ZSPError.auth("""
                The key for “\(profile)” belongs to \(id.arn), but this profile is pinned to \(p.arn). \
                Nothing was handed out: something may have replaced the key. If you changed it yourself, \
                run at the Mac: aws-cli-zsp pin reset --profile \(profile)
                """)
        }
        if creds.sessionToken != nil {
            p.sessionKeyId = creds.accessKeyId
            try writePin(profile, p)
        }
    }

    /// Whether a cached session is the one aws-cli-zsp issued. Without a pin yet (before the
    /// first session since pinning arrived), it is trusted and the next session is pinned.
    func isPinnedSession(_ profile: String, _ s: AWSCredentials) throws -> Bool {
        guard let id = try pin(profile)?.sessionKeyId else { return true }
        return id == s.accessKeyId
    }

    /// Forgets the pin after Touch ID, so the next session pins whatever account the key is in.
    public func resetPin(_ profile: String) throws {
        _ = try unlock(profile, reason: "re-pin the AWS account for profile “\(profile)”")
        try pins?.delete(.pin, profile)
        try dropSession(profile)
        bestEffort("clear the pin shown for \(profile)") { try meta.update(profile) { $0?.pinnedAccount = nil } }
        try audit.append(.pinReset, profile: profile)
    }

    func dropPin(_ profile: String) {
        bestEffort("remove the pin of \(profile)") { try pins?.delete(.pin, profile) }
    }
}
