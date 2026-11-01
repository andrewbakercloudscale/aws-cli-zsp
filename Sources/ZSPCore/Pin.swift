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

    /// The pin, or `unverifiable` when the Keychain will not answer without a dialog and none may
    /// be waited on: nobody is at the Mac, or the command runs under `withoutDialogs`. It asks
    /// whenever the build that reads an item is not the build that made it, even with the same
    /// certificate, so after any update a pin needs someone at the Mac once.
    func pinWhileAway(_ profile: String) throws -> (pin: AccountPin?, unverifiable: Bool) {
        do {
            return (try pin(profile), false)
        } catch ZSPError.keychain(let status, let message) where status == -1 && (mustNotAsk || !someoneAtMac()) {
            Log.warning("pin", "\(profile) cannot be checked without a dialog: \(message)")
            return (nil, true)
        }
    }

    /// For what runs on behalf of someone who may not be looking at the Mac. Recent input does not
    /// show they are: a phone approval stalled 26 minutes on a dialog after someone touched the
    /// Mac and walked away, with the session already issued by AWS.
    func withoutDialogs<T>(_ body: () throws -> T) rethrows -> T {
        let was = mustNotAsk
        mustNotAsk = true
        defer { mustNotAsk = was }
        return try withoutKeychainDialogs(body)
    }

    func writePin(_ profile: String, _ p: AccountPin) throws {
        try pins?.write(.pin, profile, try ZSPJSON.encoder.encode(p))
    }

    /// Writes the pin, or under `withoutDialogs` records that it could not be: AWS has already
    /// issued the session and taken the code, and neither is worth losing to the Keychain.
    func storePin(_ profile: String, _ p: AccountPin, _ creds: AWSCredentials, _ id: CallerIdentity, requester: String) throws -> Bool {
        do {
            try writePin(profile, p)
            return true
        } catch where mustNotAsk {
            Log.warning("pin", "\(profile) could not be updated without a dialog: \(error.localizedDescription)")
            try noteUnverified(profile, creds, id, requester: requester)
            return false
        }
    }

    func noteUnverified(_ profile: String, _ creds: AWSCredentials, _ id: CallerIdentity, requester: String) throws {
        try audit.append(.pinUnverified, profile: profile, detail: ["found": id.arn], requester: requester)
        if creds.sessionToken != nil { try meta.update(profile) { $0?.awaySessionKeyId = creds.accessKeyId } }
    }

    /// Checks that `creds` (a new session, or a temporary key) belong to the account and user the
    /// profile is pinned to, pinning them the first time. On a mismatch the session is dropped
    /// and nothing is handed out.
    func checkPin(_ profile: String, _ creds: AWSCredentials, requester: String) throws {
        guard pins != nil else { return }
        let id = try aws.getCallerIdentity(creds)
        let read = try pinWhileAway(profile)
        if read.unverifiable {
            // Phone approval must not depend on a dialog nobody can answer. AWS has checked your
            // phone's code against this key's own MFA device, which a key to another account
            // does not have. The account last shown is compared to catch a plain mix-up, and the
            // audit trail says the pin was not checked.
            if let shown = meta.all()[profile]?.pinnedAccount, shown != id.account {
                bestEffort("drop the session of \(profile)") { try dropSession(profile) }
                recordFailure(.keySwapped, profile: profile, detail: ["pinned": shown, "found": id.arn], requester: requester)
                throw ZSPError.auth("The key for “\(profile)” belongs to \(id.arn), but this profile is pinned to account \(shown). Nothing was handed out.")
            }
            try noteUnverified(profile, creds, id, requester: requester)
            return
        }
        guard var p = read.pin else {
            let first = AccountPin(account: id.account, arn: id.arn, sessionKeyId: creds.sessionToken == nil ? nil : creds.accessKeyId, pinnedAt: now())
            guard try storePin(profile, first, creds, id, requester: requester) else { return }
            try audit.append(.pinSet, profile: profile, detail: ["account": id.account, "arn": id.arn], requester: requester)
            Log.info("pin", "pinned \(profile) to account \(id.account)")
            bestEffort("show the pin of \(profile)") {
                try meta.update(profile) { $0?.pinnedAccount = id.account; $0?.account = id.account; $0?.arn = id.arn }
            }
            return
        }
        guard p.account == id.account, p.arn == id.arn else {
            bestEffort("drop the session of \(profile)") { try dropSession(profile) }
            recordFailure(.keySwapped, profile: profile, detail: ["pinned": p.arn, "found": id.arn], requester: requester)
            throw ZSPError.auth("""
                The key for “\(profile)” belongs to \(id.arn), but this profile is pinned to \(p.arn). \
                Nothing was handed out: something may have replaced the key. If you changed it yourself, \
                run at the Mac: aws-cli-zsp pin reset --profile \(profile)
                """)
        }
        if creds.sessionToken != nil {
            p.sessionKeyId = creds.accessKeyId
            _ = try storePin(profile, p, creds, id, requester: requester)
        }
    }

    /// Whether a cached session is the one aws-cli-zsp issued. Without a pin yet (before the
    /// first session since pinning arrived), it is trusted and the next session is pinned.
    /// A session approved by code whose pin could not be checked is served without a dialog: the
    /// person who approved it may still be on their phone, and the next `aws` command would
    /// otherwise stall where `approve` no longer does.
    func isPinnedSession(_ profile: String, _ s: AWSCredentials) throws -> Bool {
        let approvedAway = meta.all()[profile]?.awaySessionKeyId == s.accessKeyId
        let read = approvedAway ? try withoutDialogs { try pinWhileAway(profile) } : try pinWhileAway(profile)
        guard !read.unverifiable, let id = read.pin?.sessionKeyId else { return true }
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
