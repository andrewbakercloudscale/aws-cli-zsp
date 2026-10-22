import Foundation

/// The key in AWS: who it belongs to, rotating it, revoking its sessions, retiring it.
extension Vault {
    public static let revokePolicyName = "aws-cli-zsp-revoke-older-sessions"

    /// Who the key belongs to and when AWS last saw each of the user's keys used: the way to
    /// tell whether a leaked key was used by someone else.
    public func inspect(_ profile: String) throws -> InspectReport {
        let (master, c) = try unlockForIAM(profile, reason: "look up the AWS key for profile “\(profile)”")
        let identity = try aws.getCallerIdentity(c)
        let longLived = master.sessionToken == nil
        // A client's user may not be allowed to list its own keys: the identity still answers.
        var listed: [AccessKeyInfo] = []
        if longLived {
            do {
                listed = try aws.listAccessKeys(c)
            } catch let ZSPError.aws(code, _) where Self.deniedCodes.contains(code) {
                Log.info("iam", "\(profile) may not list its own keys (\(code))")
            }
        }
        let denied = longLived ? simulateAccess(c, identity) : nil
        let keys = listed.map { k in
            KeyReport(accessKeyId: k.accessKeyId, status: k.status, createDate: k.createDate,
                      lastUsed: try? aws.getAccessKeyLastUsed(c, keyId: k.accessKeyId),
                      thisProfile: k.accessKeyId == master.accessKeyId)
        }
        let status = keys.first { $0.thisProfile }?.status
        bestEffort("note what AWS said about \(profile)") {
            try meta.update(profile) {
                $0?.account = identity.account
                $0?.arn = identity.arn
                if let status { $0?.keyStatus = status }
                if let denied { $0?.iamDenied = denied }
            }
        }
        try audit.append(.keyInspected, profile: profile, detail: ["arn": identity.arn, "keys": String(keys.count)])
        return InspectReport(profile: profile, identity: identity, keys: keys)
    }

    /// Creates a new key, stores it, waits for AWS to accept it, then deletes (or with
    /// `keepOld`, deactivates) the old one.
    public func rotate(_ profile: String, keepOld: Bool = false) throws -> RotateResult {
        try guarded(profile, .keys) {
            let master = try unlock(profile, reason: "rotate the AWS access key for profile “\(profile)”")
            try requireLongLived(master, profile, "there is no key to rotate")
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
            do {
                try writeMaster(MasterKey(accessKeyId: fresh.accessKeyId, secretAccessKey: fresh.secretAccessKey, sessionToken: nil,
                                          importedAt: now(), source: "rotated", mfaSerial: master.mfaSerial, mfaSeed: master.mfaSeed), profile)
            } catch {
                // Its secret is about to be lost: a key nobody holds would only use up the user's second slot.
                bestEffort("delete the new key that could not be stored") { try aws.deleteAccessKey(admin, keyId: fresh.accessKeyId) }
                recordFailure(.keyRotateFailed, profile: profile, detail: ["new": maskKeyId(fresh.accessKeyId), "step": "store"], error: error)
                throw error
            }
            bestEffort("audit the new key") { try audit.append(.keyCreated, profile: profile, detail: ["keyId": maskKeyId(fresh.accessKeyId)]) }
            bestEffort("note the new key of \(profile)") { try meta.update(profile) {
                $0?.previousKeyId = old.accessKeyId
                $0?.accessKeyId = fresh.accessKeyId
                $0?.source = "rotated"
                $0?.temporary = false
            } }
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
                recordFailure(.keyRotateFailed, profile: profile,
                              detail: ["old": maskKeyId(old.accessKeyId), "new": maskKeyId(fresh.accessKeyId)], error: error)
                throw ZSPError.aws(code: "RotateIncomplete", message: "The new key \(maskKeyId(fresh.accessKeyId)) is stored and in use, but the old key \(maskKeyId(old.accessKeyId)) could not be retired (\(error.localizedDescription)). Delete it in the IAM console.")
            }
            try dropSession(profile)
            let t = now()
            try meta.update(profile) {
                $0?.accessKeyId = fresh.accessKeyId
                $0?.previousKeyId = old.accessKeyId
                $0?.rotatedAt = t
                $0?.importedAt = t
                $0?.keyStatus = "Active"
            }
            let action = keepOld ? "deactivated" : "deleted"
            try audit.append(.keyRotated, profile: profile,
                             detail: ["old": maskKeyId(old.accessKeyId), "new": maskKeyId(fresh.accessKeyId), "oldKey": action])
            return RotateResult(profile: profile, oldKeyId: old.accessKeyId, newKeyId: fresh.accessKeyId, oldKey: action)
        }
    }

    /// A new IAM key takes a few seconds to be accepted everywhere.
    func retryingNewKey<T>(_ body: () throws -> T) throws -> T {
        var attempt = 0
        while true {
            do { return try body() } catch let ZSPError.aws(code, _) where code == "InvalidClientTokenId" && attempt < 15 {
                attempt += 1
                Log.debug("iam", "the new key is not accepted yet (attempt \(attempt))")
                pause(2)
            }
        }
    }

    /// Cuts off every session issued from this key until now, including any a thief minted,
    /// by attaching a deny-all policy conditioned on aws:TokenIssueTime. The long-lived key
    /// keeps working and new sessions are unaffected.
    public func revokeSessions(_ profile: String) throws -> Date {
        try guarded(profile, .revoke) {
            let master = try unlock(profile, reason: "revoke every session issued for AWS profile “\(profile)”")
            try requireLongLived(master, profile, "they cannot revoke themselves")
            let admin = try adminCredentials(master)
            let identity = try aws.getCallerIdentity(admin)
            guard let user = Self.userName(fromArn: identity.arn) else {
                throw ZSPError.invalid("\(identity.arn) is not an IAM user, so its sessions cannot be revoked with a user policy")
            }
            // The MFA session above is cut off with the rest; this is its last call.
            let cutoff = now()
            try aws.putUserPolicy(admin, userName: user, policyName: Self.revokePolicyName, document: Self.revokePolicy(before: cutoff))
            try dropSession(profile)
            try meta.update(profile) {
                $0?.sessionsRevokedAt = cutoff
                $0?.account = identity.account
                $0?.arn = identity.arn
            }
            try audit.append(.sessionsRevoked, profile: profile, detail: ["user": user, "before": iso8601(cutoff)])
            return cutoff
        }
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
        try guarded(profile, .keys) {
            let (master, admin) = try unlockForIAM(profile, reason: "deactivate the AWS access key for profile “\(profile)”")
            try aws.updateAccessKey(admin, keyId: master.accessKeyId, active: false)
            try dropSession(profile)
            try meta.update(profile) { $0?.keyStatus = "Inactive" }
            try audit.append(.keyDisabled, profile: profile, detail: ["keyId": maskKeyId(master.accessKeyId)])
        }
    }

    /// Deletes the key in AWS, then everywhere locally.
    public func deleteKey(_ profile: String) throws {
        try guarded(profile, .keys) {
            let (master, admin) = try unlockForIAM(profile, reason: "delete the AWS access key for profile “\(profile)”")
            try aws.deleteAccessKey(admin, keyId: master.accessKeyId)
            try audit.append(.keyDeleted, profile: profile, detail: ["keyId": maskKeyId(master.accessKeyId)])
            try removeLocal(profile)
        }
    }
}
