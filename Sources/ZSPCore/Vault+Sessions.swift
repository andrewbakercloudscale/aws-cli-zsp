import Foundation

extension Vault {
    /// What credential_process returns. A cached session is served without a prompt while it
    /// has five minutes left; otherwise Touch ID unlocks the long-lived key for one
    /// GetSessionToken call and the key goes straight back out of memory.
    /// `asker` is the short "who wants it" for the Touch ID dialog; `requester` is the full chain
    /// the audit log keeps.
    public func credentials(for profile: String, requester: String, asker: String? = nil) throws -> AWSCredentials {
        try paths.ensureSupportDir()
        return try withFileLock(paths.lock("session-\(profile)")) {
            let t = now()
            if let cached = try cachedSession(profile, requester: requester, at: t) { return cached }
            let seconds = Settings.load(paths).duration(for: profile)
            guard someoneAtMac() else {
                recordFailure(.sessionAway, profile: profile, requester: requester)
                throw awayError(profile)
            }
            let reason = "unlock your “\(profile)” AWS key for a \(durationText(seconds)) session, for \(asker ?? requester)"
            let master = try unlock(profile, reason: reason, requester: requester)
            if master.sessionToken != nil {
                try checkPin(profile, master.credentials, requester: requester)
                try audit.append(.sessionServed, profile: profile, detail: ["temporary": "true"], requester: requester)
                bestEffort("note the use of \(profile)") { try meta.update(profile) { $0?.lastUsedAt = t; $0?.lastRequester = requester } }
                return master.credentials
            }
            return try issue(profile, master, seconds: seconds, mfa: try ownMFACode(master), approvedBy: "touch-id",
                             requester: requester)
        }
    }

    /// The sealed session, while it has five minutes left and is the one aws-cli-zsp issued.
    func cachedSession(_ profile: String, requester: String, at t: Date) throws -> AWSCredentials? {
        let data: Data?
        do {
            data = try store.read(.session, profile)
        } catch where isDeviceLocked(error) {
            // The session is fine and the Mac is locked: deleting it would lose a good session.
            Log.warning("session", "the cached session for \(profile) cannot be opened while the Mac is locked")
            return nil
        } catch {
            // A damaged or unopenable session (a cut-short file, a new enclave key) costs one
            // Touch ID for a new session rather than failing every command until it is cleared.
            Log.warning("session", "the cached session for \(profile) cannot be opened (\(error.localizedDescription)); a new one is issued")
            bestEffort("drop the unreadable session of \(profile)") { try dropSession(profile) }
            return nil
        }
        guard let data else { return nil }
        guard let s = try? ZSPJSON.decoder.decode(AWSCredentials.self, from: data) else {
            Log.warning("session", "the cached session for \(profile) does not decode; a new one is issued")
            return nil
        }
        guard let exp = s.expiration, exp > t.addingTimeInterval(300) else { return nil }
        guard try isPinnedSession(profile, s) else {
            // Issued while the pin could not be updated. Someone is back and the pin can be
            // read: it costs one Touch ID, not an alarm, and vouches for nothing.
            if meta.all()[profile]?.awaySessionKeyId == s.accessKeyId {
                Log.info("session", "the session for \(profile) approved while away is replaced now the pin can be read")
                return nil
            }
            try dropSession(profile)
            recordFailure(.sessionSwapped, profile: profile, detail: ["found": maskKeyId(s.accessKeyId)], requester: requester)
            throw ZSPError.auth("""
                The cached session for “\(profile)” is not one aws-cli-zsp issued, so it was deleted and not used. \
                Something running as you may have written it. Run the command again to start a new session with Touch ID.
                """)
        }
        try audit.append(.sessionServed, profile: profile, detail: ["expires": iso8601(exp)], requester: requester)
        bestEffort("note the use of \(profile)") {
            try meta.update(profile) { $0?.lastUsedAt = t; $0?.lastRequester = requester; $0?.sessionExpiresAt = exp }
        }
        return s
    }

    /// GetSessionToken, then the session is sealed, logged and remembered.
    func issue(_ profile: String, _ master: MasterKey, seconds: Int, mfa: MFACode?, approvedBy: String,
               requester: String, failure: (event: AuditEvent, detail: [String: String]) = (.sessionFailed, [:])) throws -> AWSCredentials {
        let session: AWSCredentials
        do {
            session = try aws.getSessionToken(master.credentials, durationSeconds: seconds, mfa: mfa)
        } catch {
            recordFailure(failure.event, profile: profile, detail: failure.detail, requester: requester, error: error)
            throw error
        }
        try checkPin(profile, session, requester: requester)
        try store.write(.session, profile, try ZSPJSON.encoder.encode(session))
        var detail = ["keyId": maskKeyId(master.accessKeyId), "seconds": String(seconds),
                      "expires": session.expiration.map(iso8601) ?? "?", "approved": approvedBy]
        if let mfa { detail["mfa"] = mfa.serial.split(separator: "/").last.map(String.init) ?? mfa.serial }
        try audit.append(.sessionIssued, profile: profile, detail: detail, requester: requester)
        bestEffort("note the session of \(profile)") {
            try meta.update(profile) {
                $0?.lastUsedAt = self.now()
                $0?.lastRequester = requester
                $0?.sessionExpiresAt = session.expiration
            }
        }
        return session
    }

    func awayError(_ profile: String) -> ZSPError {
        if meta.all()[profile]?.remoteSerial != nil {
            return .auth("Nobody is at the Mac to approve Touch ID for AWS profile “\(profile)”. "
                + "Ask the user for the 6-digit code from their MFA app, then run: aws-cli-zsp approve --profile \(profile) CODE "
                + "(and retry). Or approve at the Mac and retry.")
        }
        return .auth("Nobody is at the Mac to approve Touch ID for AWS profile “\(profile)”, and approval by MFA code is not set up "
            + "for it. Approve at the Mac and retry. "
            + phoneSetupAdvice(profile))
    }

    /// Issues a session approved by a code from your phone, with no Touch ID: what Claude Code
    /// runs over Remote Control after asking you for the code. AWS checks the code.
    public func approve(_ profile: String, code: String, requester: String) throws -> AWSCredentials {
        guard TOTP.isCode(code) else { throw ZSPError.invalid("an MFA code is 6 digits") }
        let sealed: Data?
        do {
            sealed = try store.read(.remote, profile)
        } catch where isDeviceLocked(error) {
            throw ZSPError.auth("The phone-approval copy of “\(profile)” was sealed by an older version and cannot be opened while the Mac is locked. "
                + "Unlock the Mac once: aws-cli-zsp reseals it, and after that a code works on a locked Mac. Your code was not used.")
        }
        guard let serial = meta.all()[profile]?.remoteSerial, let data = sealed else {
            throw ZSPError.invalid("Approval by MFA code is not set up for “\(profile)”. " + phoneSetupAdvice(profile))
        }
        let key = try decodeKey(data, profile)
        try paths.ensureSupportDir()
        // Another command can hold this lock for as long as a dialog at the Mac stays open, and a
        // code lasts about 30 seconds, so give up while the code has not been spent.
        let busy = ZSPError.auth("Another aws-cli-zsp command is using “\(profile)”, probably waiting on a dialog at the Mac. "
            + "Answer or close it, then try again with a new code. Your code was not used.")
        return try withFileLock(paths.lock("session-\(profile)"), timeout: approveLockWait, busy: busy) {
            try withoutDialogs {
                // A wrong code is AWS refusing GetSessionToken: audited once, as a refusal.
                let session = try issue(profile, key, seconds: Settings.load(paths).duration(for: profile),
                                        mfa: MFACode(serial: serial, code: code), approvedBy: "mfa-code", requester: requester,
                                        failure: (.authDenied, ["for": "approval by MFA code"]))
                try confirmStillEnforced(profile, session, requester: requester)
                return session
            }
        }
    }

    /// Drops cached sessions so the next command needs Touch ID again. Local only: the
    /// sessions stay valid in AWS until they expire (revoke for that).
    public func clearSessions(_ profile: String? = nil) throws -> [String] {
        let names = try profile.map { [$0] } ?? store.accounts(.session)
        for name in names { try dropSession(name) }
        try audit.append(.sessionsCleared, profile: profile, detail: ["profiles": names.joined(separator: ",")])
        return names
    }
}
