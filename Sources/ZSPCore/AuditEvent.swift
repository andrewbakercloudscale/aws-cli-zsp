import Foundation

/// Every event aws-cli-zsp writes to the audit trail, with the words the app shows for it.
/// The log stores the raw value, so these names never change.
public enum AuditEvent: String, CaseIterable, Sendable {
    case keyImported = "key.imported", keyAdded = "key.added", keyCreated = "key.created"
    case keyRotated = "key.rotated", keyRotateFailed = "key.rotate.failed"
    case keyDisabled = "key.disabled", keyDeleted = "key.deleted", keyForgotten = "key.forgotten"
    case keyInspected = "key.inspected", keyRestored = "key.restored", keysMigrated = "keys.migrated"
    case keySwapped = "key.swapped"

    case sessionIssued = "session.issued", sessionServed = "session.served", sessionFailed = "session.failed"
    case sessionAway = "session.away", sessionSwapped = "session.swapped"
    case sessionsRevoked = "sessions.revoked", sessionsCleared = "sessions.cleared"
    case authDenied = "auth.denied"

    case mfaSetup = "mfa.setup", mfaEnforced = "mfa.enforced", mfaUnenforced = "mfa.unenforced", mfaRemoved = "mfa.removed"
    case phoneCreated = "mfa.phone.created", phoneCancelled = "mfa.phone.cancelled"
    case remoteEnabled = "remote.enabled", remoteDisabled = "remote.disabled"

    case pinSet = "pin.set", pinReset = "pin.reset"
    case accessDenied = "access.denied", accessSet = "access.set"

    case settingsDuration = "settings.duration", setupDone = "setup.done"
    case installed = "zsp.installed", uninstalled = "zsp.uninstalled"
    case profileTested = "profile.tested", watcherTested = "watcher.tested"

    /// What the app calls it.
    public var title: String {
        switch self {
        case .keyImported: return "Key moved into the vault"
        case .keyAdded: return "Key added"
        case .keyCreated: return "New key created"
        case .keyRotated: return "Key rotated"
        case .keyRotateFailed: return "Rotation incomplete"
        case .keyDisabled: return "Key deactivated"
        case .keyDeleted: return "Key deleted"
        case .keyForgotten: return "Key removed from this Mac"
        case .keyInspected: return "Checked in AWS"
        case .keyRestored: return "Key written back to file"
        case .keysMigrated: return "Keys migrated"
        case .keySwapped: return "Key to another account refused"
        case .sessionIssued: return "Session issued"
        case .sessionServed: return "Session used"
        case .sessionFailed: return "Session request failed"
        case .sessionAway: return "Nobody at the Mac: no session"
        case .sessionSwapped: return "Planted session refused"
        case .sessionsRevoked: return "All sessions revoked"
        case .sessionsCleared: return "Cached sessions cleared"
        case .authDenied: return "Touch ID declined"
        case .mfaSetup: return "This Mac added as an MFA device"
        case .mfaEnforced: return "AWS now requires MFA"
        case .mfaUnenforced: return "AWS no longer requires MFA"
        case .mfaRemoved: return "This Mac's MFA device removed"
        case .phoneCreated: return "Phone MFA device created"
        case .phoneCancelled: return "Unused phone MFA device deleted"
        case .remoteEnabled: return "Phone approval turned on"
        case .remoteDisabled: return "Phone approval turned off"
        case .pinSet: return "Account pinned"
        case .pinReset: return "Account pin reset"
        case .accessDenied: return "IAM refused a change (client's key)"
        case .accessSet: return "Access level set"
        case .settingsDuration: return "Session length changed"
        case .setupDone: return "Setup"
        case .installed: return "Installed"
        case .uninstalled: return "Uninstalled"
        case .profileTested: return "Profile tested"
        case .watcherTested: return "Auto-move tested"
        }
    }

    /// Something to look at: a refusal, a failure, or a sign of tampering.
    public var isAlarm: Bool {
        [.keySwapped, .sessionSwapped, .authDenied, .sessionFailed, .keyRotateFailed, .accessDenied].contains(self)
    }
}

extension AuditLog {
    @discardableResult
    public func append(_ event: AuditEvent, profile: String? = nil, ok: Bool = true, detail: [String: String] = [:],
                       requester: String? = nil) throws -> AuditEntry {
        try append(event.rawValue, profile: profile, ok: ok, detail: detail, requester: requester)
    }
}

extension AuditEntry {
    /// Nil for an event this version does not know (written by a newer one, or a test).
    public var kind: AuditEvent? { AuditEvent(rawValue: event) }
    public var title: String { kind?.title ?? event }
}
