import Foundation
import LocalAuthentication
import Security

public enum SecretKind: String, CaseIterable, Sendable {
    /// Long-lived access keys. Read only after Touch ID.
    case master
    /// Cached STS sessions, so every `aws` command does not ask for a finger.
    case session
    /// The last audit entry's hash: rewriting the log without zsp shows up as a mismatch.
    case auditHead = "audit-head"
    /// A copy of a long-lived key, without this Mac's MFA seed, for approval by an MFA code
    /// from your phone when nobody is at the Mac. Only made by `aws-cli-zsp remote enable`.
    case remote
    /// The AWS account and user a profile is pinned to. Only ever in the login Keychain.
    case pin
    /// A hash of the public key long-lived keys are sealed to. Only ever in the login Keychain.
    case sealingKey = "sealing-key"
}

public protocol SecretStore: AnyObject {
    func read(_ kind: SecretKind, _ account: String) throws -> Data?
    /// `read` that never puts up a macOS dialog: nil when the Keychain would have asked.
    func peek(_ kind: SecretKind, _ account: String) -> Data?
    func write(_ kind: SecretKind, _ account: String, _ data: Data) throws
    func delete(_ kind: SecretKind, _ account: String) throws
    func accounts(_ kind: SecretKind) throws -> [String]
}

/// Generic passwords in the login keychain. An item's access list trusts the binary that
/// created it, so only zsp (signed with a stable identity) reads them without a prompt; any
/// other program that asks makes macOS ask you first.
public final class KeychainStore: SecretStore {
    public let prefix: String

    public init(prefix: String = "consulting.cloudscale.zsp") {
        self.prefix = prefix
    }

    func service(_ kind: SecretKind) -> String { "\(prefix).\(kind.rawValue)" }

    func base(_ kind: SecretKind, _ account: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service(kind),
         kSecAttrAccount as String: account]
    }

    static func fail(_ status: OSStatus, _ what: String) -> ZSPError {
        let message = (SecCopyErrorMessageString(status, nil) as String?) ?? "unknown"
        return .keychain(status, "\(what): \(message)")
    }

    public func read(_ kind: SecretKind, _ account: String) throws -> Data? {
        var q = base(kind, account)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &out)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw Self.fail(status, "read \(kind.rawValue) \(account)") }
        return out as? Data
    }

    /// For the audit anchor, which is checked whenever the log changes. An item made by a
    /// different build of zsp (a debug build, an ad-hoc signature) would otherwise raise a
    /// "zsp wants to use your confidential information" password dialog on every check.
    public func peek(_ kind: SecretKind, _ account: String) -> Data? {
        var q = base(kind, account)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        q[kSecUseAuthenticationUI as String] = kSecUseAuthenticationUIFail
        var out: CFTypeRef?
        SecKeychainSetUserInteractionAllowed(false)
        defer { SecKeychainSetUserInteractionAllowed(true) }
        return SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess ? out as? Data : nil
    }

    public func write(_ kind: SecretKind, _ account: String, _ data: Data) throws {
        let status = SecItemUpdate(base(kind, account) as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if status == errSecSuccess { return }
        guard status == errSecItemNotFound else { throw Self.fail(status, "update \(kind.rawValue) \(account)") }
        var add = base(kind, account)
        add[kSecValueData as String] = data
        add[kSecAttrLabel as String] = "aws-cli-zsp \(kind.rawValue): \(account)"
        add[kSecAttrDescription as String] = "AWS credentials held by aws-cli-zsp"
        let added = SecItemAdd(add as CFDictionary, nil)
        guard added == errSecSuccess else { throw Self.fail(added, "add \(kind.rawValue) \(account)") }
    }

    public func delete(_ kind: SecretKind, _ account: String) throws {
        let status = SecItemDelete(base(kind, account) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw Self.fail(status, "delete \(kind.rawValue) \(account)") }
    }

    public func accounts(_ kind: SecretKind) throws -> [String] {
        let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                kSecAttrService as String: service(kind),
                                kSecReturnAttributes as String: true,
                                kSecMatchLimit as String: kSecMatchLimitAll]
        var out: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &out)
        if status == errSecItemNotFound { return [] }
        guard status == errSecSuccess else { throw Self.fail(status, "list \(kind.rawValue)") }
        return ((out as? [[String: Any]]) ?? []).compactMap { $0[kSecAttrAccount as String] as? String }.sorted()
    }
}

/// For tests.
public final class MemoryStore: SecretStore {
    private var items: [String: Data] = [:]
    private let lock = NSLock()
    public init() {}
    func key(_ k: SecretKind, _ a: String) -> String { "\(k.rawValue)\u{0}\(a)" }
    public func read(_ kind: SecretKind, _ account: String) throws -> Data? { lock.withLock { items[key(kind, account)] } }
    public func peek(_ kind: SecretKind, _ account: String) -> Data? { try? read(kind, account) }
    public func write(_ kind: SecretKind, _ account: String, _ data: Data) throws { lock.withLock { items[key(kind, account)] = data } }
    public func delete(_ kind: SecretKind, _ account: String) throws { lock.withLock { _ = items.removeValue(forKey: key(kind, account)) } }
    public func accounts(_ kind: SecretKind) throws -> [String] {
        lock.withLock { items.keys.compactMap { k in
            let parts = k.split(separator: "\u{0}", maxSplits: 1).map(String.init)
            return parts.count == 2 && parts[0] == kind.rawValue ? parts[1] : nil
        }.sorted() }
    }
}

/// Proof that the person at the Mac wants this: Touch ID, or the login password when Touch
/// ID is unavailable (clamshell, no sensor).
public protocol UserPresence {
    func confirm(_ reason: String) throws
}

public final class DeviceOwnerPresence: UserPresence {
    /// With an EnclaveStore the Secure Enclave asks for Touch ID itself when the key is used,
    /// so confirm only prepares the dialog's wording; asking here too would mean two prompts.
    public let enclaveGated: Bool
    public private(set) var context: LAContext?

    public init(enclaveGated: Bool = false) {
        self.enclaveGated = enclaveGated
    }

    public func confirm(_ reason: String) throws {
        let context = LAContext()
        context.localizedReason = reason
        // One approval covers the next few enclave operations of this command (restoring
        // several keys, rotate's read then write).
        context.touchIDAuthenticationAllowableReuseDuration = 30
        self.context = context
        if enclaveGated { return }
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
            throw ZSPError.auth("Touch ID or password is not available here: \(error?.localizedDescription ?? "unknown")")
        }
        final class Box: @unchecked Sendable { var ok = false; var error: Error? }
        let box = Box()
        let done = DispatchSemaphore(value: 0)
        context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { ok, error in
            box.ok = ok
            box.error = error
            done.signal()
        }
        done.wait()
        guard box.ok else { throw ZSPError.auth("Not approved: \(box.error?.localizedDescription ?? "authentication failed")") }
    }
}

/// For tests.
public final class CountingPresence: UserPresence {
    public var reasons: [String] = []
    public var deny = false
    public init() {}
    public func confirm(_ reason: String) throws {
        reasons.append(reason)
        if deny { throw ZSPError.auth("Not approved: denied in test") }
    }
}
