import CryptoKit
import Foundation
import LocalAuthentication
import Security

/// Secrets sealed to this Mac's Secure Enclave.
///
/// Each secret is encrypted (P-256 ECDH, HKDF-SHA256, AES-GCM) to a Secure Enclave key that
/// never leaves the chip. The long-lived access keys use a key created with `.userPresence`,
/// so the chip itself refuses to decrypt them until you have used Touch ID (or your password)
/// for that request. Sessions and the audit anchor use a second enclave key with no prompt,
/// which keeps them unreadable off this Mac and out of a plain `cat`.
///
/// Why not ordinary Keychain items: on macOS an item made by a binary with no Apple Team ID
/// is bound to that build's exact code hash. Every update then hit a "wants to use your
/// confidential information" *password* dialog with no Touch ID, for its own keys. The
/// enclave does not care which build asks; it cares that your finger did.
public final class EnclaveStore: SecretStore {
    enum Tier: String { case guarded, open }

    let dir: URL
    /// The LAContext carrying the reason shown in the Touch ID dialog, set by
    /// DeviceOwnerPresence just before a guarded read.
    public var context: () -> LAContext? = { nil }
    /// Where the hash of the guarded public key is pinned (the login Keychain). Sealing needs
    /// only that public key, read from a file anything running as you can rewrite: without
    /// the pin, a program could swap in its own key and read every key sealed after that.
    public var keyPins: SecretStore?

    public init(dir: URL) {
        self.dir = dir
    }

    public static var isAvailable: Bool { SecureEnclave.isAvailable }

    static func tier(_ kind: SecretKind) -> Tier { kind == .master ? .guarded : .open }

    func itemURL(_ kind: SecretKind, _ account: String) -> URL {
        let hex = Data(account.utf8).map { String(format: "%02x", $0) }.joined()
        return dir.appendingPathComponent("\(kind.rawValue)/\(hex).sealed")
    }

    func keyURL(_ t: Tier) -> URL { dir.appendingPathComponent("keys/\(t.rawValue).enclave-key") }
    func publicKeyURL(_ t: Tier) -> URL { dir.appendingPathComponent("keys/\(t.rawValue).public") }

    func ensureDir(_ url: URL) throws {
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    }

    /// Writing needs only the public half, so moving a key in never asks for Touch ID.
    func publicKey(_ t: Tier) throws -> P256.KeyAgreement.PublicKey {
        if let raw = try? Data(contentsOf: publicKeyURL(t)) {
            let key = try P256.KeyAgreement.PublicKey(x963Representation: raw)
            if t == .guarded { try checkGuarded(raw) }
            return key
        }
        guard SecureEnclave.isAvailable else { throw ZSPError.invalid("this Mac has no Secure Enclave") }
        var error: Unmanaged<CFError>?
        let flags: SecAccessControlCreateFlags = t == .guarded ? [.privateKeyUsage, .userPresence] : [.privateKeyUsage]
        guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, &error) else {
            throw ZSPError.invalid("cannot create the enclave access policy: \(error?.takeRetainedValue().localizedDescription ?? "?")")
        }
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
        try ensureDir(keyURL(t).deletingLastPathComponent())
        try writeData(key.dataRepresentation, to: keyURL(t))
        try writeData(key.publicKey.x963Representation, to: publicKeyURL(t))
        if t == .guarded { try checkGuarded(key.publicKey.x963Representation) }
        return key.publicKey
    }

    /// Refuses to seal to a guarded public key that is not this vault's: it must belong to the
    /// enclave key beside it, and match the hash pinned the first time it was used.
    func checkGuarded(_ raw: Data) throws {
        func refuse(_ why: String) -> ZSPError {
            Log.error("vault", "refused to seal: \(why)")
            return .auth("""
                Nothing was stored: the vault's sealing key (\(publicKeyURL(.guarded).path)) is not the one this Mac \
                created (\(why)). Something running as you may have replaced it. Run aws-cli-zsp doctor.
                """)
        }
        if let blob = try? Data(contentsOf: keyURL(.guarded)) {
            // Rebuilding the key object from its blob and reading its public half needs no Touch ID.
            let paired = try? SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: blob).publicKey.x963Representation
            guard paired == raw else { throw refuse("it does not belong to the enclave key beside it") }
        }
        guard let keyPins else { return }
        let hash = Data(SigV4.sha256Hex(raw).utf8)
        let pinned: Data?
        do {
            pinned = try keyPins.read(.sealingKey, "guarded")
        } catch {
            throw ZSPError.keychain(-1, "Could not read the pinned sealing key from the login Keychain (\(error.localizedDescription)). Unlock the Mac and try again.")
        }
        guard let pinned else {
            try keyPins.write(.sealingKey, "guarded", hash)
            Log.info("vault", "pinned the sealing key")
            return
        }
        guard pinned == hash else { throw refuse("it does not match the key pinned in the login Keychain") }
    }

    func privateKey(_ t: Tier) throws -> SecureEnclave.P256.KeyAgreement.PrivateKey {
        guard let blob = try? Data(contentsOf: keyURL(t)) else { throw ZSPError.notFound("no enclave key yet") }
        return try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: blob, authenticationContext: t == .guarded ? context() : nil)
    }

    static func derive(_ shared: SharedSecret, _ epk: Data) -> SymmetricKey {
        shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: epk, sharedInfo: Data("aws-cli-zsp v1".utf8), outputByteCount: 32)
    }

    struct Envelope: Codable {
        var v: Int
        var epk: Data
        var box: Data
    }

    /// The item's name is bound in as associated data, so one profile's sealed key cannot be
    /// swapped in for another's.
    static func aad(_ kind: SecretKind, _ account: String) -> Data { Data("\(kind.rawValue)\u{0}\(account)".utf8) }

    public func write(_ kind: SecretKind, _ account: String, _ data: Data) throws {
        let ephemeral = P256.KeyAgreement.PrivateKey()
        let epk = ephemeral.publicKey.x963Representation
        let shared = try ephemeral.sharedSecretFromKeyAgreement(with: try publicKey(Self.tier(kind)))
        let box = try AES.GCM.seal(data, using: Self.derive(shared, epk), authenticating: Self.aad(kind, account))
        guard let combined = box.combined else { throw ZSPError.io("AES-GCM gave no sealed box for \(kind.rawValue) \(account)") }
        let sealed = try JSONEncoder().encode(Envelope(v: 1, epk: epk, box: combined))
        let url = itemURL(kind, account)
        try ensureDir(url.deletingLastPathComponent())
        try writeData(sealed, to: url)
        guard (try? Data(contentsOf: url)) == sealed else { throw ZSPError.io("the sealed \(kind.rawValue) for \(account) did not read back") }
    }

    public func read(_ kind: SecretKind, _ account: String) throws -> Data? {
        guard let raw = try? Data(contentsOf: itemURL(kind, account)) else { return nil }
        let env: Envelope
        do {
            env = try JSONDecoder().decode(Envelope.self, from: raw)
        } catch {
            Log.error("vault", "\(itemURL(kind, account).lastPathComponent) (\(kind.rawValue) \(account)) is not a sealed item: \(error)")
            throw ZSPError.invalid("The sealed \(kind.rawValue) for “\(account)” is damaged")
        }
        let shared: SharedSecret
        do {
            let epk = try P256.KeyAgreement.PublicKey(x963Representation: env.epk)
            shared = try privateKey(Self.tier(kind)).sharedSecretFromKeyAgreement(with: epk)
        } catch {
            if Self.tier(kind) == .guarded { throw ZSPError.auth("Not approved: \(error.localizedDescription)") }
            throw error
        }
        let box = try AES.GCM.SealedBox(combined: env.box)
        return try AES.GCM.open(box, using: Self.derive(shared, env.epk), authenticating: Self.aad(kind, account))
    }

    public func peek(_ kind: SecretKind, _ account: String) -> Data? {
        Self.tier(kind) == .open ? (try? read(kind, account)) ?? nil : nil
    }

    public func delete(_ kind: SecretKind, _ account: String) throws {
        let url = itemURL(kind, account)
        if FileManager.default.fileExists(atPath: url.path) { try FileManager.default.removeItem(at: url) }
    }

    public func accounts(_ kind: SecretKind) throws -> [String] {
        let names = (try? FileManager.default.contentsOfDirectory(atPath: dir.appendingPathComponent(kind.rawValue).path)) ?? []
        return names.compactMap { name -> String? in
            guard name.hasSuffix(".sealed") else { return nil }
            let hex = Array(name.dropLast(".sealed".count))
            guard hex.count % 2 == 0 else { return nil }
            var bytes: [UInt8] = []
            var i = 0
            while i < hex.count {
                guard let b = UInt8(String(hex[i..<i + 2]), radix: 16) else { return nil }
                bytes.append(b)
                i += 2
            }
            return String(bytes: bytes, encoding: .utf8)
        }.sorted()
    }

    func writeData(_ data: Data, to url: URL) throws {
        try replaceFile(data, at: url)
    }
}
