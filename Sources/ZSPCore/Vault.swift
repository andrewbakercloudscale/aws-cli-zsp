import Foundation

/// Everything that touches a long-lived key: moving keys in, handing out sessions, MFA,
/// rotation and the audit trail. The work is split by topic across the Vault+*.swift files;
/// this file holds what they share.
public final class Vault {
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
    /// Where account pins live (the login Keychain). Nil turns pinning off.
    public var pins: SecretStore?

    public init(paths: Paths, store: SecretStore, auth: UserPresence, aws: AWSService, commandPath: String) {
        self.paths = paths
        self.store = store
        self.auth = auth
        self.aws = aws
        self.commandPath = commandPath
        self.audit = AuditLog(paths: paths, anchor: store)
        self.meta = MetadataStore(paths: paths)
    }

    // MARK: The long-lived key

    /// The long-lived key, after the person at the Mac has approved `reason`.
    func unlock(_ profile: String, reason: String, requester: String? = nil) throws -> MasterKey {
        guard try store.accounts(.master).contains(profile) else {
            throw ZSPError.notFound("No key for profile “\(profile)” in the vault. Add one with: aws-cli-zsp add --profile \(profile)")
        }
        let data: Data?
        do {
            try auth.confirm(reason)
            data = try store.read(.master, profile)
        } catch let error as ZSPError {
            // The enclave reports a declined or cancelled Touch ID as .auth; anything else is a
            // vault that could not be read, which is not the person saying no.
            if case .auth = error {
                recordFailure(.authDenied, profile: profile, detail: ["for": reason], requester: requester, error: error)
            } else {
                Log.error("vault", "could not open the key for \(profile): \(error.localizedDescription)")
            }
            throw error
        } catch {
            Log.error("vault", "could not open the key for \(profile): \(error)")
            throw error
        }
        guard let data else { throw ZSPError.notFound("The key for “\(profile)” vanished from the vault") }
        return try decodeKey(data, profile)
    }

    func decodeKey(_ data: Data, _ profile: String) throws -> MasterKey {
        do {
            return try ZSPJSON.decoder.decode(MasterKey.self, from: data)
        } catch {
            Log.error("vault", "the sealed key for \(profile) does not decode: \(error)")
            throw ZSPError.invalid("The key stored for “\(profile)” is damaged. Add it again with: aws-cli-zsp add --profile \(profile)")
        }
    }

    public func hasMaster(_ profile: String) -> Bool {
        (try? store.accounts(.master).contains(profile)) ?? false
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
    public func storeMaster(raw: Data, profile: String) throws {
        _ = try decodeKey(raw, profile)
        try store.write(.master, profile, raw)
    }

    /// Drops the cached session and the expiry the app shows: after anything that changes
    /// which session is valid (a new key, MFA on or off, a revocation).
    func dropSession(_ profile: String) throws {
        try store.delete(.session, profile)
        bestEffort("clear the session time of \(profile)") { try meta.update(profile) { $0?.sessionExpiresAt = nil } }
    }

    // MARK: ~/.aws/config wiring

    public func credentialProcess(for profile: String) -> String {
        "\(shellQuote(commandPath)) credential-process --profile \(shellQuote(profile))"
    }

    func isOurs(_ credentialProcess: String) -> Bool {
        credentialProcess.contains(" credential-process --profile ") && credentialProcess.lowercased().contains("zsp")
    }

    /// Reads ~/.aws/config, lets `body` change it, and writes it back only if it changed.
    func editConfig(_ body: (inout INIDocument) -> Void) throws {
        let text = try paths.text(paths.configFile)
        var config = INIDocument(text)
        body(&config)
        if config.text != text { try writeAtomically(config.text, to: paths.configFile) }
    }

    func wire(_ profiles: [String], in config: inout INIDocument) {
        for p in profiles { config.set("credential_process", credentialProcess(for: p), in: AWSFiles.configSection(for: p)) }
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

    // MARK: Failures that must not hide the real one

    /// For a step whose failure must not undo what already happened (a note in profiles.json,
    /// tidying up): the failure goes to the support log instead of being lost.
    func bestEffort(_ what: String, _ body: () throws -> Void) {
        do { try body() } catch { Log.warning("vault", "could not \(what): \(error.localizedDescription)") }
    }

    /// Audits a failure and logs it for support. Never throws, so the error the caller is
    /// about to rethrow is the one the user sees.
    func recordFailure(_ event: AuditEvent, profile: String?, detail: [String: String] = [:], requester: String? = nil,
                       error: Error? = nil) {
        var detail = detail
        if let error, detail["error"] == nil { detail["error"] = error.localizedDescription }
        Log.error("vault", "\(event.rawValue) \(profile ?? "-"): \(detail.sorted { $0.key < $1.key }.map { "\($0.key)=\($0.value)" }.joined(separator: " "))")
        bestEffort("audit \(event.rawValue)") { try audit.append(event, profile: profile, ok: false, detail: detail, requester: requester) }
    }
}
