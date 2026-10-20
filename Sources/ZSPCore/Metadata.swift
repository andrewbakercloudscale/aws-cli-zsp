import Foundation

/// What zsp knows about a profile that is not secret: enough for the menu bar to show what
/// is in use without reading the Keychain.
public struct ProfileMeta: Codable, Equatable, Identifiable, Sendable {
    public var profile: String
    public var accessKeyId: String
    public var importedAt: Date
    public var source: String
    public var temporary: Bool
    public var rotatedAt: Date?
    public var previousKeyId: String?
    public var sessionExpiresAt: Date?
    public var sessionsRevokedAt: Date?
    public var lastUsedAt: Date?
    public var lastRequester: String?
    public var account: String?
    public var arn: String?
    public var keyStatus: String?
    /// This Mac's virtual MFA device, after `aws-cli-zsp mfa setup`.
    public var mfaSerial: String?
    /// AWS refuses the key without MFA (`aws-cli-zsp mfa enforce`).
    public var mfaEnforced: Bool?
    /// The MFA device (your phone) whose codes approve a session when nobody is at the Mac.
    public var remoteSerial: String?
    /// For display only: the account in the Keychain pin, which is what is checked.
    public var pinnedAccount: String?
    /// What IAM refused this key's user (learned, or from a policy simulation).
    public var iamDenied: [IAMPermission]?
    /// Set by hand: read-only (a client's key) or full. Nil: what IAM says.
    public var access: AccessLevel?
    /// Not stored: whether the key is in the Keychain right now.
    public var inKeychain: Bool?

    public var id: String { profile }
    public var maskedKeyId: String { maskKeyId(accessKeyId) }

    public func sessionActive(at now: Date = Date()) -> Bool {
        sessionExpiresAt.map { $0 > now } ?? false
    }
}

public final class MetadataStore {
    let paths: Paths

    public init(paths: Paths) {
        self.paths = paths
    }

    public func all() -> [String: ProfileMeta] {
        (try? load()) ?? [:]
    }

    /// Throws when profiles.json is there but unreadable, so `update` never writes over it.
    func load() throws -> [String: ProfileMeta] {
        guard let data = try? Data(contentsOf: paths.metadataFile) else { return [:] }
        let list: [ProfileMeta]
        do {
            list = try ZSPJSON.decoder.decode([ProfileMeta].self, from: data)
        } catch {
            Log.errorOnce("metadata", "\(paths.metadataFile.lastPathComponent) does not decode: \(error)")
            throw error
        }
        return Dictionary(list.map { ($0.profile, $0) }, uniquingKeysWith: { _, b in b })
    }

    public func update(_ profile: String, _ body: (inout ProfileMeta?) -> Void) throws {
        try paths.ensureSupportDir()
        try withFileLock(paths.lock("metadata")) {
            var map: [String: ProfileMeta]
            do {
                map = try load()
            } catch {
                // Kept for support rather than lost: the keys themselves are in the vault, and the
                // next Check in AWS or session fills most of this in again.
                let aside = paths.supportDir.appendingPathComponent("profiles.json.damaged-\(Int(Date().timeIntervalSince1970))")
                try? FileManager.default.moveItem(at: paths.metadataFile, to: aside)
                Log.error("metadata", "moved the damaged profiles.json to \(aside.lastPathComponent) and started a new one")
                map = [:]
            }
            var entry = map[profile]
            body(&entry)
            map[profile] = entry
            let data = try ZSPJSON.encoder.encode(map.values.sorted { $0.profile < $1.profile })
            try writeAtomically(String(decoding: data, as: UTF8.self), to: paths.metadataFile)
        }
    }
}

public struct Settings: Codable, Equatable, Sendable {
    public static let minSeconds = 900
    public static let maxSeconds = 43_200

    public var sessionSeconds: Int = 3600
    public var profileSessionSeconds: [String: Int] = [:]
    /// The watcher moves new keys in by itself. Optional, like the two below, so settings files
    /// written before they existed still load.
    public var autoImport: Bool?
    /// Profiles you chose to leave in plain text: never moved automatically.
    public var keepPlaintext: [String]?
    /// Setup has run (in the app, or `aws-cli-zsp setup`). Until then the watcher moves nothing,
    /// so the first look at your files is yours.
    public var onboarded: Bool?

    public init() {}

    public var watching: Bool { onboarded == true && autoImport != false }
    public var kept: Set<String> { Set(keepPlaintext ?? []) }

    public func duration(for profile: String) -> Int {
        min(max(profileSessionSeconds[profile] ?? sessionSeconds, Self.minSeconds), Self.maxSeconds)
    }

    public static func load(_ paths: Paths) -> Settings {
        guard let data = try? Data(contentsOf: paths.settingsFile) else { return Settings() }
        do {
            return try ZSPJSON.decoder.decode(Settings.self, from: data)
        } catch {
            // The defaults are the safe side: not set up, so the watcher moves nothing.
            Log.errorOnce("settings", "settings.json does not decode, using the defaults: \(error)")
            return Settings()
        }
    }

    public func save(_ paths: Paths) throws {
        try paths.ensureSupportDir()
        try writeAtomically(String(decoding: try ZSPJSON.encoder.encode(self), as: UTF8.self), to: paths.settingsFile)
    }
}
