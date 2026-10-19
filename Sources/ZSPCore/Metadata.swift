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
        guard let data = try? Data(contentsOf: paths.metadataFile),
              let list = try? ZSPJSON.decoder.decode([ProfileMeta].self, from: data) else { return [:] }
        return Dictionary(list.map { ($0.profile, $0) }, uniquingKeysWith: { _, b in b })
    }

    public func update(_ profile: String, _ body: (inout ProfileMeta?) -> Void) throws {
        try paths.ensureSupportDir()
        try withFileLock(paths.lock("metadata")) {
            var map = all()
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

    public init() {}

    public func duration(for profile: String) -> Int {
        min(max(profileSessionSeconds[profile] ?? sessionSeconds, Self.minSeconds), Self.maxSeconds)
    }

    public static func load(_ paths: Paths) -> Settings {
        guard let data = try? Data(contentsOf: paths.settingsFile),
              let s = try? ZSPJSON.decoder.decode(Settings.self, from: data) else { return Settings() }
        return s
    }

    public func save(_ paths: Paths) throws {
        try paths.ensureSupportDir()
        try writeAtomically(String(decoding: try ZSPJSON.encoder.encode(self), as: UTF8.self), to: paths.settingsFile)
    }
}
