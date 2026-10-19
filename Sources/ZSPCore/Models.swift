import Foundation

public enum ZSPError: Error, LocalizedError, Equatable {
    case keychain(Int32, String)
    case notFound(String)
    case auth(String)
    case aws(code: String, message: String)
    case invalid(String)
    case io(String)

    public var errorDescription: String? {
        switch self {
        case let .keychain(status, message): return "Keychain error \(status): \(message)"
        case let .notFound(m), let .auth(m), let .invalid(m), let .io(m): return m
        case let .aws(code, message): return "AWS \(code): \(message)"
        }
    }
}

public struct AWSCredentials: Codable, Equatable, Sendable {
    public var accessKeyId: String
    public var secretAccessKey: String
    public var sessionToken: String?
    public var expiration: Date?

    public init(accessKeyId: String, secretAccessKey: String, sessionToken: String? = nil, expiration: Date? = nil) {
        self.accessKeyId = accessKeyId
        self.secretAccessKey = secretAccessKey
        self.sessionToken = sessionToken
        self.expiration = expiration
    }
}

/// The long-lived key. It lives only in the Keychain and is only ever read after Touch ID.
public struct MasterKey: Codable, Equatable, Sendable {
    public var accessKeyId: String
    public var secretAccessKey: String
    /// Set when temporary credentials were pasted into the file: they are served as they are.
    public var sessionToken: String?
    public var importedAt: Date
    public var source: String

    public var credentials: AWSCredentials {
        AWSCredentials(accessKeyId: accessKeyId, secretAccessKey: secretAccessKey, sessionToken: sessionToken)
    }
}

public struct CallerIdentity: Codable, Equatable, Sendable {
    public var account: String
    public var arn: String
    public var userId: String
}

public struct AccessKeyInfo: Codable, Equatable, Sendable {
    public var accessKeyId: String
    public var status: String
    public var createDate: Date?
}

public struct AccessKeyLastUsed: Codable, Equatable, Sendable {
    public var lastUsedDate: Date?
    public var serviceName: String?
    public var region: String?
}

/// AKIAIOSFODNN7EXAMPLE → AKIA…MPLE. Key ids are not secret, but there is no reason to
/// spread them around either.
public func maskKeyId(_ id: String) -> String {
    id.count > 8 ? "\(id.prefix(4))…\(id.suffix(4))" : "…"
}

public enum ZSPJSON {
    public static let encoder: JSONEncoder = {
        let e = JSONEncoder()
        e.dateEncodingStrategy = .iso8601
        e.outputFormatting = [.sortedKeys]
        return e
    }()
    public static let decoder: JSONDecoder = {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .iso8601
        return d
    }()
}

public func iso8601(_ d: Date) -> String {
    let f = ISO8601DateFormatter()
    f.formatOptions = [.withInternetDateTime]
    return f.string(from: d)
}

public func parseISO8601(_ s: String) -> Date? {
    let f = ISO8601DateFormatter()
    f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    if let d = f.date(from: s) { return d }
    f.formatOptions = [.withInternetDateTime]
    return f.date(from: s)
}

/// "1h", "90m", "3600" → seconds.
public func parseDuration(_ s: String) -> Int? {
    let t = s.trimmingCharacters(in: .whitespaces).lowercased()
    let units: [(String, Int)] = [("h", 3600), ("m", 60), ("s", 1)]
    for (u, mult) in units where t.hasSuffix(u) {
        return Int(t.dropLast()).map { $0 * mult }
    }
    return Int(t)
}
