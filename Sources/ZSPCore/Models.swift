import Foundation
import Security

public enum ZSPError: Error, LocalizedError, Equatable {
    case keychain(Int32, String)
    case notFound(String)
    case auth(String)
    case aws(code: String, message: String)
    case invalid(String)
    case io(String)

    public var errorDescription: String? {
        switch self {
        case let .keychain(status, message):
            return "Keychain error \(status): \(message)" + (Self.keychainHint(status).map { ". \($0)" } ?? "")
        case let .notFound(m), let .auth(m), let .invalid(m), let .io(m): return m
        case let .aws(code, message):
            return "AWS \(code): \(message)" + (Self.awsHint(code, message).map { ". \($0)" } ?? "")
        }
    }

    /// What to do about the AWS errors people actually hit, so the message says more than the code.
    static func awsHint(_ code: String, _ message: String) -> String? {
        switch code {
        case "SignatureDoesNotMatch", "RequestExpired", "InvalidSignatureException":
            return message.lowercased().contains("expired") || code == "RequestExpired"
                ? "This Mac's clock is probably wrong: AWS refuses requests more than 5 minutes off (System Settings › General › Date & Time)"
                : "The secret does not match the key id: the key may have been pasted wrongly. Add it again with aws-cli-zsp add"
        case "InvalidClientTokenId":
            return "AWS does not know this key: it was deleted, or the key id is mistyped. Check the IAM console, or add the current key with aws-cli-zsp add"
        case "ExpiredToken":
            return "The session expired: run the command again for a new one"
        case "AccessDenied" where message.contains("MultiFactorAuthentication"):
            return "The MFA code was wrong or already used: wait for the next code and try again"
        case "Throttling":
            return "AWS is rate-limiting this key: wait a minute and try again"
        default:
            return nil
        }
    }

    static func keychainHint(_ status: Int32) -> String? {
        switch status {
        case errSecInteractionNotAllowed: return "The login Keychain is locked: unlock the Mac and try again"
        case errSecUserCanceled, errSecAuthFailed: return "The macOS prompt was cancelled or the password was wrong"
        default: return nil
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
    /// This Mac's own virtual MFA device for the key's IAM user (`aws-cli-zsp mfa setup`): its
    /// ARN and base32 seed. Sealed with the key, so one Touch ID gives both.
    public var mfaSerial: String? = nil
    public var mfaSeed: String? = nil

    /// The copy kept for approval by MFA code: the key without this Mac's MFA seed, so whoever
    /// reads it still needs a code from your phone.
    public var withoutMFASeed: MasterKey {
        var k = self
        k.mfaSeed = nil
        k.mfaSerial = nil
        return k
    }

    public var credentials: AWSCredentials {
        AWSCredentials(accessKeyId: accessKeyId, secretAccessKey: secretAccessKey, sessionToken: sessionToken)
    }
}

/// A one-time code from an MFA device, for GetSessionToken.
public struct MFACode: Equatable, Sendable {
    public var serial: String
    public var code: String

    public init(serial: String, code: String) {
        self.serial = serial
        self.code = code
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
