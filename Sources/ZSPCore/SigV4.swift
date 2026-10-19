import CryptoKit
import Foundation

/// AWS Signature Version 4, written out so zsp never hands a key to another program to sign
/// with.
public enum SigV4 {
    public static func amzDate(_ d: Date) -> String {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(identifier: "UTC")
        f.dateFormat = "yyyyMMdd'T'HHmmss'Z'"
        return f.string(from: d)
    }

    public static func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    static func hmac(_ key: Data, _ message: String) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: Data(message.utf8), using: SymmetricKey(data: key)))
    }

    static let unreserved = Set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~".utf8)

    /// RFC 3986 encoding: everything but unreserved characters is percent-encoded.
    public static func uriEncode(_ s: String) -> String {
        var out = ""
        for byte in s.utf8 {
            if unreserved.contains(byte) {
                out.append(Character(UnicodeScalar(byte)))
            } else {
                out += String(format: "%%%02X", byte)
            }
        }
        return out
    }

    public static func formEncode(_ items: [(String, String)]) -> String {
        items.map { "\(uriEncode($0.0))=\(uriEncode($0.1))" }.joined(separator: "&")
    }

    public static func canonicalRequest(method: String, path: String, query: [(String, String)],
                                        headers: [String: String], payloadHash: String) -> (request: String, signedHeaders: String) {
        let encoded: [(String, String)] = query.map { (uriEncode($0.0), uriEncode($0.1)) }
        let sortedQuery = encoded.sorted { a, b in a.0 == b.0 ? a.1 < b.1 : a.0 < b.0 }
        let canonicalQuery = sortedQuery.map { "\($0.0)=\($0.1)" }.joined(separator: "&")
        var normalised: [(String, String)] = []
        for (name, value) in headers {
            let collapsed = value.split(separator: " ").joined(separator: " ")
            normalised.append((name.lowercased(), collapsed))
        }
        normalised.sort { $0.0 < $1.0 }
        let canonicalHeaders = normalised.map { "\($0.0):\($0.1)\n" }.joined()
        let signedHeaders = normalised.map { $0.0 }.joined(separator: ";")
        let request = [method, path, canonicalQuery, canonicalHeaders, signedHeaders, payloadHash].joined(separator: "\n")
        return (request, signedHeaders)
    }

    public static func signingKey(secret: String, date: String, region: String, service: String) -> Data {
        let kDate = hmac(Data("AWS4\(secret)".utf8), date)
        let kRegion = hmac(kDate, region)
        let kService = hmac(kRegion, service)
        return hmac(kService, "aws4_request")
    }

    /// The value for the Authorization header. `headers` must already hold host and
    /// x-amz-date (and x-amz-security-token for temporary credentials).
    public static func authorization(method: String, path: String, query: [(String, String)], headers: [String: String],
                                     payload: Data, credentials: AWSCredentials, region: String, service: String,
                                     date: Date) -> String {
        let amz = amzDate(date)
        let day = String(amz.prefix(8))
        let (request, signedHeaders) = canonicalRequest(method: method, path: path, query: query, headers: headers,
                                                        payloadHash: sha256Hex(payload))
        let scope = "\(day)/\(region)/\(service)/aws4_request"
        let toSign = ["AWS4-HMAC-SHA256", amz, scope, sha256Hex(Data(request.utf8))].joined(separator: "\n")
        let key = signingKey(secret: credentials.secretAccessKey, date: day, region: region, service: service)
        let signature = hmac(key, toSign).map { String(format: "%02x", $0) }.joined()
        return "AWS4-HMAC-SHA256 Credential=\(credentials.accessKeyId)/\(scope), SignedHeaders=\(signedHeaders), Signature=\(signature)"
    }
}
