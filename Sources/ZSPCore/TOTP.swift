import CryptoKit
import Foundation

/// RFC 6238 time-based one-time codes, as an authenticator app makes them (SHA-1, 6 digits,
/// 30 seconds): what AWS expects from a virtual MFA device.
public enum TOTP {
    public static let period: TimeInterval = 30

    public static func counter(at date: Date) -> UInt64 {
        UInt64(max(0, date.timeIntervalSince1970) / period)
    }

    public static func code(secret: Data, counter: UInt64, digits: Int = 6) -> String {
        var big = counter.bigEndian
        let message = Data(bytes: &big, count: 8)
        let mac = Array(HMAC<Insecure.SHA1>.authenticationCode(for: message, using: SymmetricKey(data: secret)))
        let offset = Int(mac[mac.count - 1] & 0x0f)
        let value = (UInt32(mac[offset] & 0x7f) << 24) | (UInt32(mac[offset + 1]) << 16)
            | (UInt32(mac[offset + 2]) << 8) | UInt32(mac[offset + 3])
        var modulus: UInt32 = 1
        for _ in 0..<digits { modulus *= 10 }
        let s = String(value % modulus)
        return String(repeating: "0", count: digits - s.count) + s
    }

    /// RFC 4648 base32, the form AWS and authenticator apps share seeds in. Case and padding
    /// are ignored.
    public static func base32Decode(_ text: String) -> Data? {
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
        var bits: UInt64 = 0
        var count = 0
        var out = Data()
        for ch in text.uppercased() where ch != "=" && ch != " " {
            guard let v = alphabet.firstIndex(of: ch) else { return nil }
            bits = (bits << 5) | UInt64(v)
            count += 5
            if count >= 8 {
                count -= 8
                out.append(UInt8((bits >> UInt64(count)) & 0xff))
            }
        }
        return out.isEmpty ? nil : out
    }

    public static func isCode(_ s: String) -> Bool {
        s.count == 6 && s.allSatisfy(\.isNumber)
    }
}
