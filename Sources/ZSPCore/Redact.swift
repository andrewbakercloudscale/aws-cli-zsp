import Foundation

/// Takes secrets out of text bound for a log or a support report. The support log and the
/// diagnostics report only ever hold what passed through here.
public enum Redact {
    /// AKIA…/ASIA… key ids are masked, not removed: support needs to tell keys apart.
    static let keyId = try! NSRegularExpression(pattern: "\\b(AKIA|ASIA|AIDA|AROA)[A-Z0-9]{12,}\\b")
    /// Secret keys (40 characters) and session tokens (hundreds): long runs of base64.
    static let blob = try! NSRegularExpression(pattern: "(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=_-])")
    /// MFA seeds: base32, upper case and digits 2–7, 32 characters or more.
    static let base32 = try! NSRegularExpression(pattern: "(?<![A-Za-z0-9])[A-Z2-7]{32,}={0,6}(?![A-Za-z0-9])")
    /// `secret=…` in an otpauth:// URI, `aws_secret_access_key = …` in a file, a seed or code
    /// after its name. The name must start a word: AWS's "ExpiredToken: The security token…"
    /// is an error code, not a token.
    static let named = try! NSRegularExpression(
        pattern: "(?i)(?<![A-Za-z])(secret|seed|token|password|aws_secret_access_key|aws_session_token|SecretAccessKey|SessionToken)(\"?\\s*[=:]\\s*\"?)[^\\s\"&,;]+")

    public static func scrub(_ text: String) -> String {
        var out = replace(named, in: text) { m, s in
            "\(s.substring(with: m.range(at: 1)))\(s.substring(with: m.range(at: 2)))[redacted]"
        }
        out = replace(keyId, in: out) { m, s in maskKeyId(s.substring(with: m.range)) }
        out = replace(blob, in: out) { m, s in
            let run = s.substring(with: m.range)
            // A secret key is exactly 40 characters, and one in a few hundred has no digit or no
            // capital, so that length always goes, except lower-case hex (a SHA-1, a commit).
            if run.count == 40 { return run.allSatisfy(\.isHexDigit) && run == run.lowercased() ? run : "[redacted]" }
            // Any other long path or word is not a secret: a token mixes cases and digits.
            let mixed = run.contains(where: \.isUppercase) && run.contains(where: \.isLowercase) && run.contains(where: \.isNumber)
            return mixed ? "[redacted]" : run
        }
        return replace(base32, in: out) { _, _ in "[redacted]" }
    }

    static func replace(_ re: NSRegularExpression, in text: String, _ with: (NSTextCheckingResult, NSString) -> String) -> String {
        let s = text as NSString
        var out = ""
        var last = 0
        for m in re.matches(in: text, range: NSRange(location: 0, length: s.length)) {
            out += s.substring(with: NSRange(location: last, length: m.range.location - last))
            out += with(m, s)
            last = m.range.location + m.range.length
        }
        return out + s.substring(from: last)
    }

    /// An account id with only its last four digits: enough to tell accounts apart in a report.
    public static func account(_ id: String) -> String {
        id.count > 4 ? String(repeating: "•", count: id.count - 4) + id.suffix(4) : id
    }

    /// The home folder as ~, so a report does not carry the user name.
    public static func home(_ text: String) -> String {
        text.replacingOccurrences(of: FileManager.default.homeDirectoryForCurrentUser.path, with: "~")
    }
}
