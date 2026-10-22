import Foundation

/// The AWS credentials and config files, edited line by line so that comments, ordering and
/// settings zsp does not own survive a rewrite untouched.
public struct INIDocument: Equatable {
    public struct Line: Equatable {
        public enum Kind: Equatable {
            case section(String)
            case pair(key: String, value: String)
            /// Blank lines, comments and indented continuation lines (`s3 =` sub-settings).
            case other
        }
        public var raw: String
        public var kind: Kind
        /// The section the line sits in; a header's own name for a header.
        public var section: String?
    }

    public private(set) var lines: [Line] = []
    private var trailingNewline = true

    public init(_ text: String) {
        trailingNewline = text.isEmpty || text.hasSuffix("\n")
        var raws = text.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        if text.hasSuffix("\n") || text.isEmpty { raws.removeLast() }
        var current: String?
        var inPair = false
        for raw in raws {
            let stripped = raw.hasSuffix("\r") ? String(raw.dropLast()) : raw
            let t = stripped.trimmingCharacters(in: .whitespaces)
            let kind: Line.Kind
            if t.hasPrefix("[") && t.hasSuffix("]") && t.count >= 2 {
                let name = String(t.dropFirst().dropLast()).trimmingCharacters(in: .whitespaces)
                current = name
                kind = .section(name)
                inPair = false
            } else if t.isEmpty || t.hasPrefix("#") || t.hasPrefix(";") {
                kind = .other
                inPair = false
            } else if inPair, let first = stripped.first, first == " " || first == "\t" {
                kind = .other
            } else if let eq = t.firstIndex(of: "=") {
                let key = t[..<eq].trimmingCharacters(in: .whitespaces).lowercased()
                let value = t[t.index(after: eq)...].trimmingCharacters(in: .whitespaces)
                kind = .pair(key: key, value: value)
                inPair = true
            } else {
                kind = .other
                inPair = false
            }
            lines.append(Line(raw: raw, kind: kind, section: current))
        }
    }

    public var text: String {
        lines.isEmpty ? "" : lines.map(\.raw).joined(separator: "\n") + (trailingNewline ? "\n" : "")
    }

    /// Section names in file order, each once.
    public var sectionNames: [String] {
        var seen = Set<String>()
        return lines.compactMap { line in
            if case let .section(name) = line.kind, seen.insert(name).inserted { return name }
            return nil
        }
    }

    /// The value of `key` in `section`; the last one wins when a key is repeated.
    public func value(_ key: String, in section: String) -> String? {
        lines.last { $0.section == section && $0.key == key }.flatMap(\.value)
    }

    public func hasPairs(in section: String) -> Bool {
        lines.contains { $0.section == section && $0.key != nil }
    }

    /// Removes every `keys` pair in `section`, with any continuation lines under them.
    @discardableResult
    public mutating func remove(keys: Set<String>, in section: String) -> Int {
        var removed = 0
        var dropping = false
        lines = lines.filter { line in
            if line.section == section, let key = line.key {
                dropping = keys.contains(key)
                if dropping { removed += 1 }
                return !dropping
            }
            if case .section = line.kind { dropping = false; return true }
            if dropping, line.kind == .other, let first = line.raw.first, first == " " || first == "\t",
               !line.raw.trimmingCharacters(in: .whitespaces).isEmpty {
                return false
            }
            dropping = false
            return true
        }
        return removed
    }

    /// Sets `key` in `section`, replacing the existing pair or adding one at the end of the
    /// section. A missing section is appended to the file.
    public mutating func set(_ key: String, _ value: String, in section: String) {
        let raw = "\(key) = \(value)"
        if let i = lines.lastIndex(where: { $0.section == section && $0.key == key }) {
            lines[i] = Line(raw: raw, kind: .pair(key: key, value: value), section: section)
            return
        }
        trailingNewline = true
        if let header = lines.firstIndex(where: { $0.kind == .section(section) }) {
            var insertAt = header + 1
            var j = header + 1
            while j < lines.count, lines[j].isHeader == false {
                if !lines[j].raw.trimmingCharacters(in: .whitespaces).isEmpty { insertAt = j + 1 }
                j += 1
            }
            lines.insert(Line(raw: raw, kind: .pair(key: key, value: value), section: section), at: insertAt)
            return
        }
        if let last = lines.last, !last.raw.trimmingCharacters(in: .whitespaces).isEmpty {
            lines.append(Line(raw: "", kind: .other, section: last.section))
        }
        lines.append(Line(raw: "[\(section)]", kind: .section(section), section: section))
        lines.append(Line(raw: raw, kind: .pair(key: key, value: value), section: section))
    }

    /// Drops the header of a section left with no settings, and the blank line before it.
    public mutating func removeHeaderIfEmpty(_ section: String) {
        guard !hasPairs(in: section) else { return }
        var i = 0
        while i < lines.count {
            if lines[i].kind == .section(section) {
                lines.remove(at: i)
                if i > 0, lines[i - 1].raw.trimmingCharacters(in: .whitespaces).isEmpty,
                   i == lines.count || lines[i].isHeader || lines[i].raw.trimmingCharacters(in: .whitespaces).isEmpty {
                    lines.remove(at: i - 1)
                    i -= 1
                }
            } else {
                i += 1
            }
        }
        while let first = lines.first, first.raw.trimmingCharacters(in: .whitespaces).isEmpty { lines.removeFirst() }
    }

    public mutating func prepend(comments: [String]) {
        let section = lines.first?.isHeader == true ? nil : lines.first?.section
        lines.insert(contentsOf: comments.map { Line(raw: $0, kind: .other, section: section) }, at: 0)
        trailingNewline = true
    }
}

extension INIDocument.Line {
    var key: String? { if case let .pair(k, _) = kind { return k }; return nil }
    var value: String? { if case let .pair(_, v) = kind { return v }; return nil }
    var isHeader: Bool { if case .section = kind { return true }; return false }
}

/// How the two AWS files name profiles: `[name]` in credentials, `[profile name]` in config,
/// `[default]` in both.
public enum AWSFiles {
    public static let secretKeys: Set<String> = ["aws_access_key_id", "aws_secret_access_key", "aws_session_token", "aws_security_token"]
    public static let managedMarker = "# Managed by aws-cli-zsp"

    public static func profileName(configSection s: String) -> String? {
        if s == "default" { return "default" }
        guard s.hasPrefix("profile ") else { return nil }
        let name = s.dropFirst("profile ".count).trimmingCharacters(in: .whitespaces)
        return name.isEmpty ? nil : name
    }

    public static func configSection(for profile: String) -> String {
        profile == "default" ? "default" : "profile \(profile)"
    }
}

/// Quotes for the shell-style split every AWS SDK applies to credential_process.
public func shellQuote(_ s: String) -> String {
    let safe = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_./:@+=")
    if !s.isEmpty, s.unicodeScalars.allSatisfy({ safe.contains($0) }) { return s }
    return "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'"
}

/// The words a shell-style split makes of `s`: the inverse of `shellQuote`, with double quotes
/// and backslashes as in Python's shlex, which the AWS CLI uses. Nil when a quote is left open.
public func shellWords(_ s: String) -> [String]? {
    var words: [String] = []
    var word = ""
    var inWord = false
    var quote: Character?
    var escaped = false
    for c in s {
        if escaped { word.append(c); escaped = false; continue }
        switch quote {
        case "'":
            if c == "'" { quote = nil } else { word.append(c) }
        case "\"":
            if c == "\"" { quote = nil } else if c == "\\" { escaped = true } else { word.append(c) }
        default:
            if c == "'" || c == "\"" { quote = c; inWord = true }
            else if c == "\\" { escaped = true; inWord = true }
            else if c.isWhitespace { if inWord { words.append(word); word = ""; inWord = false } }
            else { word.append(c); inWord = true }
        }
    }
    guard quote == nil, !escaped else { return nil }
    if inWord { words.append(word) }
    return words
}
