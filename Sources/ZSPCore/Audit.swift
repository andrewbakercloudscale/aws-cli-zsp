import Foundation

public struct AuditEntry: Codable, Equatable, Identifiable, Sendable {
    public var seq: Int
    public var ts: String
    public var event: String
    public var profile: String?
    public var ok: Bool
    public var detail: [String: String]
    public var requester: String?
    /// The previous entry's hash: deleting or editing a line breaks the chain after it.
    public var prev: String
    public var hash: String

    public var id: Int { seq }
    public var date: Date? { parseISO8601(ts) }
}

public struct AuditVerification: Codable, Equatable, Sendable {
    public var entries: Int
    public var intact: Bool
    /// Whether the newest entry matches the copy of its hash kept in the Keychain.
    public var anchored: Bool?
    public var problem: String?
}

/// An append-only, hash-chained JSON Lines log of everything zsp does with a key.
public final class AuditLog {
    public static let genesis = "genesis"
    static let rotateBytes = 5 * 1024 * 1024

    let paths: Paths
    /// Where the head hash is anchored. nil for readers that only display the log.
    let anchor: SecretStore?

    public init(paths: Paths, anchor: SecretStore?) {
        self.paths = paths
        self.anchor = anchor
    }

    static func digest(_ e: AuditEntry) -> String {
        var body = e
        body.hash = ""
        let data = (try? ZSPJSON.encoder.encode(body)) ?? Data()
        return SigV4.sha256Hex(data)
    }

    @discardableResult
    public func append(_ event: String, profile: String? = nil, ok: Bool = true, detail: [String: String] = [:],
                       requester: String? = nil) throws -> AuditEntry {
        try paths.ensureSupportDir()
        return try withFileLock(paths.lock("audit")) {
            let head = readHead()
            let f = ISO8601DateFormatter()
            f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
            var e = AuditEntry(seq: head.seq + 1, ts: f.string(from: Date()), event: event, profile: profile, ok: ok,
                               detail: detail, requester: requester, prev: head.hash, hash: "")
            e.hash = Self.digest(e)
            let fm = FileManager.default
            if let size = (try? fm.attributesOfItem(atPath: paths.auditFile.path))?[.size] as? Int, size > Self.rotateBytes {
                let archived = paths.supportDir.appendingPathComponent("audit-\(SigV4.amzDate(Date())).jsonl")
                try? fm.moveItem(at: paths.auditFile, to: archived)
            }
            var line = try ZSPJSON.encoder.encode(e)
            line.append(UInt8(ascii: "\n"))
            let fd = open(paths.auditFile.path, O_CREAT | O_WRONLY | O_APPEND, 0o600)
            guard fd >= 0 else { throw ZSPError.io("cannot open the audit log: \(String(cString: strerror(errno)))") }
            defer { close(fd) }
            let written = line.withUnsafeBytes { write(fd, $0.baseAddress, $0.count) }
            guard written == line.count else { throw ZSPError.io("cannot write the audit log: \(String(cString: strerror(errno)))") }
            let headLine = "\(e.seq) \(e.hash)"
            try writeAtomically(headLine + "\n", to: paths.auditHeadFile)
            try anchor?.write(.auditHead, "head", Data(headLine.utf8))
            return e
        }
    }

    func readHead() -> (seq: Int, hash: String) {
        if let text = try? String(contentsOf: paths.auditHeadFile, encoding: .utf8) {
            let parts = text.trimmingCharacters(in: .whitespacesAndNewlines).split(separator: " ")
            if parts.count == 2, let seq = Int(parts[0]) { return (seq, String(parts[1])) }
        }
        if let last = entries(limit: 1).last { return (last.seq, last.hash) }
        return (0, Self.genesis)
    }

    /// The newest `limit` entries of the current log, oldest first.
    public func entries(limit: Int? = nil) -> [AuditEntry] {
        guard let data = try? Data(contentsOf: paths.auditFile) else { return [] }
        var lines = data.split(separator: UInt8(ascii: "\n"))
        if let limit, lines.count > limit { lines = Array(lines.suffix(limit)) }
        return lines.compactMap { try? ZSPJSON.decoder.decode(AuditEntry.self, from: Data($0)) }
    }

    public func verify() -> AuditVerification {
        guard let data = try? Data(contentsOf: paths.auditFile) else {
            return AuditVerification(entries: 0, intact: true, anchored: nil, problem: nil)
        }
        var previous: AuditEntry?
        var count = 0
        for (n, raw) in data.split(separator: UInt8(ascii: "\n")).enumerated() {
            guard let e = try? ZSPJSON.decoder.decode(AuditEntry.self, from: Data(raw)) else {
                return AuditVerification(entries: count, intact: false, anchored: nil, problem: "line \(n + 1) is not an audit entry")
            }
            if Self.digest(e) != e.hash {
                return AuditVerification(entries: count, intact: false, anchored: nil, problem: "entry \(e.seq) was altered")
            }
            if let p = previous, e.prev != p.hash || e.seq != p.seq + 1 {
                return AuditVerification(entries: count, intact: false, anchored: nil, problem: "entries are missing before \(e.seq)")
            }
            if previous == nil, e.seq == 1, e.prev != Self.genesis {
                return AuditVerification(entries: count, intact: false, anchored: nil, problem: "the first entry does not start the chain")
            }
            previous = e
            count += 1
        }
        var anchored: Bool?
        var problem: String?
        if let anchor, let stored = anchor.peek(.auditHead, "head").map({ String(decoding: $0, as: UTF8.self) }) {
            anchored = previous.map { "\($0.seq) \($0.hash)" } == stored
            if anchored == false { problem = "the log does not end where zsp last wrote it (Keychain head \(stored.prefix(20))…)" }
        }
        return AuditVerification(entries: count, intact: anchored != false, anchored: anchored, problem: problem)
    }
}
