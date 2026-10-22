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

/// Where the chain stands: the newest entry, and the first entry of the current file (the
/// segment since the last rotation). Kept in audit.head and, sealed, in the vault, as
/// "seq hash baseSeq basePrev". The base is what catches lines cut from the top of the file,
/// or the whole file deleted: the chain that is left still links up on its own.
struct AuditHead: Equatable {
    var seq: Int
    var hash: String
    var baseSeq: Int?
    var basePrev: String?

    init(seq: Int, hash: String, baseSeq: Int? = nil, basePrev: String? = nil) {
        self.seq = seq
        self.hash = hash
        self.baseSeq = baseSeq
        self.basePrev = basePrev
    }

    /// Two fields before the base was recorded, four after.
    init?(_ text: String) {
        let parts = text.trimmingCharacters(in: .whitespacesAndNewlines).split(separator: " ").map(String.init)
        guard parts.count == 2 || parts.count == 4, let seq = Int(parts[0]) else { return nil }
        self.init(seq: seq, hash: parts[1], baseSeq: parts.count == 4 ? Int(parts[2]) : nil, basePrev: parts.count == 4 ? parts[3] : nil)
    }

    var text: String {
        guard let baseSeq, let basePrev else { return "\(seq) \(hash)" }
        return "\(seq) \(hash) \(baseSeq) \(basePrev)"
    }

    /// The newest entry, which is what the anchor vouches for.
    var tip: String { "\(seq) \(hash)" }
}

/// An append-only, hash-chained JSON Lines log of everything zsp does with a key.
public final class AuditLog {
    public static let genesis = "genesis"
    /// Archived files kept after a rotation: 20 × 5 MB. The oldest go first.
    static let keepArchives = 20
    /// The size at which the log is archived and a new file started. Smaller in tests.
    var rotateBytes = 5 * 1024 * 1024

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
            let rotated = rotateIfFull(next: e.seq)
            // A new segment starts only at the very first entry or at a rotation done here. A file
            // that vanished by itself keeps the old base, so verify still sees what is missing.
            var base = (seq: head.baseSeq, prev: head.basePrev)
            if head.seq == 0 || rotated {
                base = (e.seq, e.prev)
            } else if base.seq == nil, let first = firstEntry() {
                // Written before the base was recorded: the file's first entry is the best there is.
                base = (first.seq, first.prev)
            }
            var line = try ZSPJSON.encoder.encode(e)
            line.append(UInt8(ascii: "\n"))
            let fd = open(paths.auditFile.path, O_CREAT | O_WRONLY | O_APPEND, 0o600)
            guard fd >= 0 else { throw ZSPError.io("cannot open the audit log: \(String(cString: strerror(errno)))") }
            defer { close(fd) }
            let written = line.withUnsafeBytes { write(fd, $0.baseAddress, $0.count) }
            guard written == line.count else { throw ZSPError.io("cannot write the audit log: \(String(cString: strerror(errno)))") }
            let newHead = AuditHead(seq: e.seq, hash: e.hash, baseSeq: base.seq, basePrev: base.prev).text
            try writeAtomically(newHead + "\n", to: paths.auditHeadFile)
            // The entry is written: failing the command now would not take it back. Verify shows the
            // stale anchor until the next entry seals a new one.
            do { try anchor?.write(.auditHead, "head", Data(newHead.utf8)) } catch {
                Log.error("audit", "could not seal the anchor for entry \(e.seq): \(error.localizedDescription)")
            }
            return e
        }
    }

    /// Moves a full log aside and drops the oldest archives. Returns whether it rotated.
    func rotateIfFull(next seq: Int) -> Bool {
        let fm = FileManager.default
        guard let size = (try? fm.attributesOfItem(atPath: paths.auditFile.path))?[.size] as? Int, size > rotateBytes else { return false }
        let archived = paths.supportDir.appendingPathComponent("audit-\(SigV4.amzDate(Date()))-\(seq).jsonl")
        do { try fm.moveItem(at: paths.auditFile, to: archived) } catch {
            Log.warning("audit", "could not archive the full audit log: \(error.localizedDescription)")
            return false
        }
        let old = archives().dropLast(Self.keepArchives)
        for url in old {
            do { try fm.removeItem(at: url) } catch {
                Log.warning("audit", "could not remove the old audit archive \(url.lastPathComponent): \(error.localizedDescription)")
            }
        }
        if !old.isEmpty { Log.info("audit", "removed \(old.count) audit archive(s) beyond the newest \(Self.keepArchives)") }
        return true
    }

    /// Archived audit files, oldest first (their names sort by date, then by the entry after them).
    func archives() -> [URL] {
        let names = (try? FileManager.default.contentsOfDirectory(atPath: paths.supportDir.path)) ?? []
        return names.filter { $0.hasPrefix("audit-") && $0.hasSuffix(".jsonl") }.sorted()
            .map { paths.supportDir.appendingPathComponent($0) }
    }

    func readHeadFile() -> AuditHead? {
        (try? String(contentsOf: paths.auditHeadFile, encoding: .utf8)).flatMap(AuditHead.init)
    }

    func readSealedHead() -> AuditHead? {
        anchor?.peek(.auditHead, "head").map { String(decoding: $0, as: UTF8.self) }.flatMap(AuditHead.init)
    }

    /// Where the next entry links on. The plain head file is ahead of the sealed copy only when
    /// sealing failed; when it is missing or behind, the sealed copy wins, so deleting the log
    /// and its head file does not restart the chain at 1.
    func readHead() -> AuditHead {
        let sealed = readSealedHead()
        if let head = readHeadFile(), head.seq >= (sealed?.seq ?? 0) { return head }
        if let sealed { return sealed }
        if let last = entries(limit: 1).last { return AuditHead(seq: last.seq, hash: last.hash) }
        return AuditHead(seq: 0, hash: Self.genesis)
    }

    func firstEntry() -> AuditEntry? {
        guard let handle = try? FileHandle(forReadingFrom: paths.auditFile) else { return nil }
        defer { try? handle.close() }
        var data = Data()
        while let chunk = try? handle.read(upToCount: 64 * 1024), !chunk.isEmpty {
            data.append(chunk)
            if let nl = data.firstIndex(of: UInt8(ascii: "\n")) { return try? ZSPJSON.decoder.decode(AuditEntry.self, from: data[..<nl]) }
        }
        return data.isEmpty ? nil : try? ZSPJSON.decoder.decode(AuditEntry.self, from: data)
    }

    /// The newest `limit` entries of the current log, oldest first. Only the end of the file is
    /// read when there is a limit: the app asks every few seconds.
    public func entries(limit: Int? = nil) -> [AuditEntry] {
        guard let data = limit.map({ tail(lines: $0) }) ?? (try? Data(contentsOf: paths.auditFile)) else { return [] }
        var lines = data.split(separator: UInt8(ascii: "\n"))
        if let limit, lines.count > limit { lines = Array(lines.suffix(limit)) }
        return lines.compactMap { try? ZSPJSON.decoder.decode(AuditEntry.self, from: Data($0)) }
    }

    /// At least the last `lines` whole lines of the log (more when a chunk ends mid-file).
    func tail(lines: Int) -> Data? {
        guard let handle = try? FileHandle(forReadingFrom: paths.auditFile) else { return nil }
        defer { try? handle.close() }
        guard let size = try? handle.seekToEnd() else { return nil }
        var offset = size
        var data = Data()
        let chunk: UInt64 = 256 * 1024
        while offset > 0 {
            let step = min(chunk, offset)
            offset -= step
            guard (try? handle.seek(toOffset: offset)) != nil, let part = try? handle.read(upToCount: Int(step)) else { return nil }
            data = part + data
            if data.reduce(0, { $0 + ($1 == UInt8(ascii: "\n") ? 1 : 0) }) > lines { break }
        }
        // A read that starts mid-line drops that partial line.
        if offset > 0, let nl = data.firstIndex(of: UInt8(ascii: "\n")) { data = data[data.index(after: nl)...] }
        return data
    }

    /// Checks the chain under the same lock appends take, so an entry half-written (line, then
    /// head, then anchor) is never mistaken for tampering.
    public func verify() -> AuditVerification {
        do {
            try paths.ensureSupportDir()
            return try withFileLock(paths.lock("audit")) { verifyUnlocked() }
        } catch {
            Log.warning("audit", "verifying without the audit lock: \(error.localizedDescription)")
            return verifyUnlocked()
        }
    }

    func verifyUnlocked() -> AuditVerification {
        func broken(_ count: Int, _ problem: String) -> AuditVerification {
            AuditVerification(entries: count, intact: false, anchored: nil, problem: problem)
        }
        let fileHead = readHeadFile()
        let sealed = readSealedHead()
        // The sealed copy is trusted over the plain head file, which anything running as you can
        // edit. A copy sealed before the base was recorded takes the base from the head file.
        var expected = sealed ?? fileHead
        if expected?.baseSeq == nil, let fileHead, fileHead.baseSeq != nil {
            expected?.baseSeq = fileHead.baseSeq
            expected?.basePrev = fileHead.basePrev
        }
        let data = (try? Data(contentsOf: paths.auditFile)) ?? Data()
        let raws = data.split(separator: UInt8(ascii: "\n"))
        if raws.isEmpty {
            if let expected, expected.seq > 0 {
                return broken(0, "the audit log is missing or empty, but aws-cli-zsp last wrote entry \(expected.seq)")
            }
            return AuditVerification(entries: 0, intact: true, anchored: nil, problem: nil)
        }
        var previous: AuditEntry?
        var count = 0
        for (n, raw) in raws.enumerated() {
            guard let e = try? ZSPJSON.decoder.decode(AuditEntry.self, from: Data(raw)) else {
                return broken(count, "line \(n + 1) is not an audit entry")
            }
            if Self.digest(e) != e.hash { return broken(count, "entry \(e.seq) was altered") }
            if let p = previous, e.prev != p.hash || e.seq != p.seq + 1 { return broken(count, "entries are missing before \(e.seq)") }
            if previous == nil {
                if let problem = checkStart(e, expected) { return broken(count, problem) }
            }
            previous = e
            count += 1
        }
        guard anchor != nil else { return AuditVerification(entries: count, intact: true, anchored: nil, problem: nil) }
        guard let sealed else {
            // There but not readable now (a locked Mac cannot use the enclave): only the chain
            // could be checked, which is not tampering.
            if (try? anchor?.accounts(.auditHead).contains("head")) == true {
                Log.warning("audit", "the sealed copy of the newest entry cannot be opened right now; checked the chain only")
                return AuditVerification(entries: count, intact: true, anchored: nil, problem: nil)
            }
            // No sealed copy at all, though entries were written with one: it was removed.
            return AuditVerification(entries: count, intact: false, anchored: nil,
                                     problem: "the sealed copy of the newest entry is missing from the vault")
        }
        let anchored = previous.map { "\($0.seq) \($0.hash)" } == sealed.tip
        return AuditVerification(entries: count, intact: anchored, anchored: anchored,
                                 problem: anchored ? nil : "the log does not end where zsp last wrote it (sealed head \(sealed.tip.prefix(20))…)")
    }

    /// The file's first entry must be where the current segment began. Before the base was
    /// recorded, a file not starting at 1 is only explained by a rotation into an archive.
    func checkStart(_ first: AuditEntry, _ expected: AuditHead?) -> String? {
        if let baseSeq = expected?.baseSeq, let basePrev = expected?.basePrev {
            guard first.seq == baseSeq, first.prev == basePrev else {
                return first.seq > baseSeq ? "entries \(baseSeq)–\(first.seq - 1) were cut from the start of the log"
                    : "the first entry is not where the log began"
            }
            return nil
        }
        if first.seq == 1 { return first.prev == Self.genesis ? nil : "the first entry does not start the chain" }
        return archives().isEmpty ? "entries before \(first.seq) are missing and no archive holds them" : nil
    }
}
