import Foundation
import os

/// The support log: what aws-cli-zsp did, how long AWS took and why something failed, for
/// whoever helps you when it goes wrong. The audit trail records key use for you; this records
/// errors and timings. It never holds a secret: every line goes through `Redact.scrub`.
///
/// Lines go to <support dir>/logs/aws-cli-zsp.log (rotated at 1 MB, one older copy kept) and to
/// the unified log (Console.app, subsystem consulting.cloudscale.zsp). Debug lines go to the
/// file only with ZSP_DEBUG=1.
public enum Log {
    public enum Level: String, Codable, Comparable, Sendable {
        case debug, info, warning, error

        static let order: [Level] = [.debug, .info, .warning, .error]
        public static func < (a: Level, b: Level) -> Bool { order.firstIndex(of: a)! < order.firstIndex(of: b)! }
    }

    public static let subsystem = "consulting.cloudscale.zsp"
    static let maxBytes = 1_000_000

    final class Sink: @unchecked Sendable {
        let lock = NSLock()
        var file: URL?
        var process = "aws-cli-zsp"
        var debug = ProcessInfo.processInfo.environment["ZSP_DEBUG"] == "1"
        var said: Set<String> = []
    }

    static let sink = Sink()

    /// Where the file log goes, and the name each line carries ("cli", "watcher", "menu").
    /// Nil leaves only the unified log: tests use that.
    public static func configure(_ paths: Paths?, process: String) {
        sink.lock.withLock {
            sink.file = paths?.logFile
            sink.process = process
        }
    }

    public static func debug(_ category: String, _ message: @autoclosure () -> String) {
        guard sink.debug else { return }
        write(.debug, category, message())
    }

    public static func info(_ category: String, _ message: @autoclosure () -> String) { write(.info, category, message()) }
    public static func warning(_ category: String, _ message: @autoclosure () -> String) { write(.warning, category, message()) }
    public static func error(_ category: String, _ message: @autoclosure () -> String) { write(.error, category, message()) }

    /// An error worth one line per process, from code that runs every few seconds (the app's refresh).
    public static func errorOnce(_ category: String, _ message: @autoclosure () -> String) {
        let text = message()
        guard sink.lock.withLock({ sink.said.insert(text).inserted }) else { return }
        write(.error, category, text)
    }

    /// Runs `body`, logging how long it took, and its error if it threw.
    public static func timed<T>(_ category: String, _ what: String, _ body: () throws -> T) rethrows -> T {
        let start = Date()
        do {
            let value = try body()
            debug(category, "\(what) ok in \(milliseconds(since: start)) ms")
            return value
        } catch {
            warning(category, "\(what) failed in \(milliseconds(since: start)) ms: \(error.localizedDescription)")
            throw error
        }
    }

    static func milliseconds(since start: Date) -> Int { Int(Date().timeIntervalSince(start) * 1000) }

    static func write(_ level: Level, _ category: String, _ raw: String) {
        let message = Redact.scrub(raw)
        let logger = Logger(subsystem: subsystem, category: category)
        switch level {
        case .debug: logger.debug("\(message, privacy: .public)")
        case .info: logger.info("\(message, privacy: .public)")
        case .warning: logger.warning("\(message, privacy: .public)")
        case .error: logger.error("\(message, privacy: .public)")
        }
        sink.lock.withLock {
            guard let file = sink.file else { return }
            let line = LogLine(date: Date(), level: level, process: "\(sink.process)[\(getpid())]", category: category, message: message)
            append(line.text + "\n", to: file)
        }
    }

    /// Never throws: a log that cannot be written must not stop a command.
    static func append(_ text: String, to file: URL) {
        let fm = FileManager.default
        try? fm.createDirectory(at: file.deletingLastPathComponent(), withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        if let size = (try? fm.attributesOfItem(atPath: file.path))?[.size] as? Int, size > maxBytes {
            let old = file.deletingPathExtension().appendingPathExtension("1.log")
            try? fm.removeItem(at: old)
            try? fm.moveItem(at: file, to: old)
        }
        let fd = open(file.path, O_CREAT | O_WRONLY | O_APPEND, 0o600)
        guard fd >= 0 else { return }
        defer { close(fd) }
        let data = Data(text.utf8)
        _ = data.withUnsafeBytes { Darwin.write(fd, $0.baseAddress, $0.count) }
    }

    /// The newest `limit` lines at `level` or above, oldest first, from the current file and the
    /// rotated one before it.
    public static func recent(_ paths: Paths, limit: Int = 200, atLeast level: Level = .debug) -> [LogLine] {
        let files = [paths.logFile.deletingPathExtension().appendingPathExtension("1.log"), paths.logFile]
        let lines = files.flatMap { url -> [LogLine] in
            guard let text = try? String(contentsOf: url, encoding: .utf8) else { return [] }
            return text.split(separator: "\n").compactMap { LogLine(parsing: String($0)) }
        }
        return Array(lines.filter { $0.level >= level }.suffix(limit))
    }
}

/// One line of the support log: `2026-10-20T09:15:02.120Z ERROR cli[812] vault: message`.
public struct LogLine: Codable, Hashable, Sendable {
    public var date: Date
    public var level: Log.Level
    public var process: String
    public var category: String
    public var message: String

    static let formatter: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f
    }()

    public var text: String {
        "\(Self.formatter.string(from: date)) \(level.rawValue.uppercased()) \(process) \(category): \(message)"
    }

    init(date: Date, level: Log.Level, process: String, category: String, message: String) {
        self.date = date
        self.level = level
        self.process = process
        self.category = category
        self.message = message
    }

    init?(parsing line: String) {
        let parts = line.split(separator: " ", maxSplits: 4, omittingEmptySubsequences: false)
        guard parts.count == 5, let date = Self.formatter.date(from: String(parts[0])),
              let level = Log.Level(rawValue: parts[1].lowercased()), parts[3].hasSuffix(":") else { return nil }
        self.init(date: date, level: level, process: String(parts[2]), category: String(parts[3].dropLast()), message: String(parts[4]))
    }
}
