import Foundation

/// Where everything lives. The AWS files honour the same environment variables the AWS CLI
/// does, so zsp always scrubs the files the CLI actually reads.
public struct Paths: Sendable, Equatable {
    public var credentialsFile: URL
    public var configFile: URL
    public var supportDir: URL

    public init(credentialsFile: URL, configFile: URL, supportDir: URL) {
        self.credentialsFile = credentialsFile
        self.configFile = configFile
        self.supportDir = supportDir
    }

    public static func standard(_ env: [String: String] = ProcessInfo.processInfo.environment) -> Paths {
        let home = FileManager.default.homeDirectoryForCurrentUser
        func expand(_ p: String) -> URL { URL(fileURLWithPath: (p as NSString).expandingTildeInPath) }
        return Paths(
            credentialsFile: env["AWS_SHARED_CREDENTIALS_FILE"].map(expand) ?? home.appendingPathComponent(".aws/credentials"),
            configFile: env["AWS_CONFIG_FILE"].map(expand) ?? home.appendingPathComponent(".aws/config"),
            supportDir: env["ZSP_HOME"].map(expand) ?? home.appendingPathComponent("Library/Application Support/aws-cli-zsp")
        )
    }

    public var auditFile: URL { supportDir.appendingPathComponent("audit.jsonl") }
    public var auditHeadFile: URL { supportDir.appendingPathComponent("audit.head") }
    public var metadataFile: URL { supportDir.appendingPathComponent("profiles.json") }
    public var settingsFile: URL { supportDir.appendingPathComponent("settings.json") }
    public var watchLog: URL { supportDir.appendingPathComponent("watch.log") }

    /// A lock file for `name`. Profile names can hold anything, so they are reduced to a safe
    /// stem plus a short hash that keeps two similar names apart.
    public func lock(_ name: String) -> URL {
        let stem = String(name.map { $0.isLetter || $0.isNumber || $0 == "-" ? $0 : "_" }.prefix(40))
        let tag = String(SigV4.sha256Hex(Data(name.utf8)).prefix(8))
        return supportDir.appendingPathComponent("locks/\(stem)-\(tag).lock")
    }

    public func ensureSupportDir() throws {
        let fm = FileManager.default
        try fm.createDirectory(at: supportDir.appendingPathComponent("locks"), withIntermediateDirectories: true,
                               attributes: [.posixPermissions: 0o700])
        try? fm.setAttributes([.posixPermissions: 0o700], ofItemAtPath: supportDir.path)
    }
}

/// An exclusive advisory lock held for the length of `body`. The AWS CLI runs
/// credential_process once per command, often several at a time.
public func withFileLock<T>(_ url: URL, _ body: () throws -> T) throws -> T {
    try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true,
                                            attributes: [.posixPermissions: 0o700])
    let fd = open(url.path, O_CREAT | O_RDWR, 0o600)
    guard fd >= 0 else { throw ZSPError.io("cannot open lock \(url.path): \(String(cString: strerror(errno)))") }
    defer { close(fd) }
    guard flock(fd, LOCK_EX) == 0 else { throw ZSPError.io("cannot lock \(url.path): \(String(cString: strerror(errno)))") }
    defer { flock(fd, LOCK_UN) }
    return try body()
}

/// Replaces `url` in one step, so a reader never sees half a file. A symlinked file is
/// written through the link rather than replacing the link.
public func writeAtomically(_ text: String, to url: URL, mode: Int = 0o600) throws {
    let target = url.resolvingSymlinksInPath()
    let dir = target.deletingLastPathComponent()
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    let tmp = dir.appendingPathComponent(".\(target.lastPathComponent).zsp-\(getpid())-\(UUID().uuidString.prefix(8))")
    guard FileManager.default.createFile(atPath: tmp.path, contents: Data(text.utf8), attributes: [.posixPermissions: mode]) else {
        throw ZSPError.io("cannot write \(tmp.path)")
    }
    guard rename(tmp.path, target.path) == 0 else {
        let reason = String(cString: strerror(errno))
        unlink(tmp.path)
        throw ZSPError.io("cannot replace \(target.path): \(reason)")
    }
}
