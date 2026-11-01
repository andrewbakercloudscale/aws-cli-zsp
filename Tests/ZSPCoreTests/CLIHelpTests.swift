import XCTest

/// Runs the real binary in a sandbox: `--help` never reaches the command it follows.
final class CLIHelpTests: XCTestCase {
    /// Leaves out install, uninstall, ui and selftest-watcher: they reach outside ZSP_HOME, so a
    /// regression here must not run them. The check is one line ahead of every command.
    static let commands = [
        "clear-sessions", "forget", "rotate", "revoke-sessions", "revoke", "disable-key", "delete-key",
        "import", "add", "duration", "migrate", "setup", "pin", "access", "approve", "mfa", "remote",
    ]

    func run(_ args: [String], home: URL) throws -> (output: String, status: Int32) {
        // The test bundle sits beside the binaries in .build/debug.
        let binary = Bundle(for: Self.self).bundleURL.deletingLastPathComponent().appendingPathComponent("zsp")
        let p = Process()
        p.executableURL = binary
        p.arguments = args
        p.environment = [
            "ZSP_HOME": home.path,
            "AWS_SHARED_CREDENTIALS_FILE": home.appendingPathComponent("credentials").path,
            "AWS_CONFIG_FILE": home.appendingPathComponent("config").path,
        ]
        let out = Pipe()
        p.standardOutput = out
        p.standardError = out
        try p.run()
        let data = out.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return (String(decoding: data, as: UTF8.self), p.terminationStatus)
    }

    func testHelpFlagPrintsHelpAndDoesNothingElse() throws {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: home) }
        for command in Self.commands {
            for flag in ["--help", "-h"] {
                let r = try run([command, flag, "--yes"], home: home)
                XCTAssertEqual(r.status, 0, "\(command) \(flag)")
                XCTAssertTrue(r.output.hasPrefix("aws-cli-zsp "), "\(command) \(flag) printed: \(r.output)")
                XCTAssertTrue(r.output.contains("Rotate and revoke"), "\(command) \(flag) printed: \(r.output)")
            }
        }
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: home.path), [], "--help wrote to the sandbox")
    }

    func testVersionFlagPrintsVersionOnly() throws {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: home) }
        let r = try run(["clear-sessions", "--version"], home: home)
        XCTAssertEqual(r.status, 0)
        XCTAssertFalse(r.output.contains("cached sessions"), r.output)
        XCTAssertEqual(r.output.split(separator: "\n").count, 1, r.output)
    }
}
