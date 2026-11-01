import XCTest

/// Runs the real binary in a sandbox: what a command cannot read stops it before it runs.
final class CLIArgumentTests: XCTestCase {
    var home: URL!

    override func setUpWithError() throws {
        home = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws { try FileManager.default.removeItem(at: home) }

    func run(_ args: [String]) throws -> (output: String, status: Int32) {
        let p = Process()
        p.executableURL = Bundle(for: Self.self).bundleURL.deletingLastPathComponent().appendingPathComponent("zsp")
        p.arguments = args
        p.environment = [
            "ZSP_HOME": home.path,
            "AWS_SHARED_CREDENTIALS_FILE": home.appendingPathComponent("credentials").path,
            "AWS_CONFIG_FILE": home.appendingPathComponent("config").path,
        ]
        let out = Pipe()
        p.standardOutput = out
        p.standardError = out
        p.standardInput = FileHandle.nullDevice
        try p.run()
        let data = out.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return (String(decoding: data, as: UTF8.self), p.terminationStatus)
    }

    func testWhatACommandCannotReadStopsIt() throws {
        for args in [
            ["clear-sessions", "--profil", "personal"],
            ["clear-sessions", "--profil=personal"],
            ["clear-sessions", "personal"],
            ["clear-sessions", "--profile"],
            ["clear-sessions", "--profile", "--yes"],
            ["clear-sessions", "--keep-old"],
            ["forget", "--profile", "x", "--yes", "extra"],
            ["rotate", "--profile", "x", "--keepold"],
            ["exec", "--profile", "x", "aws", "s3", "ls", "--recursive"],
            ["approve", "--profile", "x", "123456", "654321"],
            ["doctor", "--profile", "x"],
            ["import", "--auto", "x"],
        ] {
            let r = try run(args)
            XCTAssertEqual(r.status, 2, "\(args): \(r.output)")
            XCTAssertTrue(r.output.contains("Nothing was changed"), "\(args): \(r.output)")
        }
    }

    func testTheProblemNeverRepeatsAValue() throws {
        for (args, value) in [(["clear-sessions", "--secret=hunter2"], "hunter2"), (["approve", "--profile", "x", "123456", "654321"], "654321")] {
            XCTAssertFalse(try run(args).output.contains(value), "\(args)")
        }
    }

    func testWhatCommandsTakeStillRuns() throws {
        for args in [
            ["clear-sessions"], ["clear-sessions", "--json"], ["clear-sessions", "--profile", "x"],
            ["clear-sessions", "--profile=x", "--yes"], ["scan", "-y"], ["list", "--json"],
            ["import", "--auto"], ["import", "--auto", "--json"], ["import", "--all"],
            ["import", "--profiles", "a,b"], ["audit", "--limit", "5"], ["audit", "--verify"],
            ["duration", "--profile", "x", "8h"], ["doctor", "--offline", "--json"],
        ] {
            let r = try run(args)
            XCTAssertNotEqual(r.status, 2, "\(args): \(r.output)")
            XCTAssertFalse(r.output.contains("Nothing was changed"), "\(args): \(r.output)")
        }
    }

    /// `--` ends the checking: what follows belongs to the command exec runs.
    func testExecLeavesTheCommandsOwnOptionsAlone() throws {
        let r = try run(["exec", "--profile", "x", "--", "aws", "s3", "ls", "--recursive"])
        XCTAssertFalse(r.output.contains("Nothing was changed"), r.output)
    }
}
