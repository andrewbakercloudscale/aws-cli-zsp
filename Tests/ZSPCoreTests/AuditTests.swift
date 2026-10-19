import XCTest
@testable import ZSPCore

final class AuditTests: XCTestCase {
    func testChainVerifiesAndCatchesTampering() throws {
        let s = Sandbox(); defer { s.cleanup() }
        let log = AuditLog(paths: s.paths, anchor: s.store)
        for i in 1...5 { try log.append("e\(i)", profile: "p", detail: ["i": String(i)]) }
        XCTAssertEqual(log.verify(), AuditVerification(entries: 5, intact: true, anchored: true, problem: nil))
        XCTAssertEqual(log.entries(limit: 2).map(\.seq), [4, 5])
        XCTAssertEqual(log.entries().first?.prev, AuditLog.genesis)

        let text = try String(contentsOf: s.paths.auditFile, encoding: .utf8)
        try text.replacingOccurrences(of: "\"e3\"", with: "\"eX\"").write(to: s.paths.auditFile, atomically: true, encoding: .utf8)
        XCTAssertFalse(log.verify().intact)
        XCTAssertEqual(log.verify().problem, "entry 3 was altered")

        var lines = text.split(separator: "\n")
        lines.remove(at: 2)
        try (lines.joined(separator: "\n") + "\n").write(to: s.paths.auditFile, atomically: true, encoding: .utf8)
        XCTAssertEqual(log.verify().problem, "entries are missing before 4")

        // Dropping the newest entries keeps the chain consistent, but not with the Keychain.
        try (text.split(separator: "\n").prefix(4).joined(separator: "\n") + "\n").write(to: s.paths.auditFile, atomically: true, encoding: .utf8)
        let v = log.verify()
        XCTAssertEqual(v.anchored, false)
        XCTAssertFalse(v.intact)
    }

    func testChainContinuesAfterRestart() throws {
        let s = Sandbox(); defer { s.cleanup() }
        try AuditLog(paths: s.paths, anchor: s.store).append("a")
        try FileManager.default.removeItem(at: s.paths.auditHeadFile)
        try AuditLog(paths: s.paths, anchor: s.store).append("b")
        XCTAssertTrue(AuditLog(paths: s.paths, anchor: s.store).verify().intact)
        XCTAssertNil(AuditLog(paths: s.paths, anchor: nil).verify().anchored, "a reader without the Keychain cannot check the anchor")
    }

    func testRequesterRedactsSecrets() {
        XCTAssertEqual(Requester.redact(["aws", "configure", "set", "aws_secret_access_key", "abc"]),
                       ["aws", "configure", "set", "aws_secret_access_key", "[redacted]"])
        XCTAssertEqual(Requester.redact(["--token=xyz", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "s3"]),
                       ["--token=[redacted]", "[redacted]", "s3"])
        XCTAssertTrue(Requester.describe(pid: getpid()).contains("[\(getpid())]"))
    }

    func testDurations() {
        XCTAssertEqual(parseDuration("1h"), 3600)
        XCTAssertEqual(parseDuration("90m"), 5400)
        XCTAssertEqual(parseDuration("900"), 900)
        XCTAssertNil(parseDuration("soon"))
        var s = Settings()
        s.sessionSeconds = 10
        XCTAssertEqual(s.duration(for: "x"), Settings.minSeconds)
        s.profileSessionSeconds["y"] = 999_999
        XCTAssertEqual(s.duration(for: "y"), Settings.maxSeconds)
    }
}

/// The real login keychain, under a test-only service name.
final class KeychainTests: XCTestCase {
    func testRoundTrip() throws {
        let store = KeychainStore(prefix: "consulting.cloudscale.zsp.test-\(UUID().uuidString.prefix(8))")
        defer { try? store.delete(.master, "p1"); try? store.delete(.master, "p2") }
        XCTAssertNil(try store.read(.master, "p1"))
        try store.write(.master, "p1", Data("one".utf8))
        try store.write(.master, "p1", Data("two".utf8))
        try store.write(.master, "p2", Data("x".utf8))
        XCTAssertEqual(try store.read(.master, "p1"), Data("two".utf8))
        XCTAssertEqual(try store.accounts(.master), ["p1", "p2"])
        XCTAssertEqual(try store.accounts(.session), [])
        try store.delete(.master, "p1")
        XCTAssertNil(try store.read(.master, "p1"))
    }
}
