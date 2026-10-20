import XCTest
@testable import ZSPCore

/// The support log, the diagnostics report and the doctor: what support sees must never carry
/// a secret, and must be enough to tell what went wrong.
final class SupportTests: XCTestCase {
    let secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

    override func tearDown() {
        Log.configure(nil, process: "test")
    }

    func testRedactMasksKeysAndRemovesSecrets() {
        let text = Redact.scrub("""
            key AKIAIOSFODNN7EXAMPLE secret \(secret)
            aws_secret_access_key = \(secret)
            otpauth://totp/AWS:me?secret=JBSWY3DPEHPK3PXP&issuer=AWS
            "SessionToken": "abc"
            /Users/me/Library/Application Support/aws-cli-zsp/logs/aws-cli-zsp.log
            """)
        XCTAssertFalse(text.contains(secret), text)
        XCTAssertFalse(text.contains("AKIAIOSFODNN7EXAMPLE"), text)
        XCTAssertTrue(text.contains(maskKeyId("AKIAIOSFODNN7EXAMPLE")), text)
        XCTAssertFalse(text.contains("JBSWY3DPEHPK3PXP"), text)
        XCTAssertFalse(text.contains("abc\""), text)
        XCTAssertTrue(text.contains("Application Support/aws-cli-zsp/logs/aws-cli-zsp.log"), "a path is not a secret: \(text)")
    }

    func testAccountKeepsItsLastFourDigits() {
        XCTAssertEqual(Redact.account("123456789012"), "••••••••9012")
        XCTAssertEqual(SupportReport.clean("arn:aws:iam::123456789012:user/me"), "arn:aws:iam::••••••••9012:user/me")
    }

    func testLogLinesRoundTripAndAreRedacted() throws {
        let s = Sandbox(); defer { s.cleanup() }
        Log.configure(s.paths, process: "test")
        Log.warning("aws", "refused \(secret)")
        Log.error("vault", "broken")
        Log.debug("aws", "only with ZSP_DEBUG")
        let lines = Log.recent(s.paths)
        XCTAssertEqual(lines.map(\.message), ["refused [redacted]", "broken"])
        XCTAssertEqual(lines.first?.category, "aws")
        XCTAssertEqual(Log.recent(s.paths, atLeast: .error).map(\.category), ["vault"])
        XCTAssertEqual(LogLine(parsing: try XCTUnwrap(lines.last).text), lines.last)
    }

    func testEveryAuditEventHasATitle() {
        for e in AuditEvent.allCases { XCTAssertNotEqual(e.title, e.rawValue, "\(e) needs a title") }
        XCTAssertEqual(Set(AuditEvent.allCases.map(\.rawValue)).count, AuditEvent.allCases.count)
    }

    func testTheReportCarriesNoSecret() throws {
        let s = Sandbox(); defer { s.cleanup() }
        Log.configure(s.paths, process: "test")
        s.write(credentials: "[leaky]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = \(secret)\n")
        _ = try s.vault.importPlaintext(origin: "test")
        _ = try s.vault.credentials(for: "leaky", requester: "aws s3 ls")
        Log.error("test", "a careless line with \(secret) in it")
        try "watcher saw \(secret)\n".write(to: s.paths.watchLog, atomically: true, encoding: .utf8)
        let checks = [Check(name: "Example", ok: false, detail: "detail with \(secret)")]
        let text = SupportReport(version: "9.9", checks: checks, vault: s.vault).text()
        XCTAssertFalse(text.contains(secret), text)
        XCTAssertFalse(text.contains("AKIAIOSFODNN7EXAMPLE"), text)
        XCTAssertFalse(text.contains("123456789012"), "account ids are masked: \(text)")
        XCTAssertTrue(text.contains("leaky"), text)
        XCTAssertTrue(text.contains("== Audit trail"), text)
        XCTAssertTrue(text.contains("a careless line"), text)
    }

    func testADamagedProfilesFileIsSetAsideNotOverwritten() throws {
        let s = Sandbox(); defer { s.cleanup() }
        try s.paths.ensureSupportDir()
        try "{ not json".write(to: s.paths.metadataFile, atomically: true, encoding: .utf8)
        XCTAssertThrowsError(try s.vault.meta.load())
        try s.vault.meta.update("new") { $0 = ProfileMeta(profile: "new", accessKeyId: "AKIANEW0000000000001", importedAt: Date(), source: "test", temporary: false) }
        let aside = try FileManager.default.contentsOfDirectory(atPath: s.paths.supportDir.path).filter { $0.hasPrefix("profiles.json.damaged-") }
        XCTAssertEqual(aside.count, 1)
        XCTAssertEqual(try String(contentsOf: s.paths.supportDir.appendingPathComponent(aside[0]), encoding: .utf8), "{ not json")
        XCTAssertEqual(s.vault.meta.all().keys.sorted(), ["new"])
    }

    func testMFACountersNeverReuseAWindow() throws {
        let s = Sandbox(); defer { s.cleanup() }
        let counters = MFACounters(paths: s.paths)
        var now = Date(timeIntervalSince1970: 1_000_000)
        var waited: TimeInterval = 0
        let first = try counters.fresh("arn:mfa", now: { now }, pause: { waited += $0; now += $0 })
        let second = try counters.fresh("arn:mfa", now: { now }, pause: { waited += $0; now += $0 })
        XCTAssertGreaterThan(second, first)
        XCTAssertGreaterThan(waited, 0)
        XCTAssertEqual(counters.load()["arn:mfa"], second)
    }

    func doctor(_ s: Sandbox, home: URL? = nil, env: [String: String] = [:]) -> [Check] {
        var probes = DoctorProbes(binary: s.vault.commandPath, watcherLoaded: { true }, menuAtLogin: { true }, someoneAtMac: { true }, pins: nil)
        probes.network = false
        probes.environment = env
        probes.home = home ?? s.dir
        return Doctor(vault: s.vault, probes: probes).run()
    }

    func testDoctorOffersFixesForPlaintextAndWiring() throws {
        let s = Sandbox(); defer { s.cleanup() }
        s.write(credentials: screenshotCredentials)
        _ = try s.vault.importPlaintext(origin: "test")
        s.write(credentials: "[later]\naws_access_key_id = AKIALATER0000000001\naws_secret_access_key = \(secret)\n", config: "")
        let checks = Dictionary(uniqueKeysWithValues: doctor(s).map { ($0.name, $0) })
        XCTAssertEqual(checks["No plaintext keys"]?.fix, .moveKeys)
        XCTAssertEqual(checks["AWS CLI wired to the vault"]?.ok, false)
        XCTAssertEqual(checks["AWS CLI wired to the vault"]?.fix, .install)
    }

    func testDoctorFindsKeysExportedInShellFiles() throws {
        let s = Sandbox(); defer { s.cleanup() }
        try "export PATH=$PATH:~/bin\nexport AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n".write(to: s.dir.appendingPathComponent(".zshrc"), atomically: true, encoding: .utf8)
        let checks = doctor(s, env: ["AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE"])
        let shell = try XCTUnwrap(checks.first { $0.name == "No keys in shell files" })
        XCTAssertFalse(shell.ok)
        XCTAssertTrue(shell.detail.contains("~/.zshrc:2"), shell.detail)
        XCTAssertTrue(checks.contains { $0.name == "This shell" && $0.warn })
    }

    func testDoctorReportsRecentErrors() throws {
        let s = Sandbox(); defer { s.cleanup() }
        Log.configure(s.paths, process: "test")
        Log.error("aws", "ExpiredToken")
        let check = try XCTUnwrap(doctor(s).first { $0.name == "Errors in the last day" })
        XCTAssertTrue(check.warn)
        XCTAssertTrue(check.detail.contains("ExpiredToken"), check.detail)
    }

    func testClockSkewHeaderParses() {
        XCTAssertEqual(AWSProbe.httpDate("Tue, 20 Oct 2026 06:42:56 GMT")?.timeIntervalSince1970, 1_792_478_576)
    }
}
