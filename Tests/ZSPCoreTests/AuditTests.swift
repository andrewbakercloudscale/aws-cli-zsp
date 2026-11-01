import CryptoKit
import Security
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

    func testDeletingTheLogOrItsFirstLinesIsCaught() throws {
        let s = Sandbox(); defer { s.cleanup() }
        let log = AuditLog(paths: s.paths, anchor: s.store)
        for i in 1...5 { try log.append("e\(i)") }
        let text = try String(contentsOf: s.paths.auditFile, encoding: .utf8)

        // The first two lines cut: what is left still links up on its own.
        try (text.split(separator: "\n").dropFirst(2).joined(separator: "\n") + "\n").write(to: s.paths.auditFile, atomically: true, encoding: .utf8)
        XCTAssertEqual(log.verify().problem, "entries 1–2 were cut from the start of the log")

        // The whole file deleted, and the next entry written as if nothing happened.
        try FileManager.default.removeItem(at: s.paths.auditFile)
        XCTAssertFalse(log.verify().intact)
        try log.append("e6")
        XCTAssertFalse(log.verify().intact, "a new file after a deletion is not a rotation")

        // Deleting the head file as well does not restart the chain at 1: the sealed copy says where it was.
        try FileManager.default.removeItem(at: s.paths.auditFile)
        try FileManager.default.removeItem(at: s.paths.auditHeadFile)
        XCTAssertEqual(try log.append("e7").seq, 7)
    }

    func testMissingAnchorIsNotIntact() throws {
        let s = Sandbox(); defer { s.cleanup() }
        let log = AuditLog(paths: s.paths, anchor: s.store)
        try log.append("a")
        try s.store.delete(.auditHead, "head")
        let v = log.verify()
        XCTAssertFalse(v.intact)
        XCTAssertNil(v.anchored)
    }

    func testRotationStartsANewSegmentAndKeepsTwentyArchives() throws {
        let s = Sandbox(); defer { s.cleanup() }
        let log = AuditLog(paths: s.paths, anchor: s.store)
        log.rotateBytes = 1
        try log.append("first")
        for n in 0..<22 {
            // Archive names carry the time to the second: give each its own.
            try "".write(to: s.paths.supportDir.appendingPathComponent("audit-2026010\(n / 10)T0000\(n % 10)0Z.jsonl"), atomically: true, encoding: .utf8)
        }
        try log.append("second")
        try log.append("third")
        let v = log.verify()
        XCTAssertTrue(v.intact, v.problem ?? "")
        XCTAssertEqual(v.entries, 1, "only the newest segment is in the current file")
        XCTAssertEqual(log.entries().first?.seq, 3)
        XCTAssertEqual(log.archives().count, AuditLog.keepArchives)
    }

    func testEntriesReadsOnlyTheTail() throws {
        let s = Sandbox(); defer { s.cleanup() }
        let log = AuditLog(paths: s.paths, anchor: s.store)
        for i in 1...40 { try log.append("e\(i)", detail: ["pad": String(repeating: "x", count: 20_000)]) }
        XCTAssertEqual(log.entries(limit: 3).map(\.seq), [38, 39, 40])
        XCTAssertEqual(log.entries().count, 40)
    }

    func testShortCommandForDialogs() {
        XCTAssertEqual(Requester.shortCommand(["/opt/homebrew/bin/aws", "sts", "get-caller-identity", "--profile", "default"]),
                       "aws sts get-caller-identity")
        XCTAssertEqual(Requester.shortCommand(["python3.13", "/opt/homebrew/bin/aws", "s3", "cp", "/tmp/a.zip", "s3://b/"]), "aws s3 cp")
        XCTAssertEqual(Requester.shortCommand([]), "an unknown program")
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

/// The real Secure Enclave. Only the no-prompt tier is read here: the guarded tier needs a finger.
final class EnclaveTests: XCTestCase {
    /// When-unlocked enclave keys cannot be created on a locked Mac.
    static var macIsUnlocked: Bool {
        guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage], nil) else { return false }
        return (try? SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)) != nil
    }

    func tempStore() -> (EnclaveStore, URL) {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("zsp-enclave-\(UUID().uuidString)")
        return (EnclaveStore(dir: dir), dir)
    }

    /// An item as the old version sealed it: to the when-unlocked key, as envelope v1.
    func sealLegacy(_ store: EnclaveStore, _ kind: SecretKind, _ account: String, _ data: Data) throws {
        let ephemeral = P256.KeyAgreement.PrivateKey()
        let epk = ephemeral.publicKey.x963Representation
        let shared = try ephemeral.sharedSecretFromKeyAgreement(with: try store.publicKey(.open))
        let box = try AES.GCM.seal(data, using: EnclaveStore.derive(shared, epk), authenticating: EnclaveStore.aad(kind, account))
        let url = store.itemURL(kind, account)
        try store.ensureDir(url.deletingLastPathComponent())
        try JSONEncoder().encode(EnclaveStore.Envelope(v: 1, epk: epk, box: box.combined!)).write(to: url)
    }

    func version(_ store: EnclaveStore, _ kind: SecretKind, _ account: String) throws -> Int {
        try JSONDecoder().decode(EnclaveStore.Envelope.self, from: Data(contentsOf: store.itemURL(kind, account))).v
    }

    func testNewItemsUseTheKeyThatOpensOnALockedMac() throws {
        try XCTSkipUnless(EnclaveStore.isAvailable)
        let (store, dir) = tempStore(); defer { try? FileManager.default.removeItem(at: dir) }
        try store.write(.remote, "p", Data("copy".utf8))
        XCTAssertEqual(try version(store, .remote, "p"), 2)
        XCTAssertEqual(try store.read(.remote, "p"), Data("copy".utf8))
        XCTAssertFalse(FileManager.default.fileExists(atPath: store.keyURL(.open).path))
    }

    func testOldItemsAreResealedAndTheSweepRunsOnce() throws {
        try XCTSkipUnless(EnclaveStore.isAvailable)
        try XCTSkipUnless(Self.macIsUnlocked, "the Mac is locked")
        let (store, dir) = tempStore(); defer { try? FileManager.default.removeItem(at: dir) }
        try sealLegacy(store, .remote, "p", Data("copy".utf8))
        try sealLegacy(store, .session, "p", Data("session".utf8))
        XCTAssertEqual(try version(store, .remote, "p"), 1)
        store.migrateUnattended()
        XCTAssertEqual(try version(store, .remote, "p"), 2)
        XCTAssertEqual(try version(store, .session, "p"), 2)
        XCTAssertEqual(try store.read(.remote, "p"), Data("copy".utf8))
        XCTAssertEqual(try store.read(.session, "p"), Data("session".utf8))
        XCTAssertTrue(FileManager.default.fileExists(atPath: store.migrationMarker.path))
    }

    func testAnOldItemStaysReadableIfTheSweepHasNotRun() throws {
        try XCTSkipUnless(EnclaveStore.isAvailable)
        try XCTSkipUnless(Self.macIsUnlocked, "the Mac is locked")
        let (store, dir) = tempStore(); defer { try? FileManager.default.removeItem(at: dir) }
        try sealLegacy(store, .remote, "p", Data("copy".utf8))
        XCTAssertEqual(try store.read(.remote, "p"), Data("copy".utf8))
        XCTAssertEqual(try version(store, .remote, "p"), 2, "reading it reseals it")
    }

    func testSealOpenAndBinding() throws {
        try XCTSkipUnless(EnclaveStore.isAvailable)
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("zsp-enclave-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = EnclaveStore(dir: dir)
        try store.write(.session, "a b/c", Data("hello".utf8))
        XCTAssertEqual(try store.read(.session, "a b/c"), Data("hello".utf8))
        XCTAssertEqual(store.peek(.session, "a b/c"), Data("hello".utf8))
        XCTAssertEqual(try store.accounts(.session), ["a b/c"])
        let raw = try String(contentsOf: store.itemURL(.session, "a b/c"), encoding: .utf8)
        XCTAssertFalse(raw.contains("hello"))

        // A sealed item moved under another name does not open.
        try FileManager.default.copyItem(at: store.itemURL(.session, "a b/c"), to: store.itemURL(.session, "other"))
        XCTAssertThrowsError(try store.read(.session, "other"))

        // Creating the guarded key needs an unlocked Mac; the rest of this test does not.
        try XCTSkipUnless(Self.macIsUnlocked, "the Mac is locked")
        // Writing a guarded item needs no Touch ID; peeking at one never prompts.
        try store.write(.master, "p", Data("secret".utf8))
        XCTAssertEqual(try store.accounts(.master), ["p"])
        XCTAssertNil(store.peek(.master, "p"))
        try store.delete(.master, "p")
        XCTAssertEqual(try store.accounts(.master), [])
    }
}
