import CryptoKit
import XCTest
@testable import ZSPCore

/// Failure paths found in review: each one used to lose a key, a file or the truth.
final class HardeningTests: XCTestCase {
    func testAnUnreadableConfigIsNeverWrittenBackAsEmpty() throws {
        let s = Sandbox(); defer { s.cleanup() }
        s.write(credentials: screenshotCredentials)
        // One Latin-1 byte: not UTF-8.
        let config = Data("[profile sso]\nsso_start_url = https://example.awsapps.com/start\n# caf\u{e9}\n".utf8) + Data([0xE9, 0x0A])
        try config.write(to: s.paths.configFile)
        XCTAssertThrowsError(try s.vault.importPlaintext(origin: "test"))
        XCTAssertEqual(try Data(contentsOf: s.paths.configFile), config, "left exactly as it was")
        XCTAssertEqual(Scanner.scan(s.paths).count, 3, "and the keys stay in the credentials file")
        XCTAssertEqual(Scanner.unreadable(s.paths), [s.paths.configFile.path])
    }

    func testImportKeepsAChangeMadeWhileSealing() throws {
        let s = Sandbox(); defer { s.cleanup() }
        s.write(credentials: screenshotCredentials)
        let original = s.credentials
        let store = s.store
        // `aws configure set region …` lands while the first key is being sealed.
        var once = true
        let racing = HookStore(store) { kind in
            guard once, kind == .master else { return }
            once = false
            try! (original + "\n[later]\nregion = eu-west-1\n").write(to: s.paths.credentialsFile, atomically: true, encoding: .utf8)
        }
        let vault = Vault(paths: s.paths, store: racing, auth: s.auth, aws: s.aws, commandPath: "/bin/zsp")
        _ = try vault.importPlaintext(origin: "test")
        XCTAssertTrue(s.credentials.contains("[later]\nregion = eu-west-1"), s.credentials)
        XCTAssertEqual(Scanner.scan(s.paths), [])
    }

    func testRestoreAndForgetRefuseAnEnforcedKey() throws {
        let s = try MFAUndoTests().enforced(); defer { s.cleanup() }
        XCTAssertThrowsError(try s.vault.forget("bedrock")) { XCTAssertTrue("\($0)".contains("mfa remove"), "\($0)") }
        XCTAssertThrowsError(try s.vault.restorePlaintext())
        XCTAssertNotNil(s.master("bedrock")?.mfaSeed, "this Mac's MFA is still there")
        XCTAssertFalse(s.credentials.contains("bedrocksecret"))
    }

    func testRestoreStopsWhenAKeyCannotBeRead() throws {
        let s = Sandbox(); defer { s.cleanup() }
        s.write(credentials: screenshotCredentials)
        _ = try s.vault.importPlaintext(origin: "test")
        let holed = HookStore(s.store, missing: ["personal"])
        let vault = Vault(paths: s.paths, store: holed, auth: s.auth, aws: s.aws, commandPath: "/bin/zsp")
        XCTAssertThrowsError(try vault.restorePlaintext())
        XCTAssertNotNil(s.master("personal"), "never deleted without being written back")
        XCTAssertNotNil(s.master("default"))
        XCTAssertFalse(s.credentials.contains("secret"))
    }

    func testTheSameKeyAfterProfilesJsonWasLostKeepsItsMFA() throws {
        let s = try MFAUndoTests().enforced(); defer { s.cleanup() }
        try FileManager.default.removeItem(at: s.paths.metadataFile)
        try s.vault.add(profile: "bedrock", accessKeyId: "AKIABEDROCK00000001", secretAccessKey: "bedrocksecretbedrocksecretbedrocksecret1")
        XCTAssertEqual(s.master("bedrock")?.mfaSeed, s.aws.mfaSeed, "the sealed key was opened, found the same, and kept")
        XCTAssertNotNil(s.vault.meta.all()["bedrock"]?.mfaSerial)
    }

    func testRotateDeletesANewKeyItCouldNotStore() throws {
        let s = Sandbox(); defer { s.cleanup() }
        s.write(credentials: screenshotCredentials)
        _ = try s.vault.importPlaintext(origin: "test")
        s.aws.keys = [AccessKeyInfo(accessKeyId: "AKIABEDROCK00000001", status: "Active", createDate: nil)]
        let full = HookStore(s.store) { kind in if kind == .master { throw ZSPError.io("disk full") } }
        let vault = Vault(paths: s.paths, store: full, auth: s.auth, aws: s.aws, commandPath: "/bin/zsp")
        XCTAssertThrowsError(try vault.rotate("bedrock"))
        XCTAssertTrue(s.aws.calls.contains { $0.hasPrefix("DeleteAccessKey") && $0.hasSuffix("AKIANEWKEY000000001") }, "\(s.aws.calls)")
        XCTAssertEqual(s.aws.keys.map(\.accessKeyId), ["AKIABEDROCK00000001"], "no orphan key in AWS")
        XCTAssertEqual(s.master("bedrock")?.accessKeyId, "AKIABEDROCK00000001")
    }

    func testAnUnreadableSessionIsReplacedNotFatal() throws {
        let s = Sandbox(); defer { s.cleanup() }
        s.write(credentials: screenshotCredentials)
        _ = try s.vault.importPlaintext(origin: "test")
        let broken = HookStore(s.store, unreadable: [.session])
        try s.store.write(.session, "bedrock", Data("x".utf8))
        let vault = Vault(paths: s.paths, store: broken, auth: s.auth, aws: s.aws, commandPath: "/bin/zsp")
        XCTAssertNoThrow(try vault.credentials(for: "bedrock", requester: "aws s3 ls"))
    }

    func testRemoteApprovalNeedsThePolicyStillInAWS() throws {
        let s = try MFAUndoTests().enforced(); defer { s.cleanup() }
        s.aws.mfaDevices.append("arn:aws:iam::123456789012:mfa/phone")
        // Deleted in the IAM console: profiles.json still says enforced.
        s.aws.policies.removeAll()
        XCTAssertThrowsError(try s.vault.enableRemote("bedrock", serial: nil)) { XCTAssertTrue("\($0)".contains("mfa enforce"), "\($0)") }
        XCTAssertNil(try s.store.read(.remote, "bedrock"))

        try s.vault.enforceMFA("bedrock")
        _ = try s.vault.enableRemote("bedrock", serial: nil)
        s.aws.policies.removeAll()
        XCTAssertThrowsError(try s.vault.approve("bedrock", code: "123456", requester: "claude"))
        XCTAssertNil(try s.store.read(.remote, "bedrock"), "a copy that opens without Touch ID is gone once AWS stops demanding a code")
        XCTAssertNil(try s.store.read(.session, "bedrock"))
    }

    func testAWrongPhoneCodeIsAuditedOnce() throws {
        let s = try MFAUndoTests().enforced(); defer { s.cleanup() }
        s.aws.mfaDevices.append("arn:aws:iam::123456789012:mfa/phone")
        _ = try s.vault.enableRemote("bedrock", serial: nil)
        s.aws.failSession = .aws(code: "AccessDenied", message: "MultiFactorAuthentication failed")
        XCTAssertThrowsError(try s.vault.approve("bedrock", code: "123456", requester: "claude"))
        let failures = s.vault.audit.entries().filter { !$0.ok }
        XCTAssertEqual(failures.map(\.event), ["auth.denied"])
    }

    func testPolicyCheckMatchesWhatEnforceWrites() {
        XCTAssertTrue(Vault.demandsMFA(Vault.requireMFAPolicy))
        XCTAssertFalse(Vault.demandsMFA(Vault.revokePolicy(before: Date())))
        XCTAssertFalse(Vault.demandsMFA("not json"))
    }

    func testShellWordsReadsCredentialProcessLines() {
        let vault = Sandbox().vault
        XCTAssertEqual(shellWords(vault.credentialProcess(for: "it's prod")),
                       [vault.commandPath, "credential-process", "--profile", "it's prod"])
        XCTAssertEqual(shellWords(#"/tmp/evil "/a b/zsp" credential-process"#), ["/tmp/evil", "/a b/zsp", "credential-process"])
        XCTAssertNil(shellWords("'open"))
    }

    func testRequesterRedactsSecretsInsideArguments() {
        let out = Requester.redact(["aws", "sts", "--cli-input-json", #"{"SecretAccessKey":"abc"}"#, "--access-key", "AKIAABCDEFGHIJKLMNOP",
                                    "configure", "set", "aws_secret_access_key", "s3cr3t", "--token=xyz"])
        XCTAssertFalse(out.joined(separator: " ").contains("abc"), "\(out)")
        XCTAssertFalse(out.joined(separator: " ").contains("s3cr3t"), "\(out)")
        XCTAssertFalse(out.contains("AKIAABCDEFGHIJKLMNOP"), "\(out)")
        XCTAssertTrue(out.contains("aws_secret_access_key"))
        XCTAssertTrue(out.contains("--token=[redacted]"), "\(out)")
    }

    func testAtomicWriteCreatesTheFileWithItsModeFromTheStart() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("zsp-write-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appendingPathComponent("f")
        try writeAtomically("one", to: url)
        try writeAtomically("two", to: url)
        XCTAssertEqual(try String(contentsOf: url, encoding: .utf8), "two")
        XCTAssertEqual(try FileManager.default.attributesOfItem(atPath: url.path)[.posixPermissions] as? Int, 0o600)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: dir.path), ["f"], "no temporary file left")
    }
}

final class SealingKeyTests: XCTestCase {
    func testASwappedSealingKeyIsRefused() throws {
        try XCTSkipUnless(EnclaveStore.isAvailable)
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("zsp-seal-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }
        let pins = MemoryStore()
        let store = EnclaveStore(dir: dir)
        store.keyPins = pins
        try store.write(.master, "p", Data("secret".utf8))
        XCTAssertNotNil(try pins.read(.sealingKey, "guarded"), "pinned the first time it is used")

        // Something running as you writes its own public key.
        let original = try Data(contentsOf: store.publicKeyURL(.guarded))
        try P256.KeyAgreement.PrivateKey().publicKey.x963Representation.write(to: store.publicKeyURL(.guarded))
        XCTAssertThrowsError(try store.write(.master, "q", Data("secret".utf8)))
        XCTAssertEqual(try store.accounts(.master), ["p"])

        // Its own enclave key too: the pin still refuses it.
        try original.write(to: store.publicKeyURL(.guarded))
        try FileManager.default.removeItem(at: store.keyURL(.guarded))
        try FileManager.default.removeItem(at: store.publicKeyURL(.guarded))
        XCTAssertThrowsError(try store.write(.master, "q", Data("secret".utf8)))
    }
}

/// A store that can fail, hide items, or run something just before a write.
final class HookStore: SecretStore {
    let inner: SecretStore
    let beforeWrite: (SecretKind) throws -> Void
    let missing: Set<String>
    let unreadable: Set<SecretKind>

    init(_ inner: SecretStore, missing: Set<String> = [], unreadable: Set<SecretKind> = [],
         beforeWrite: @escaping (SecretKind) throws -> Void = { _ in }) {
        self.inner = inner
        self.missing = missing
        self.unreadable = unreadable
        self.beforeWrite = beforeWrite
    }

    func read(_ kind: SecretKind, _ account: String) throws -> Data? {
        if unreadable.contains(kind) { throw ZSPError.invalid("damaged") }
        return missing.contains(account) ? nil : try inner.read(kind, account)
    }
    func peek(_ kind: SecretKind, _ account: String) -> Data? { try? read(kind, account) }
    func write(_ kind: SecretKind, _ account: String, _ data: Data) throws {
        try beforeWrite(kind)
        try inner.write(kind, account, data)
    }
    func delete(_ kind: SecretKind, _ account: String) throws { try inner.delete(kind, account) }
    func accounts(_ kind: SecretKind) throws -> [String] { try inner.accounts(kind) }
}
