import XCTest
@testable import ZSPCore

final class VaultTests: XCTestCase {
    func testImportMovesEveryKeyAndWiresConfig() throws {
        let s = Sandbox(); defer { s.cleanup() }
        s.write(credentials: screenshotCredentials, config: "[default]\nregion = af-south-1\n")
        XCTAssertEqual(Scanner.scan(s.paths).count, 3)

        let report = try s.vault.importPlaintext(origin: "test")
        XCTAssertEqual(report.imported.sorted(), ["bedrock", "default", "personal"])
        XCTAssertFalse(s.credentials.contains("secret"), s.credentials)
        XCTAssertFalse(s.credentials.contains("AKIA"), s.credentials)
        XCTAssertTrue(s.credentials.contains("region = us-east-1"), "non-secret settings stay: \(s.credentials)")
        XCTAssertTrue(s.credentials.hasPrefix(AWSFiles.managedMarker))
        XCTAssertEqual(Scanner.scan(s.paths), [])

        let cfg = INIDocument(s.config)
        XCTAssertEqual(cfg.value("region", in: "default"), "af-south-1")
        XCTAssertEqual(cfg.value("credential_process", in: "default"),
                       "/Users/me/Applications/aws-cli-zsp.app/Contents/MacOS/zsp credential-process --profile default")
        XCTAssertNotNil(cfg.value("credential_process", in: "profile bedrock"))
        XCTAssertEqual(s.master("bedrock")?.secretAccessKey, "bedrocksecretbedrocksecretbedrocksecret1")
        XCTAssertEqual(s.auth.reasons, [], "moving keys in needs no Touch ID")

        let perms = try FileManager.default.attributesOfItem(atPath: s.paths.credentialsFile.path)[.posixPermissions] as? Int
        XCTAssertEqual(perms, 0o600)
        XCTAssertEqual(s.vault.audit.entries().filter { $0.event == "key.imported" }.count, 3)
    }

    func testImportIsIdempotentAndReplacesNewKeys() throws {
        let s = Sandbox(); defer { s.cleanup() }
        s.write(credentials: screenshotCredentials)
        _ = try s.vault.importPlaintext(origin: "test")
        let config = s.config, creds = s.credentials
        XCTAssertEqual(try s.vault.importPlaintext(origin: "test"), ImportReport())
        XCTAssertEqual(s.config, config, "a second pass writes nothing")
        XCTAssertEqual(s.credentials, creds)

        // `aws configure` writes a new key for an existing profile.
        try s.store.write(.session, "bedrock", Data("old session".utf8))
        s.write(credentials: s.credentials + "\n[bedrock]\naws_access_key_id = AKIABEDROCK00000002\naws_secret_access_key = new2new2new2new2new2new2new2new2new2new2\n")
        let r = try s.vault.importPlaintext(origin: "test")
        XCTAssertEqual(r.replaced, ["bedrock"])
        XCTAssertEqual(s.master("bedrock")?.accessKeyId, "AKIABEDROCK00000002")
        XCTAssertNil(try s.store.read(.session, "bedrock"), "a session from the old key is dropped")
        XCTAssertEqual(s.vault.meta.all()["bedrock"]?.previousKeyId, "AKIABEDROCK00000001")
    }

    func testHalfWrittenPairWaitsAndConfigFileKeysMove() throws {
        let s = Sandbox(); defer { s.cleanup() }
        s.write(credentials: "[a]\naws_access_key_id = AKIAHALF00000000001\n",
                config: "[profile b]\nregion = eu-west-1\naws_access_key_id = AKIACONFIG000000001\naws_secret_access_key = cfgsecretcfgsecretcfgsecretcfgsecret1234\n")
        let r = try s.vault.importPlaintext(origin: "test")
        XCTAssertEqual(r.imported, ["b"])
        XCTAssertEqual(r.incomplete.map(\.profile), ["a"])
        XCTAssertTrue(s.credentials.contains("AKIAHALF"), "a half-written pair is left for the next pass")
        XCTAssertEqual(s.config, "[profile b]\nregion = eu-west-1\ncredential_process = /Users/me/Applications/aws-cli-zsp.app/Contents/MacOS/zsp credential-process --profile b\n")
    }

    func testKeychainFailureLeavesTheFileAlone() throws {
        final class Broken: SecretStore {
            func read(_ kind: SecretKind, _ account: String) throws -> Data? { nil }
            func peek(_ kind: SecretKind, _ account: String) -> Data? { nil }
            func write(_ kind: SecretKind, _ account: String, _ data: Data) throws { throw ZSPError.keychain(-25308, "locked") }
            func delete(_ kind: SecretKind, _ account: String) throws {}
            func accounts(_ kind: SecretKind) throws -> [String] { [] }
        }
        let s = Sandbox(); defer { s.cleanup() }
        s.write(credentials: screenshotCredentials)
        let vault = Vault(paths: s.paths, store: Broken(), auth: s.auth, aws: s.aws, commandPath: "/zsp")
        XCTAssertThrowsError(try vault.importPlaintext(origin: "test"))
        XCTAssertEqual(s.credentials, screenshotCredentials)
    }

    func testSessionsAreCachedAndTouchIDGuardsTheKey() throws {
        let s = Sandbox(); defer { s.cleanup() }
        s.write(credentials: screenshotCredentials)
        _ = try s.vault.importPlaintext(origin: "test")
        var settings = Settings()
        settings.profileSessionSeconds["bedrock"] = 7200
        try settings.save(s.paths)

        let first = try s.vault.credentials(for: "bedrock", requester: "aws s3 ls")
        let second = try s.vault.credentials(for: "bedrock", requester: "aws s3 ls")
        XCTAssertEqual(first.accessKeyId, second.accessKeyId)
        XCTAssertEqual(first.sessionToken, second.sessionToken)
        XCTAssertEqual(first.sessionToken, "token1")
        XCTAssertEqual(s.auth.reasons.count, 1, "the cached session needs no second Touch ID")
        XCTAssertEqual(s.aws.calls, ["GetSessionToken AKIABEDROCK00000001 7200"])
        let meta = s.vault.meta.all()["bedrock"]!
        XCTAssertEqual(meta.lastRequester, "aws s3 ls")
        XCTAssertTrue(meta.sessionActive())
        XCTAssertEqual(s.vault.audit.entries().suffix(2).map(\.event), ["session.issued", "session.served"])

        s.auth.deny = true
        XCTAssertThrowsError(try s.vault.credentials(for: "personal", requester: "x"))
        XCTAssertEqual(s.vault.audit.entries().last?.event, "auth.denied")
        XCTAssertThrowsError(try s.vault.credentials(for: "nope", requester: "x")) {
            XCTAssertTrue("\($0)".contains("zsp add"))
        }
    }

    func testTemporaryCredentialsArePassedThrough() throws {
        let s = Sandbox(); defer { s.cleanup() }
        s.write(credentials: "[tmp]\naws_access_key_id = ASIATEMP00000000001\naws_secret_access_key = tmpsecret\naws_session_token = tok\n")
        _ = try s.vault.importPlaintext(origin: "test")
        let c = try s.vault.credentials(for: "tmp", requester: "x")
        XCTAssertEqual(c.sessionToken, "tok")
        XCTAssertEqual(s.aws.calls, [])
        XCTAssertThrowsError(try s.vault.rotate("tmp"))
    }

    func testRotateCreatesVerifiesThenDeletesTheOldKey() throws {
        let s = Sandbox(); defer { s.cleanup() }
        s.write(credentials: screenshotCredentials)
        _ = try s.vault.importPlaintext(origin: "test")
        _ = try s.vault.credentials(for: "default", requester: "x")
        s.aws.keys = [AccessKeyInfo(accessKeyId: "AKIADEFAULT00000001", status: "Active", createDate: nil)]
        s.aws.rejectNewKeyTimes = 2
        s.aws.calls = []

        let r = try s.vault.rotate("default")
        XCTAssertEqual(r.newKeyId, "AKIANEWKEY000000001")
        XCTAssertEqual(r.oldKey, "deleted")
        XCTAssertEqual(s.master("default")?.accessKeyId, "AKIANEWKEY000000001")
        XCTAssertEqual(s.aws.calls, [
            "ListAccessKeys AKIADEFAULT00000001", "CreateAccessKey AKIADEFAULT00000001",
            "GetCallerIdentity AKIANEWKEY000000001", "GetCallerIdentity AKIANEWKEY000000001", "GetCallerIdentity AKIANEWKEY000000001",
            "DeleteAccessKey AKIANEWKEY000000001 AKIADEFAULT00000001",
        ])
        XCTAssertNil(try s.store.read(.session, "default"), "sessions from the old key are dropped")
        let meta = s.vault.meta.all()["default"]!
        XCTAssertEqual(meta.accessKeyId, "AKIANEWKEY000000001")
        XCTAssertEqual(meta.previousKeyId, "AKIADEFAULT00000001")
        XCTAssertNotNil(meta.rotatedAt)
    }

    func testRotateRefusesAThirdKeyAndKeepOldDeactivates() throws {
        let s = Sandbox(); defer { s.cleanup() }
        s.write(credentials: screenshotCredentials)
        _ = try s.vault.importPlaintext(origin: "test")
        s.aws.keys = [AccessKeyInfo(accessKeyId: "AKIADEFAULT00000001", status: "Active", createDate: nil),
                      AccessKeyInfo(accessKeyId: "AKIAOTHER0000000001", status: "Active", createDate: nil)]
        XCTAssertThrowsError(try s.vault.rotate("default")) { XCTAssertTrue("\($0)".contains("AKIA…0001")) }
        XCTAssertEqual(s.master("default")?.accessKeyId, "AKIADEFAULT00000001")

        s.aws.keys.removeLast()
        let r = try s.vault.rotate("default", keepOld: true)
        XCTAssertEqual(r.oldKey, "deactivated")
        XCTAssertTrue(s.aws.calls.contains("UpdateAccessKey AKIANEWKEY000000001 AKIADEFAULT00000001 Inactive"))
    }

    func testRevokeSessionsAttachesATokenIssueTimePolicy() throws {
        let s = Sandbox(); defer { s.cleanup() }
        s.write(credentials: screenshotCredentials)
        _ = try s.vault.importPlaintext(origin: "test")
        _ = try s.vault.credentials(for: "personal", requester: "x")
        let cutoff = try s.vault.revokeSessions("personal")
        XCTAssertEqual(s.aws.policies.first?.user, "andrew")
        XCTAssertEqual(s.aws.policies.first?.name, Vault.revokePolicyName)
        let doc = try JSONSerialization.jsonObject(with: Data(s.aws.policies.first!.document.utf8)) as! [String: Any]
        let statement = (doc["Statement"] as! [[String: Any]])[0]
        XCTAssertEqual(statement["Effect"] as? String, "Deny")
        let cond = (statement["Condition"] as! [String: [String: String]])["DateLessThan"]!["aws:TokenIssueTime"]
        XCTAssertEqual(cond, iso8601(cutoff))
        XCTAssertNil(try s.store.read(.session, "personal"))
        XCTAssertEqual(Vault.userName(fromArn: "arn:aws:iam::1:user/a/b/carol"), "carol")
        XCTAssertNil(Vault.userName(fromArn: "arn:aws:iam::1:root"))
        XCTAssertNil(Vault.userName(fromArn: "arn:aws:sts::1:assumed-role/r/s"))
    }

    func testDeleteForgetAndRestore() throws {
        let s = Sandbox(); defer { s.cleanup() }
        s.write(credentials: screenshotCredentials, config: "[default]\nregion = af-south-1\n")
        _ = try s.vault.importPlaintext(origin: "test")
        try s.vault.deleteKey("personal")
        XCTAssertTrue(s.aws.calls.contains("DeleteAccessKey AKIAPERSONAL0000001 AKIAPERSONAL0000001"))
        XCTAssertNil(s.master("personal"))
        XCTAssertNil(INIDocument(s.config).value("credential_process", in: "profile personal"))
        try s.vault.forget("bedrock")
        XCTAssertEqual(s.vault.list().map(\.profile), ["default"])

        let restored = try s.vault.restorePlaintext()
        XCTAssertEqual(restored, ["default"])
        XCTAssertTrue(s.credentials.contains("aws_secret_access_key = defaultsecretdefaultsecretdefaultsecret1"))
        XCTAssertEqual(s.config, "[default]\nregion = af-south-1\n")
        XCTAssertEqual(s.vault.list(), [])
    }

    func testInspectReportsLastUse() throws {
        let s = Sandbox(); defer { s.cleanup() }
        s.write(credentials: screenshotCredentials)
        _ = try s.vault.importPlaintext(origin: "test")
        s.aws.keys = [AccessKeyInfo(accessKeyId: "AKIADEFAULT00000001", status: "Active", createDate: nil)]
        let r = try s.vault.inspect("default")
        XCTAssertEqual(r.keys.first?.lastUsed?.serviceName, "s3")
        XCTAssertTrue(r.keys.first!.thisProfile)
        XCTAssertEqual(s.vault.meta.all()["default"]?.arn, "arn:aws:iam::123456789012:user/team/andrew")
    }

    func testClearSessions() throws {
        let s = Sandbox(); defer { s.cleanup() }
        s.write(credentials: screenshotCredentials)
        _ = try s.vault.importPlaintext(origin: "test")
        _ = try s.vault.credentials(for: "default", requester: "x")
        _ = try s.vault.credentials(for: "bedrock", requester: "x")
        XCTAssertEqual(try s.vault.clearSessions(), ["bedrock", "default"])
        XCTAssertEqual(try s.store.accounts(.session), [])
    }

    func testFailedSessionIsAudited() throws {
        let s = Sandbox(); defer { s.cleanup() }
        s.write(credentials: screenshotCredentials)
        _ = try s.vault.importPlaintext(origin: "test")
        s.aws.failSession = .aws(code: "InvalidClientTokenId", message: "The security token included in the request is invalid.")
        XCTAssertThrowsError(try s.vault.credentials(for: "default", requester: "x"))
        XCTAssertEqual(s.vault.audit.entries().last?.event, "session.failed")
        XCTAssertEqual(s.vault.audit.entries().last?.ok, false)
    }
}
