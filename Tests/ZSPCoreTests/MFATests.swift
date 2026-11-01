import XCTest
@testable import ZSPCore

final class MFATests: XCTestCase {
    func testTOTPMatchesRFC6238() {
        // RFC 6238 appendix B, SHA-1, last 6 of the 8 digits.
        let secret = Data("12345678901234567890".utf8)
        XCTAssertEqual(TOTP.code(secret: secret, counter: TOTP.counter(at: Date(timeIntervalSince1970: 59))), "287082")
        XCTAssertEqual(TOTP.code(secret: secret, counter: TOTP.counter(at: Date(timeIntervalSince1970: 1_111_111_109))), "081804")
        XCTAssertEqual(TOTP.base32Decode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"), secret)
        XCTAssertNil(TOTP.base32Decode("not base32!"))
        XCTAssertTrue(TOTP.isCode("012345"))
        XCTAssertFalse(TOTP.isCode("12345"))
    }

    func setUpWithMFA() throws -> Sandbox {
        let s = Sandbox()
        s.write(credentials: screenshotCredentials)
        _ = try s.vault.importPlaintext(origin: "test")
        let serial = try s.vault.setupMFA("bedrock", deviceName: "aws-cli-zsp-mac-bedrock")
        XCTAssertEqual(serial, "arn:aws:iam::123456789012:mfa/aws-cli-zsp-mac-bedrock")
        return s
    }

    func testSetupSealsTheSeedWithTheKeyAndSessionsCarryMFA() throws {
        let s = try setUpWithMFA(); defer { s.cleanup() }
        XCTAssertEqual(s.aws.enabled.count, 1)
        XCTAssertNotEqual(s.aws.enabled[0].code1, s.aws.enabled[0].code2, "two consecutive codes")
        XCTAssertEqual(s.master("bedrock")?.mfaSeed, s.aws.mfaSeed)
        XCTAssertEqual(s.vault.meta.all()["bedrock"]?.mfaSerial, "arn:aws:iam::123456789012:mfa/aws-cli-zsp-mac-bedrock")

        _ = try s.vault.credentials(for: "bedrock", requester: "aws s3 ls")
        let code = try XCTUnwrap(s.aws.mfaCodes.last)
        XCTAssertEqual(code.serial, "arn:aws:iam::123456789012:mfa/aws-cli-zsp-mac-bedrock")
        XCTAssertNotEqual(code.code, s.aws.enabled[0].code2, "a code AWS has seen is not sent again")

        // Re-importing the same key keeps the seed.
        s.write(credentials: "[bedrock]\naws_access_key_id=AKIABEDROCK00000001\naws_secret_access_key=bedrocksecretbedrocksecretbedrocksecret1\n")
        _ = try s.vault.importPlaintext(origin: "test")
        XCTAssertEqual(s.master("bedrock")?.mfaSeed, s.aws.mfaSeed)
    }

    func testEnforceNeedsSetupAndAttachesTheDenyWithoutMFAPolicy() throws {
        let s = Sandbox(); defer { s.cleanup() }
        s.write(credentials: screenshotCredentials)
        _ = try s.vault.importPlaintext(origin: "test")
        XCTAssertThrowsError(try s.vault.enforceMFA("bedrock"), "no MFA device here: would lock this Mac out")
        XCTAssertTrue(s.aws.policies.isEmpty)

        _ = try s.vault.setupMFA("bedrock", deviceName: "mac")
        try s.vault.enforceMFA("bedrock")
        let p = try XCTUnwrap(s.aws.policies.last)
        XCTAssertEqual(p.name, Vault.requireMFAPolicyName)
        XCTAssertTrue(p.document.contains("\"aws:MultiFactorAuthPresent\":\"false\""))
        let doc = try JSONSerialization.jsonObject(with: Data(p.document.utf8)) as? [String: Any]
        let statements = try XCTUnwrap(doc?["Statement"] as? [[String: Any]])
        XCTAssertEqual(statements.count, 2, "valid JSON with both statements")
        XCTAssertTrue((statements[1]["Action"] as? [String])?.contains("iam:CreateAccessKey") == true)
        XCTAssertTrue(s.aws.calls.contains { $0.hasPrefix("GetSessionToken AKIABEDROCK00000001 900 mfa=") },
                      "the policy is attached from an MFA session: \(s.aws.calls)")
        XCTAssertEqual(s.vault.meta.all()["bedrock"]?.mfaEnforced, true)
    }

    func testRemoteApprovalNeedsEnforcementAndKeepsNoSeed() throws {
        let s = try setUpWithMFA(); defer { s.cleanup() }
        XCTAssertThrowsError(try s.vault.enableRemote("bedrock", serial: nil), "not enforced yet")
        try s.vault.enforceMFA("bedrock")
        XCTAssertThrowsError(try s.vault.enableRemote("bedrock", serial: nil), "no phone device yet")

        s.aws.mfaDevices.append("arn:aws:iam::123456789012:mfa/iphone")
        XCTAssertEqual(try s.vault.enableRemote("bedrock", serial: nil), "arn:aws:iam::123456789012:mfa/iphone")
        let copy = try XCTUnwrap(try s.store.read(.remote, "bedrock")).flatMap { try ZSPJSON.decoder.decode(MasterKey.self, from: $0) }
        XCTAssertEqual(copy?.accessKeyId, "AKIABEDROCK00000001")
        XCTAssertNil(copy?.mfaSeed, "the remote copy must not be able to make its own codes")

        let before = s.auth.reasons.count
        XCTAssertThrowsError(try s.vault.approve("bedrock", code: "12345", requester: "x"))
        let session = try s.vault.approve("bedrock", code: "654321", requester: "aws s3 ls ← claude")
        XCTAssertEqual(s.auth.reasons.count, before, "approval by code asks for no Touch ID")
        XCTAssertEqual(s.aws.mfaCodes.last, MFACode(serial: "arn:aws:iam::123456789012:mfa/iphone", code: "654321"))
        // The next aws command is served that session, away or not.
        s.vault.someoneAtMac = { false }
        XCTAssertEqual(try s.vault.credentials(for: "bedrock", requester: "aws s3 ls").accessKeyId, session.accessKeyId)
        XCTAssertEqual(s.vault.audit.entries().last { $0.event == "session.issued" }?.detail["approved"], "mfa-code")

        try s.vault.disableRemote("bedrock")
        XCTAssertNil(try s.store.read(.remote, "bedrock"))
        XCTAssertThrowsError(try s.vault.approve("bedrock", code: "654321", requester: "x"))
    }

    func testNobodyAtTheMacFailsAtOnceWithWhatToDo() throws {
        let s = Sandbox(); defer { s.cleanup() }
        s.write(credentials: screenshotCredentials)
        _ = try s.vault.importPlaintext(origin: "test")
        s.vault.someoneAtMac = { false }
        XCTAssertThrowsError(try s.vault.credentials(for: "default", requester: "aws s3 ls")) { error in
            XCTAssertTrue(error.localizedDescription.contains("remote enable"), error.localizedDescription)
        }
        XCTAssertEqual(s.auth.reasons, [], "no prompt nobody would see")
        XCTAssertEqual(s.vault.audit.entries().last?.event, "session.away")
    }

    func testRotateKeepsMFAAndRetiresTheOldKeyFromTheMFASession() throws {
        let s = try setUpWithMFA(); defer { s.cleanup() }
        try s.vault.enforceMFA("bedrock")
        s.aws.mfaDevices.append("arn:aws:iam::123456789012:mfa/iphone")
        _ = try s.vault.enableRemote("bedrock", serial: nil)
        s.aws.keys = [AccessKeyInfo(accessKeyId: "AKIABEDROCK00000001", status: "Active", createDate: nil)]
        s.aws.calls = []
        _ = try s.vault.rotate("bedrock")
        XCTAssertEqual(s.master("bedrock")?.mfaSeed, s.aws.mfaSeed)
        let delete = try XCTUnwrap(s.aws.calls.first { $0.hasPrefix("DeleteAccessKey") })
        XCTAssertTrue(delete.hasPrefix("DeleteAccessKey ASIA"), "the old key is retired from an MFA session: \(delete)")
        let copy = try XCTUnwrap(try s.store.read(.remote, "bedrock")).flatMap { try ZSPJSON.decoder.decode(MasterKey.self, from: $0) }
        XCTAssertEqual(copy?.accessKeyId, "AKIANEWKEY000000001", "the remote copy follows the rotation")
        XCTAssertNil(copy?.mfaSeed)
    }
}

final class SetupTests: XCTestCase {
    func testImportOnlyAndSkip() throws {
        let s = Sandbox(); defer { s.cleanup() }
        s.write(credentials: screenshotCredentials)
        let r = try s.vault.importPlaintext(origin: "test", only: ["bedrock", "default"], skip: ["default"])
        XCTAssertEqual(r.imported, ["bedrock"])
        XCTAssertEqual(Set(Scanner.scan(s.paths).map(\.profile)), ["default", "personal"], "the others stay where they were")
    }

    func testOldSettingsFilesStillLoad() throws {
        let s = Sandbox(); defer { s.cleanup() }
        try s.paths.ensureSupportDir()
        try #"{"profileSessionSeconds":{"bedrock":43200},"sessionSeconds":1800}"#.write(to: s.paths.settingsFile, atomically: true, encoding: .utf8)
        let settings = Settings.load(s.paths)
        XCTAssertEqual(settings.sessionSeconds, 1800, "0.2 settings keep their values")
        XCTAssertFalse(settings.watching, "not set up yet: the watcher waits")
        var on = settings
        on.onboarded = true
        XCTAssertTrue(on.watching)
        on.autoImport = false
        XCTAssertFalse(on.watching)
    }
}

final class MFAUndoTests: XCTestCase {
    func enforced() throws -> Sandbox {
        let s = Sandbox()
        s.write(credentials: screenshotCredentials)
        _ = try s.vault.importPlaintext(origin: "test")
        _ = try s.vault.setupMFA("bedrock", deviceName: "aws-cli-zsp-mac-bedrock")
        try s.vault.enforceMFA("bedrock")
        return s
    }

    func testAddPhoneFromTheMacEnablesItAndTurnsOnApproval() throws {
        let s = try enforced(); defer { s.cleanup() }
        let d = try s.vault.addPhone("bedrock", deviceName: "aws-cli-zsp-phone-bedrock")
        XCTAssertTrue(d.uri.hasPrefix("otpauth://totp/AWS:andrew@123456789012"), d.uri)
        XCTAssertTrue(d.uri.contains("secret=\(s.aws.phoneSeed)"))
        XCTAssertNil(s.vault.meta.all()["bedrock"]?.remoteSerial, "not until the phone has proved it scanned the code")
        XCTAssertThrowsError(try s.vault.confirmPhone("bedrock", serial: d.serial, code1: "123456", code2: "123456"), "two different codes")
        try s.vault.confirmPhone("bedrock", serial: d.serial, code1: "123456", code2: "654321")
        XCTAssertEqual(s.vault.meta.all()["bedrock"]?.remoteSerial, d.serial)
        XCTAssertNotNil(try s.store.read(.remote, "bedrock"))
    }

    func testAPhoneNeverConfirmedIsNamedEverywherePhoneApprovalIsSaidToBeOff() throws {
        let s = try enforced(); defer { s.cleanup() }
        let d = try s.vault.addPhone("bedrock", deviceName: "aws-cli-zsp-phone-bedrock")
        XCTAssertEqual(s.vault.waitingPhone("bedrock"), d.serial)
        let finish = "mfa confirm-phone --profile bedrock --serial \(d.serial) CODE1 CODE2"
        XCTAssertTrue(s.vault.phoneSetupAdvice("bedrock").contains(finish))
        XCTAssertTrue(s.vault.phoneSetupAdvice("bedrock").contains("mfa cancel-phone --profile bedrock --serial \(d.serial)"))
        XCTAssertFalse(s.vault.phoneSetupAdvice("bedrock").contains("remote enable"), "that finds no device: AWS lists it only once enabled")

        s.vault.someoneAtMac = { false }
        XCTAssertThrowsError(try s.vault.credentials(for: "bedrock", requester: "aws s3 ls")) { XCTAssertTrue("\($0)".contains(finish), "\($0)") }
        XCTAssertThrowsError(try s.vault.approve("bedrock", code: "123456", requester: "t")) { XCTAssertTrue("\($0)".contains(finish), "\($0)") }
        XCTAssertThrowsError(try s.vault.enableRemote("bedrock", serial: nil)) { XCTAssertTrue("\($0)".contains(finish), "\($0)") }
    }

    func testNoPhoneWaitingStillSendsYouToRemoteEnable() throws {
        let s = try enforced(); defer { s.cleanup() }
        XCTAssertNil(s.vault.waitingPhone("bedrock"))
        s.vault.someoneAtMac = { false }
        for attempt in [{ _ = try s.vault.credentials(for: "bedrock", requester: "aws s3 ls") },
                        { _ = try s.vault.approve("bedrock", code: "123456", requester: "t") }] {
            XCTAssertThrowsError(try attempt()) {
                XCTAssertTrue("\($0)".contains("remote enable --profile bedrock"), "\($0)")
                XCTAssertFalse("\($0)".contains("confirm-phone"), "\($0)")
            }
        }
        XCTAssertThrowsError(try s.vault.enableRemote("bedrock", serial: nil)) { XCTAssertTrue("\($0)".contains("mfa add-phone"), "\($0)") }
    }

    func testAPhoneStopsWaitingOnceConfirmedOrCancelled() throws {
        let s = try enforced(); defer { s.cleanup() }
        let cancelled = try s.vault.addPhone("bedrock", deviceName: "phone-a")
        try s.vault.cancelPhone("bedrock", serial: cancelled.serial)
        XCTAssertNil(s.vault.waitingPhone("bedrock"), "cancelled")

        let confirmed = try s.vault.addPhone("bedrock", deviceName: "phone-b")
        try s.vault.confirmPhone("bedrock", serial: confirmed.serial, code1: "123456", code2: "654321")
        XCTAssertNil(s.vault.waitingPhone("bedrock"), "confirmed")
        try s.vault.disableRemote("bedrock")
        XCTAssertNil(s.vault.waitingPhone("bedrock"), "confirmed, then phone approval turned off: nothing to finish")
    }

    func testAPhoneDoesNotWaitOncePhoneApprovalIsOnThroughAnother() throws {
        let s = try enforced(); defer { s.cleanup() }
        _ = try s.vault.addPhone("bedrock", deviceName: "phone-never-scanned")
        s.aws.mfaDevices.append("arn:aws:iam::123456789012:mfa/phone-in-iam")
        _ = try s.vault.enableRemote("bedrock", serial: "arn:aws:iam::123456789012:mfa/phone-in-iam")
        XCTAssertNil(s.vault.waitingPhone("bedrock"), "codes already approve this key")
    }

    func testOnlyTheNewestOfSeveralWaitingPhonesAndOnlyItsOwnProfile() throws {
        let s = try enforced(); defer { s.cleanup() }
        let older = try s.vault.addPhone("bedrock", deviceName: "phone-a")
        let newer = try s.vault.addPhone("bedrock", deviceName: "phone-b")
        try s.vault.audit.append(.phoneCreated, profile: "other", detail: ["device": "arn:aws:iam::123456789012:mfa/other"])
        XCTAssertEqual(s.vault.waitingPhone("bedrock"), newer.serial)
        try s.vault.cancelPhone("bedrock", serial: newer.serial)
        XCTAssertEqual(s.vault.waitingPhone("bedrock"), older.serial)
        XCTAssertNil(s.vault.waitingPhone("other"), "not a key in the vault")
    }

    func testAPhoneDoesNotWaitOnceAWSNoLongerDemandsMFA() throws {
        let s = try enforced(); defer { s.cleanup() }
        _ = try s.vault.addPhone("bedrock", deviceName: "phone")
        try s.vault.unenforceMFA("bedrock")
        XCTAssertNil(s.vault.waitingPhone("bedrock"), "confirm-phone would refuse: run mfa enforce first")
    }

    /// The class of fault: a message saying phone approval is off that forgets a waiting phone.
    func testOnlyTheAdviceSendsAnyoneToRemoteEnable() throws {
        let sources = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().appendingPathComponent("Sources/ZSPCore")
        let files = try FileManager.default.contentsOfDirectory(at: sources, includingPropertiesForKeys: nil)
        let swift = files.filter { $0.pathExtension == "swift" }
        XCTAssertGreaterThan(swift.count, 5, "the sources were found")
        let found = try swift.flatMap { url in
            try String(contentsOf: url, encoding: .utf8).components(separatedBy: "\n")
                .filter { $0.contains("remote enable") && !$0.trimmingCharacters(in: .whitespaces).hasPrefix("//") }
                .map { "\(url.lastPathComponent): \($0)" }
        }
        XCTAssertEqual(found.count, 1, found.joined(separator: "\n"))
        XCTAssertTrue(found.first?.hasPrefix("Vault+Phone.swift") == true, found.joined(separator: "\n"))
        let status = sources.deletingLastPathComponent().appendingPathComponent("zsp/KeyCommands.swift")
        XCTAssertTrue(try String(contentsOf: status, encoding: .utf8).contains("vault.phoneSetupAdvice(p.profile)"), "status names the waiting phone")
    }

    func testAddPhoneNeedsEnforcement() throws {
        let s = Sandbox(); defer { s.cleanup() }
        s.write(credentials: screenshotCredentials)
        _ = try s.vault.importPlaintext(origin: "test")
        XCTAssertThrowsError(try s.vault.addPhone("bedrock", deviceName: "phone"))
        XCTAssertFalse(s.aws.calls.contains { $0.hasPrefix("CreateVirtualMFADevice") })
    }

    func testUnenforceRemovesThePolicyAndPhoneApproval() throws {
        let s = try enforced(); defer { s.cleanup() }
        s.aws.mfaDevices.append("arn:aws:iam::123456789012:mfa/phone")
        _ = try s.vault.enableRemote("bedrock", serial: nil)
        try s.vault.unenforceMFA("bedrock")
        XCTAssertTrue(s.aws.policies.isEmpty)
        let m = s.vault.meta.all()["bedrock"]
        XCTAssertNil(m?.mfaEnforced)
        XCTAssertNil(m?.remoteSerial, "its copy of the key is safe only while AWS demands a code")
        XCTAssertNil(try s.store.read(.remote, "bedrock"))
        XCTAssertNotNil(m?.mfaSerial, "this Mac stays an MFA device")
    }

    func testRemoveUndoesEverythingFromTheMFASessionFirst() throws {
        let s = try enforced(); defer { s.cleanup() }
        try s.vault.removeMFA("bedrock")
        let serial = "arn:aws:iam::123456789012:mfa/aws-cli-zsp-mac-bedrock"
        let policy = try XCTUnwrap(s.aws.calls.firstIndex { $0.hasPrefix("DeleteUserPolicy") })
        let deactivate = try XCTUnwrap(s.aws.calls.firstIndex(of: "DeactivateMFADevice andrew \(serial)"))
        XCTAssertLessThan(policy, deactivate, "the policy goes while the device can still give MFA")
        XCTAssertTrue(s.aws.calls.contains("DeleteVirtualMFADevice \(serial)"))
        XCTAssertNil(s.master("bedrock")?.mfaSeed)
        XCTAssertNil(s.vault.meta.all()["bedrock"]?.mfaSerial)
        _ = try s.vault.credentials(for: "bedrock", requester: "aws s3 ls")
        XCTAssertTrue(s.aws.calls.last?.hasSuffix(" 3600") == true, "plain sessions again: \(s.aws.calls.last ?? "")")
    }
}
