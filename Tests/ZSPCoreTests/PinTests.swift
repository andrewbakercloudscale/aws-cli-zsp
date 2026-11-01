import Security
import XCTest
@testable import ZSPCore

final class PinTests: XCTestCase {
    func pinned() throws -> (Sandbox, MemoryStore) {
        let s = Sandbox()
        let pins = MemoryStore()
        s.vault.pins = pins
        s.write(credentials: screenshotCredentials)
        _ = try s.vault.importPlaintext(origin: "test")
        return (s, pins)
    }

    /// The Keychain refusing to answer without a dialog.
    final class SilentPins: SecretStore {
        let inner = MemoryStore()
        var refuse = false
        func read(_ kind: SecretKind, _ account: String) throws -> Data? {
            if refuse { throw ZSPError.keychain(errSecAuthFailed, "would need a dialog") }
            return try inner.read(kind, account)
        }
        func peek(_ kind: SecretKind, _ account: String) -> Data? { inner.peek(kind, account) }
        func write(_ kind: SecretKind, _ account: String, _ data: Data) throws {
            if refuse { throw ZSPError.keychain(errSecAuthFailed, "would need a dialog") }
            try inner.write(kind, account, data)
        }
        func delete(_ kind: SecretKind, _ account: String) throws { try inner.delete(kind, account) }
        func accounts(_ kind: SecretKind) throws -> [String] { try inner.accounts(kind) }
    }

    func awaySandbox() throws -> (Sandbox, SilentPins, AWSCredentials) {
        let s = Sandbox()
        let pins = SilentPins()
        s.vault.pins = pins
        s.write(credentials: screenshotCredentials)
        _ = try s.vault.importPlaintext(origin: "test")
        return (s, pins, try s.vault.credentials(for: "bedrock", requester: "at the mac"))
    }

    func testAnUnreadablePinDoesNotBlockACachedSessionWhileAway() throws {
        let (s, pins, session) = try awaySandbox(); defer { s.cleanup() }
        pins.refuse = true
        s.vault.someoneAtMac = { false }
        XCTAssertEqual(try s.vault.credentials(for: "bedrock", requester: "away").accessKeyId, session.accessKeyId)
    }

    func testAnUnreadablePinStillFailsWithSomeoneAtTheMac() throws {
        let (s, pins, _) = try awaySandbox(); defer { s.cleanup() }
        pins.refuse = true
        XCTAssertThrowsError(try s.vault.credentials(for: "bedrock", requester: "here"))
    }

    func testASessionIssuedAwayIsAuditedAndReplacedQuietlyOnReturn() throws {
        let (s, pins, _) = try awaySandbox(); defer { s.cleanup() }
        let before = try XCTUnwrap(s.vault.pin("bedrock")).sessionKeyId
        let away = AWSCredentials(accessKeyId: "ASIAAWAY", secretAccessKey: "x", sessionToken: "t", expiration: Date().addingTimeInterval(3600))
        pins.refuse = true
        s.vault.someoneAtMac = { false }
        try s.vault.checkPin("bedrock", away, requester: "phone")
        XCTAssertTrue(s.vault.audit.entries().contains { $0.event == "pin.unverified" })
        try s.store.write(.session, "bedrock", try ZSPJSON.encoder.encode(away))

        pins.refuse = false
        s.vault.someoneAtMac = { true }
        let fresh = try s.vault.credentials(for: "bedrock", requester: "back")
        XCTAssertNotEqual(fresh.accessKeyId, "ASIAAWAY")
        XCTAssertNotEqual(fresh.accessKeyId, before)
        XCTAssertFalse(s.vault.audit.entries().contains { $0.event == "session.swapped" })
    }

    func testAKeyToAnotherAccountIsRefusedWhileAwayToo() throws {
        let (s, pins, _) = try awaySandbox(); defer { s.cleanup() }
        pins.refuse = true
        s.vault.someoneAtMac = { false }
        s.aws.identity = CallerIdentity(account: "999999999999", arn: "arn:aws:iam::999999999999:user/attacker", userId: "AIDAX")
        let creds = AWSCredentials(accessKeyId: "ASIAX", secretAccessKey: "x", sessionToken: "t", expiration: Date().addingTimeInterval(3600))
        XCTAssertThrowsError(try s.vault.checkPin("bedrock", creds, requester: "phone"))
    }

    func testFirstSessionPinsTheAccountAndUser() throws {
        let (s, _) = try pinned(); defer { s.cleanup() }
        let session = try s.vault.credentials(for: "bedrock", requester: "aws s3 ls")
        let pin = try XCTUnwrap(try s.vault.pin("bedrock"))
        XCTAssertEqual(pin.account, "123456789012")
        XCTAssertEqual(pin.arn, "arn:aws:iam::123456789012:user/team/andrew")
        XCTAssertEqual(pin.sessionKeyId, session.accessKeyId)
        XCTAssertEqual(s.vault.meta.all()["bedrock"]?.pinnedAccount, "123456789012")
        XCTAssertTrue(s.vault.audit.entries().contains { $0.event == "pin.set" })
    }

    func testAKeyToAnotherAccountIsRefused() throws {
        let (s, _) = try pinned(); defer { s.cleanup() }
        _ = try s.vault.credentials(for: "bedrock", requester: "aws s3 ls")
        try s.vault.clearSessions("bedrock")
        s.aws.identity = CallerIdentity(account: "999999999999", arn: "arn:aws:iam::999999999999:user/attacker", userId: "AIDAX")
        XCTAssertThrowsError(try s.vault.credentials(for: "bedrock", requester: "aws s3 ls")) {
            XCTAssertTrue($0.localizedDescription.contains("pinned to arn:aws:iam::123456789012"), $0.localizedDescription)
        }
        XCTAssertNil(try s.store.read(.session, "bedrock"), "the attacker's session is not kept")
        XCTAssertTrue(s.vault.audit.entries().contains { $0.event == "key.swapped" })
    }

    func testASessionNotIssuedByUsIsNotServed() throws {
        let (s, _) = try pinned(); defer { s.cleanup() }
        _ = try s.vault.credentials(for: "bedrock", requester: "aws s3 ls")
        let planted = AWSCredentials(accessKeyId: "ASIAPLANTED", secretAccessKey: "x", sessionToken: "t",
                                     expiration: Date().addingTimeInterval(3600))
        try s.store.write(.session, "bedrock", try ZSPJSON.encoder.encode(planted))
        XCTAssertThrowsError(try s.vault.credentials(for: "bedrock", requester: "aws s3 ls"))
        XCTAssertNil(try s.store.read(.session, "bedrock"))
        XCTAssertTrue(s.vault.audit.entries().contains { $0.event == "session.swapped" })
        // The next call issues a fresh session with Touch ID.
        XCTAssertNotEqual(try s.vault.credentials(for: "bedrock", requester: "aws s3 ls").accessKeyId, "ASIAPLANTED")
    }

    func testRotationInTheSameAccountPassesAndResetRepins() throws {
        let (s, _) = try pinned(); defer { s.cleanup() }
        _ = try s.vault.credentials(for: "bedrock", requester: "aws s3 ls")
        let cached = try s.vault.credentials(for: "bedrock", requester: "aws s3 ls")
        XCTAssertEqual(cached.accessKeyId, try s.vault.pin("bedrock")?.sessionKeyId, "our own cached session is served")

        try s.vault.clearSessions("bedrock")
        s.aws.identity = CallerIdentity(account: "999999999999", arn: "arn:aws:iam::999999999999:user/me", userId: "AIDAY")
        try s.vault.resetPin("bedrock")
        XCTAssertNil(try s.vault.pin("bedrock"))
        _ = try s.vault.credentials(for: "bedrock", requester: "aws s3 ls")
        XCTAssertEqual(try s.vault.pin("bedrock")?.account, "999999999999")
    }

    func testForgetDropsThePin() throws {
        let (s, pins) = try pinned(); defer { s.cleanup() }
        _ = try s.vault.credentials(for: "bedrock", requester: "aws s3 ls")
        try s.vault.forget("bedrock")
        XCTAssertNil(try pins.read(.pin, "bedrock"))
    }
}
