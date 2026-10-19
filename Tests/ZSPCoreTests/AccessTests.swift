import XCTest
@testable import ZSPCore

/// A client's key with a read-only IAM user: sessions work, IAM changes are not offered.
final class AccessTests: XCTestCase {
    static let readOnly: Set<String> = ["iam:ListAccessKeys", "iam:CreateAccessKey", "iam:UpdateAccessKey", "iam:DeleteAccessKey",
                                        "iam:PutUserPolicy", "iam:CreateVirtualMFADevice", "iam:EnableMFADevice"]

    func imported() throws -> Sandbox {
        let s = Sandbox()
        s.write(credentials: screenshotCredentials)
        _ = try s.vault.importPlaintext(origin: "test")
        return s
    }

    func testSessionsWorkForAReadOnlyUser() throws {
        let s = try imported(); defer { s.cleanup() }
        s.aws.denied = Self.readOnly
        XCTAssertEqual(try s.vault.credentials(for: "bedrock", requester: "aws s3 ls").accessKeyId, "ASIASESSION1")
    }

    func testARefusalIsLearnedAndTheNextAttemptNeedsNoTouchID() throws {
        let s = try imported(); defer { s.cleanup() }
        s.aws.denied = Self.readOnly
        XCTAssertThrowsError(try s.vault.rotate("bedrock")) {
            XCTAssertTrue($0.localizedDescription.contains("not allowed to change its access keys"), $0.localizedDescription)
        }
        XCTAssertEqual(s.vault.meta.all()["bedrock"]?.iamDenied, [.keys])
        XCTAssertTrue(s.vault.audit.entries().contains { $0.event == "access.denied" })
        let prompts = s.auth.reasons.count
        XCTAssertThrowsError(try s.vault.disableKey("bedrock"))
        XCTAssertEqual(s.auth.reasons.count, prompts, "refused before Touch ID")
        XCTAssertFalse(s.vault.meta.all()["bedrock"]!.cannot(.revoke), "only what was refused is hidden")
    }

    func testCheckInAWSSimulatesWhatTheUserMayDo() throws {
        let s = try imported(); defer { s.cleanup() }
        s.aws.denied = Self.readOnly
        let r = try s.vault.inspect("bedrock")
        XCTAssertEqual(r.identity.account, "123456789012", "listing keys refused, the identity still answers")
        XCTAssertTrue(r.keys.isEmpty)
        XCTAssertEqual(s.vault.meta.all()["bedrock"]?.iamDenied, IAMPermission.allCases)
        XCTAssertTrue(s.vault.meta.all()["bedrock"]!.readOnly)

        s.aws.denied = []
        _ = try s.vault.inspect("bedrock")
        XCTAssertEqual(s.vault.meta.all()["bedrock"]?.iamDenied, [], "a full user is offered everything again")
    }

    func testARefusedSimulationKeepsWhatWasLearned() throws {
        let s = try imported(); defer { s.cleanup() }
        s.aws.denied = ["iam:CreateAccessKey"]
        XCTAssertThrowsError(try s.vault.rotate("bedrock"))
        s.aws.simulationRefused = true
        _ = try s.vault.inspect("bedrock")
        XCTAssertEqual(s.vault.meta.all()["bedrock"]?.iamDenied, [.keys])
    }

    func testMarkingByHand() throws {
        let s = try imported(); defer { s.cleanup() }
        try s.vault.setAccess("bedrock", .readOnly)
        XCTAssertTrue(s.vault.meta.all()["bedrock"]!.readOnly)
        XCTAssertThrowsError(try s.vault.revokeSessions("bedrock")) {
            XCTAssertTrue($0.localizedDescription.contains("marked read-only"), $0.localizedDescription)
        }
        XCTAssertTrue(s.auth.reasons.isEmpty)

        try s.vault.setAccess("bedrock", nil)
        XCTAssertFalse(s.vault.meta.all()["bedrock"]!.readOnly)
        _ = try s.vault.revokeSessions("bedrock")
    }
}
