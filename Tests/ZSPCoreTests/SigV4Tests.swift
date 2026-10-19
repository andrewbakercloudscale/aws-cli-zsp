import XCTest
@testable import ZSPCore

final class SigV4Tests: XCTestCase {
    /// The worked example from AWS's Signature Version 4 documentation (IAM ListUsers).
    func testAWSDocumentationVector() {
        let headers = ["content-type": "application/x-www-form-urlencoded; charset=utf-8",
                       "host": "iam.amazonaws.com", "x-amz-date": "20150830T123600Z"]
        let (request, signed) = SigV4.canonicalRequest(method: "GET", path: "/",
                                                       query: [("Version", "2010-05-08"), ("Action", "ListUsers")],
                                                       headers: headers, payloadHash: SigV4.sha256Hex(Data()))
        XCTAssertEqual(signed, "content-type;host;x-amz-date")
        XCTAssertEqual(SigV4.sha256Hex(Data(request.utf8)), "f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59")

        var f = DateComponents()
        f.year = 2015; f.month = 8; f.day = 30; f.hour = 12; f.minute = 36; f.second = 0
        var cal = Calendar(identifier: .gregorian)
        cal.timeZone = TimeZone(identifier: "UTC")!
        let date = cal.date(from: f)!
        let auth = SigV4.authorization(method: "GET", path: "/", query: [("Action", "ListUsers"), ("Version", "2010-05-08")],
                                       headers: headers, payload: Data(),
                                       credentials: AWSCredentials(accessKeyId: "AKIDEXAMPLE", secretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"),
                                       region: "us-east-1", service: "iam", date: date)
        XCTAssertEqual(auth, "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7")
    }

    func testURIEncoding() {
        XCTAssertEqual(SigV4.uriEncode("a b/c+d=e~f"), "a%20b%2Fc%2Bd%3De~f")
        XCTAssertEqual(SigV4.uriEncode("é"), "%C3%A9")
    }

    func testQueryServiceSignsAndParses() throws {
        var seen: URLRequest?
        let xml = """
        <GetSessionTokenResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetSessionTokenResult><Credentials>
        <SessionToken>TOKEN</SessionToken><SecretAccessKey>SECRET</SecretAccessKey>
        <Expiration>2026-10-19T12:00:00Z</Expiration><AccessKeyId>ASIAX</AccessKeyId></Credentials></GetSessionTokenResult></GetSessionTokenResponse>
        """
        let svc = AWSQueryService(transport: { r in seen = r; return (200, Data(xml.utf8)) })
        let s = try svc.getSessionToken(AWSCredentials(accessKeyId: "AKIA1", secretAccessKey: "s"), durationSeconds: 900)
        XCTAssertEqual(s, AWSCredentials(accessKeyId: "ASIAX", secretAccessKey: "SECRET", sessionToken: "TOKEN",
                                         expiration: parseISO8601("2026-10-19T12:00:00Z")))
        XCTAssertEqual(seen?.url?.host, "sts.us-east-1.amazonaws.com")
        XCTAssertEqual(String(data: seen!.httpBody!, encoding: .utf8), "Action=GetSessionToken&Version=2011-06-15&DurationSeconds=900")
        XCTAssertTrue(seen!.value(forHTTPHeaderField: "Authorization")!.hasPrefix("AWS4-HMAC-SHA256 Credential=AKIA1/"))
    }

    func testQueryServiceErrorsAndLists() throws {
        let err = "<ErrorResponse><Error><Type>Sender</Type><Code>InvalidClientTokenId</Code><Message>bad</Message></Error></ErrorResponse>"
        let bad = AWSQueryService(transport: { _ in (403, Data(err.utf8)) })
        XCTAssertThrowsError(try bad.getCallerIdentity(AWSCredentials(accessKeyId: "a", secretAccessKey: "b"))) {
            XCTAssertEqual($0 as? ZSPError, .aws(code: "InvalidClientTokenId", message: "bad"))
        }
        let list = """
        <ListAccessKeysResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><ListAccessKeysResult><AccessKeyMetadata>
        <member><UserName>u</UserName><AccessKeyId>AKIA1</AccessKeyId><Status>Active</Status><CreateDate>2024-01-01T00:00:00Z</CreateDate></member>
        <member><UserName>u</UserName><AccessKeyId>AKIA2</AccessKeyId><Status>Inactive</Status><CreateDate>2025-01-01T00:00:00Z</CreateDate></member>
        </AccessKeyMetadata><IsTruncated>false</IsTruncated></ListAccessKeysResult></ListAccessKeysResponse>
        """
        let ok = AWSQueryService(transport: { _ in (200, Data(list.utf8)) })
        let keys = try ok.listAccessKeys(AWSCredentials(accessKeyId: "a", secretAccessKey: "b"))
        XCTAssertEqual(keys.map(\.accessKeyId), ["AKIA1", "AKIA2"])
        XCTAssertEqual(keys.map(\.status), ["Active", "Inactive"])
    }
}

/// Real STS with a made-up key: AWS must answer InvalidClientTokenId, which proves the
/// request reached it signed and well formed. Opt in with ZSP_NETWORK_TESTS=1.
final class NetworkTests: XCTestCase {
    func testRealSTSRejectsAFakeKey() throws {
        try XCTSkipUnless(ProcessInfo.processInfo.environment["ZSP_NETWORK_TESTS"] == "1")
        let fake = AWSCredentials(accessKeyId: "AKIAZSPTESTFAKE00001", secretAccessKey: "fakefakefakefakefakefakefakefakefake0001")
        XCTAssertThrowsError(try AWSQueryService().getCallerIdentity(fake)) {
            XCTAssertEqual(($0 as? ZSPError).flatMap { if case let .aws(code, _) = $0 { return code }; return nil }, "InvalidClientTokenId")
        }
    }
}
