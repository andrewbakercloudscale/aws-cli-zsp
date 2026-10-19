import XCTest
@testable import ZSPCore

final class INITests: XCTestCase {
    func testRoundTripKeepsEverything() {
        let text = "# top\n[default]\nregion = af-south-1\ns3 =\n  max_concurrent_requests = 20\n\n[profile x] ; c\nk=v\n"
        XCTAssertEqual(INIDocument(text).text, text)
        XCTAssertEqual(INIDocument("a = b").text, "a = b")
        XCTAssertEqual(INIDocument("").text, "")
    }

    func testValuesAndSections() {
        let doc = INIDocument(screenshotCredentials)
        XCTAssertEqual(doc.sectionNames, ["default", "bedrock", "personal"])
        XCTAssertEqual(doc.value("aws_access_key_id", in: "bedrock"), "AKIABEDROCK00000001")
        XCTAssertEqual(doc.value("region", in: "bedrock"), "us-east-1")
        XCTAssertNil(doc.value("region", in: "default"))
    }

    func testRemoveKeepsOtherSettingsAndContinuations() {
        var doc = INIDocument("[a]\naws_secret_access_key = x\nregion = r\ns3 =\n  addressing_style = path\n")
        XCTAssertEqual(doc.remove(keys: AWSFiles.secretKeys, in: "a"), 1)
        XCTAssertEqual(doc.text, "[a]\nregion = r\ns3 =\n  addressing_style = path\n")
        var nested = INIDocument("[a]\naws_session_token =\n  junk\nregion = r\n")
        nested.remove(keys: AWSFiles.secretKeys, in: "a")
        XCTAssertEqual(nested.text, "[a]\nregion = r\n")
    }

    func testSetReplacesAddsAndCreates() {
        var doc = INIDocument("[default]\nregion = a\n\n[profile b]\nregion = b\n")
        doc.set("region", "z", in: "default")
        doc.set("output", "json", in: "default")
        doc.set("credential_process", "zsp", in: "profile c")
        XCTAssertEqual(doc.text, "[default]\nregion = z\noutput = json\n\n[profile b]\nregion = b\n\n[profile c]\ncredential_process = zsp\n")
        var empty = INIDocument("")
        empty.set("k", "v", in: "default")
        XCTAssertEqual(empty.text, "[default]\nk = v\n")
    }

    func testRemoveHeaderIfEmpty() {
        var doc = INIDocument("[a]\nk = v\n\n[b]\n\n[c]\nk = v\n")
        doc.removeHeaderIfEmpty("b")
        XCTAssertEqual(doc.text, "[a]\nk = v\n\n[c]\nk = v\n")
        doc.removeHeaderIfEmpty("a")
        XCTAssertEqual(doc.text, "[a]\nk = v\n\n[c]\nk = v\n", "a section with settings stays")
    }

    func testProfileNames() {
        XCTAssertEqual(AWSFiles.profileName(configSection: "default"), "default")
        XCTAssertEqual(AWSFiles.profileName(configSection: "profile bedrock"), "bedrock")
        XCTAssertNil(AWSFiles.profileName(configSection: "sso-session corp"))
        XCTAssertEqual(AWSFiles.configSection(for: "default"), "default")
        XCTAssertEqual(AWSFiles.configSection(for: "x"), "profile x")
    }

    func testShellQuote() {
        XCTAssertEqual(shellQuote("/a/b/zsp"), "/a/b/zsp")
        XCTAssertEqual(shellQuote("my profile"), "'my profile'")
        XCTAssertEqual(shellQuote("it's"), "'it'\\''s'")
    }
}
