import CoreImage
import XCTest
@testable import ZSPCore

final class QRTextTests: XCTestCase {
    let uri = "otpauth://totp/AWS:andrew@123456789012%20(bedrock)?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=AWS" // pragma:allow-secret, a made-up example seed
    /// Reads a module grid back the way a phone would: draws it 10 pixels a module, black on
    /// white with a quiet zone, and asks CoreImage's QR detector what it says.
    func decode(_ m: [[Bool]]) -> String? {
        let scale = 10, quiet = 4, side = (m.count + 2 * quiet) * scale
        var px = [UInt8](repeating: 255, count: side * side * 4)
        for y in 0..<side { for x in 0..<side {
            let (my, mx) = (y / scale - quiet, x / scale - quiet)
            let dark = my >= 0 && my < m.count && mx >= 0 && mx < m.count && m[my][mx]
            if dark { let i = (y * side + x) * 4; px[i] = 0; px[i + 1] = 0; px[i + 2] = 0 }
        } }
        let image = CIImage(bitmapData: Data(px), bytesPerRow: side * 4, size: CGSize(width: side, height: side),
                            format: .RGBA8, colorSpace: CGColorSpaceCreateDeviceRGB())
        let detector = CIDetector(ofType: CIDetectorTypeQRCode, context: nil, options: [CIDetectorAccuracy: CIDetectorAccuracyHigh])
        return (detector?.features(in: image).first as? CIQRCodeFeature)?.messageString
    }

    func testModulesScanBackToTheURI() throws {
        let m = try XCTUnwrap(QRText.modules(uri))
        XCTAssertTrue(m.count >= 21 && m.allSatisfy { $0.count == m.count }, "a square grid of at least version 1")
        XCTAssertEqual(decode(m), uri)
    }

    func testFinderPatternsSitInTheCorners() throws {
        // No CoreImage margin left in: the top-left module is the finder's dark corner.
        let m = try XCTUnwrap(QRText.modules(uri))
        let n = m.count
        for (y, x) in [(0, 0), (0, n - 7), (n - 7, 0)] {
            XCTAssertTrue((0..<7).allSatisfy { m[y][x + $0] && m[y + 6][x + $0] && m[y + $0][x] && m[y + $0][x + 6] }, "finder ring at \(y),\(x)")
            XCTAssertTrue((2..<5).allSatisfy { i in (2..<5).allSatisfy { m[y + i][x + $0] } }, "finder centre at \(y),\(x)")
            XCTAssertTrue((1..<6).allSatisfy { !m[y + 1][x + $0] }, "light ring inside the finder at \(y),\(x)")
        }
        XCTAssertTrue((0..<8).allSatisfy { !m[7][$0] && !m[$0][7] }, "the separator after the top-left finder is light")
    }

    func testAnotherTextIsNotThisCode() throws {
        let other = try XCTUnwrap(QRText.modules(uri.replacingOccurrences(of: "JBSW", with: "KBSW")))
        XCTAssertNotEqual(decode(other), uri)
    }

    func testRenderIsBlackOnWhiteHalfBlocksWithAQuietZone() throws {
        let m = try XCTUnwrap(QRText.modules(uri))
        let text = try XCTUnwrap(QRText.render(uri))
        let lines = text.components(separatedBy: "\n")
        let side = m.count + 8
        XCTAssertEqual(lines.count, (side + 1) / 2, "two module rows a line")
        let body = lines.map { $0.replacingOccurrences(of: "\u{1B}[38;5;16;48;5;231m", with: "").replacingOccurrences(of: "\u{1B}[0m", with: "") }
        XCTAssertTrue(lines.allSatisfy { $0.hasPrefix("\u{1B}[38;5;16;48;5;231m") && $0.hasSuffix("\u{1B}[0m") }, "colours set and reset on every line")
        XCTAssertTrue(body.allSatisfy { $0.count == side }, "one character a module column")
        XCTAssertEqual(body[0], String(repeating: " ", count: side), "quiet zone on top")
        XCTAssertEqual(body[1], String(repeating: " ", count: side), "four modules of it")
        // Rebuild the grid from the half blocks and scan it.
        var grid: [[Bool]] = []
        for line in body {
            let chars = Array(line)
            grid.append(chars.map { $0 == "█" || $0 == "▀" })
            grid.append(chars.map { $0 == "█" || $0 == "▄" })
        }
        let inner = grid[4..<(4 + m.count)].map { Array($0[4..<(4 + m.count)]) }
        XCTAssertEqual(inner, m, "the half blocks carry exactly the modules")
        XCTAssertEqual(decode(inner), uri)
    }
}
