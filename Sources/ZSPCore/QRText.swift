import CoreImage
import Foundation

/// A QR code drawn in the terminal, so `mfa add-phone` can be scanned where it was run
/// instead of the user hunting for a QR generator to paste the secret into.
public enum QRText {
    /// The QR modules for `text`, `true` for dark, with no quiet zone. Nil when CoreImage cannot
    /// encode it.
    public static func modules(_ text: String) -> [[Bool]]? {
        guard let f = CIFilter(name: "CIQRCodeGenerator") else { return nil }
        f.setValue(Data(text.utf8), forKey: "inputMessage")
        f.setValue("M", forKey: "inputCorrectionLevel")
        guard let image = f.outputImage else { return nil }
        // CoreImage adds a one-module margin of its own; render at one pixel a module and read it back.
        let w = Int(image.extent.width), h = Int(image.extent.height)
        guard w > 2, w == h else { return nil }
        var pixels = [UInt8](repeating: 0, count: w * h * 4)
        CIContext(options: [.useSoftwareRenderer: true]).render(
            image, toBitmap: &pixels, rowBytes: w * 4, bounds: image.extent,
            format: .RGBA8, colorSpace: CGColorSpaceCreateDeviceRGB())
        // The bitmap's first row is the image's top; a pixel under half brightness is a dark module.
        let all = (0..<h).map { y in (0..<w).map { x in pixels[(y * w + x) * 4] < 128 } }
        return Array(all[1..<(h - 1)].map { Array($0[1..<(w - 1)]) })
    }

    /// The code as text, two module rows per line with half blocks, black on white whatever the
    /// terminal's theme (a scanner needs dark modules on a light ground), with the four-module
    /// quiet zone the QR standard asks for.
    public static func render(_ text: String) -> String? {
        guard let m = modules(text) else { return nil }
        let quiet = 4
        let size = m.count + 2 * quiet
        let dark = { (y: Int, x: Int) -> Bool in
            let (yy, xx) = (y - quiet, x - quiet)
            return yy >= 0 && yy < m.count && xx >= 0 && xx < m.count && m[yy][xx]
        }
        var lines: [String] = []
        for y in stride(from: 0, to: size, by: 2) {
            var line = "\u{1B}[38;5;16;48;5;231m"
            for x in 0..<size {
                switch (dark(y, x), dark(y + 1, x)) {
                case (true, true): line += "█"
                case (true, false): line += "▀"
                case (false, true): line += "▄"
                case (false, false): line += " "
                }
            }
            lines.append(line + "\u{1B}[0m")
        }
        return lines.joined(separator: "\n")
    }
}
