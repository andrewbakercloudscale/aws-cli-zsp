// Draws Resources/AppIcon.icns: a white lock-shield on a dark AWS-orange-edged tile.
// Touch ID and Keychain dialogs badge themselves with this icon.
//   swift scripts/make-icon.swift && iconutil -c icns build/AppIcon.iconset -o Resources/AppIcon.icns
import AppKit

let set = URL(fileURLWithPath: "build/AppIcon.iconset")
try? FileManager.default.removeItem(at: set)
try FileManager.default.createDirectory(at: set, withIntermediateDirectories: true)

func draw(_ px: Int) -> Data {
    let s = CGFloat(px)
    let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: px, pixelsHigh: px, bitsPerSample: 8, samplesPerPixel: 4,
                               hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
    // macOS icon grid: the tile is 824/1024 of the canvas, corner radius ~185/1024.
    let tile = NSRect(x: s * 0.098, y: s * 0.098, width: s * 0.804, height: s * 0.804)
    let path = NSBezierPath(roundedRect: tile, xRadius: s * 0.18, yRadius: s * 0.18)
    NSGradient(starting: NSColor(red: 0.14, green: 0.18, blue: 0.27, alpha: 1),
               ending: NSColor(red: 0.05, green: 0.07, blue: 0.12, alpha: 1))!.draw(in: path, angle: -90)
    NSColor(red: 1.0, green: 0.6, blue: 0.0, alpha: 1).setStroke()   // AWS orange
    path.lineWidth = s * 0.018
    path.stroke()
    let config = NSImage.SymbolConfiguration(pointSize: s * 0.46, weight: .semibold)
        .applying(.init(paletteColors: [NSColor(red: 1.0, green: 0.6, blue: 0.0, alpha: 1), .white]))
    let symbol = NSImage(systemSymbolName: "lock.shield.fill", accessibilityDescription: nil)!.withSymbolConfiguration(config)!
    let size = symbol.size
    symbol.draw(in: NSRect(x: (s - size.width) / 2, y: (s - size.height) / 2, width: size.width, height: size.height))
    NSGraphicsContext.restoreGraphicsState()
    return rep.representation(using: .png, properties: [:])!
}

for base in [16, 32, 128, 256, 512] {
    try draw(base).write(to: set.appendingPathComponent("icon_\(base)x\(base).png"))
    try draw(base * 2).write(to: set.appendingPathComponent("icon_\(base)x\(base)@2x.png"))
}
