import SwiftUI

@main
struct ZSPMenuApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @StateObject private var model = Model()

    var body: some Scene {
        MenuBarExtra {
            ContentView().environmentObject(model)
        } label: {
            Image(systemName: model.statusSymbol)
        }
        .menuBarExtraStyle(.window)
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    /// `ZSPMenu --snapshot out.png [--audit]` renders the panel to a file and quits: how the
    /// README screenshots are made, and a way to check the UI without clicking the menu bar.
    func applicationDidFinishLaunching(_ notification: Notification) {
        let args = CommandLine.arguments
        guard let i = args.firstIndex(of: "--snapshot"), i + 1 < args.count else { return }
        MainActor.assumeIsolated {
            let model = Model()
            if args.contains("--audit") { model.tab = .audit }
            // An offscreen window rather than ImageRenderer, which draws AppKit-backed controls
            // (pickers, menus, scroll views) as placeholders.
            let host = NSHostingView(rootView: ContentView().environmentObject(model))
            let window = NSWindow(contentRect: NSRect(x: -10_000, y: 0, width: 460, height: 700), styleMask: [.borderless],
                                  backing: .buffered, defer: false)
            window.contentView = host
            window.orderFrontRegardless()
            DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
                window.setContentSize(host.fittingSize)
                host.layoutSubtreeIfNeeded()
                if let rep = host.bitmapImageRepForCachingDisplay(in: host.bounds) {
                    host.cacheDisplay(in: host.bounds, to: rep)
                    try? rep.representation(using: .png, properties: [:])?.write(to: URL(fileURLWithPath: args[i + 1]))
                }
                exit(0)
            }
        }
    }
}
