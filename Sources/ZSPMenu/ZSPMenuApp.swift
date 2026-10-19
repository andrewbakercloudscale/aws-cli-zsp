import SwiftUI

@main
struct ZSPMenuApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate

    var body: some Scene {
        MenuBarExtra {
            ContentView().environmentObject(delegate.model)
        } label: {
            StatusIcon(model: delegate.model)
        }
        .menuBarExtraStyle(.window)
    }
}

struct StatusIcon: View {
    @ObservedObject var model: Model
    var body: some View { Image(systemName: model.statusSymbol) }
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate, NSWindowDelegate {
    /// One model for the menu bar panel and the window, so both show the same state.
    let model = Model()
    private var window: NSWindow?

    /// A full menu bar hides status items behind the notch without telling anyone, so the panel
    /// is also a window: opening the app (Spotlight, Finder, `aws-cli-zsp ui`) shows it. The
    /// login agent starts it with no window.
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        showWindow()
        return false
    }

    func showWindow() {
        if window == nil {
            let w = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 460, height: 600),
                             styleMask: [.titled, .closable, .miniaturizable], backing: .buffered, defer: false)
            w.title = "AWS CLI: ZSP"
            w.isReleasedWhenClosed = false
            w.delegate = self
            let host = NSHostingView(rootView: ContentView().environmentObject(model))
            host.sizingOptions = [.preferredContentSize]   // the window follows the panel's height
            w.contentView = host
            w.center()
            window = w
        }
        // In the Dock and ⌘-Tab while the window is open; menu bar only again once it closes.
        NSApp.setActivationPolicy(.regular)
        window?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    func windowWillClose(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)
    }

    /// `ZSPMenu --snapshot out.png [--audit]` renders the panel to a file and quits: how the
    /// README screenshots are made, and a way to check the UI without clicking the menu bar.
    func applicationDidFinishLaunching(_ notification: Notification) {
        let args = CommandLine.arguments
        guard let i = args.firstIndex(of: "--snapshot"), i + 1 < args.count else {
            let atLogin = args.contains("--background")
                || ProcessInfo.processInfo.environment["XPC_SERVICE_NAME"] == "consulting.cloudscale.zsp.menu"
            if !atLogin { showWindow() }
            return
        }
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
