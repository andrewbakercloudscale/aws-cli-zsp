import AppKit
import SwiftUI
import ZSPCore

/// The panel: header, tabs, the selected screen, then the footer. Setup and About replace the
/// tabs while they are open.
struct ContentView: View {
    @EnvironmentObject var model: Model

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Header()
            switch model.page {
            case .setup: SetupView()
            case .about: AboutView()
            case let .phoneGuide(profile): PhoneGuideView(selected: profile)
            case .main:
                TabBar(selection: $model.tab, badges: [.overview: model.exposed.count])
                ScrollView {
                    Group {
                        switch model.tab {
                        case .overview: OverviewView()
                        case .keys: KeysView()
                        case .protection: ProtectionView()
                        case .audit: AuditView()
                        }
                    }
                    .padding(.bottom, 4)
                }
                .frame(maxHeight: 560)
            }
            if let b = model.banner { BannerView(banner: b) }
            Footer()
        }
        .padding(16)
        .frame(width: 640)
    }
}

struct Header: View {
    @EnvironmentObject var model: Model

    var body: some View {
        HStack(spacing: 12) {
            Image(nsImage: NSApp.applicationIconImage).resizable().frame(width: 42, height: 42)
            VStack(alignment: .leading, spacing: 1) {
                Text("AWS CLI: ZSP").font(.title3.weight(.bold))
                Text("v\(Model.appVersion)  ·  Zero Standing Permissions").font(.callout).foregroundStyle(.secondary)
            }
            Spacer()
            if let busy = model.busy {
                HStack(spacing: 6) { ProgressView().controlSize(.small); Text(busy).font(.caption) }
                    .padding(.horizontal, 10).padding(.vertical, 5)
                    .background(Capsule().fill(Color.primary.opacity(0.06)))
            } else if !model.exposed.isEmpty {
                Pill(text: "\(model.exposed.count) plaintext key\(model.exposed.count == 1 ? "" : "s")", symbol: "exclamationmark.triangle.fill", color: Theme.danger)
            } else if !model.keptPlaintext.isEmpty {
                Pill(text: "\(model.keptPlaintext.count) kept in plain text", symbol: "doc.plaintext", color: .orange)
            } else {
                Pill(text: "no plaintext keys", symbol: "checkmark.shield.fill", color: Theme.safe)
            }
            let active = model.profiles.filter { $0.sessionActive() }.count
            Pill(text: "\(active) active session\(active == 1 ? "" : "s")", symbol: "clock.fill", color: active > 0 ? Theme.info : Theme.slate)
        }
    }
}

struct BannerView: View {
    @EnvironmentObject var model: Model
    let banner: Banner

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: banner.isError ? "exclamationmark.triangle.fill" : "checkmark.circle.fill")
                .foregroundStyle(banner.isError ? Theme.danger : Theme.safe)
            VStack(alignment: .leading, spacing: 4) {
                Text(banner.text).font(.callout).textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
                if banner.isError {
                    Button("Save diagnostics for support…") { model.saveDiagnostics() }.buttonStyle(.link).font(.caption)
                }
            }
            Spacer()
            Button { model.banner = nil } label: { Image(systemName: "xmark") }.buttonStyle(.borderless)
        }
        .padding(10)
        .background(RoundedRectangle(cornerRadius: 10).fill((banner.isError ? Theme.danger : Theme.safe).opacity(0.12)))
    }
}

struct Footer: View {
    @EnvironmentObject var model: Model

    var body: some View {
        HStack(spacing: 8) {
            if model.page != .main {
                Button { model.page = .main } label: { Label("Back", systemImage: "chevron.left") }.buttonStyle(.pill(Theme.slate))
            }
            Spacer()
            Button { model.page = .setup } label: { Label("Setup", systemImage: "wand.and.stars") }.buttonStyle(.pill(Theme.violet))
                .help("Look at ~/.aws again and choose what moves into the vault, and whether new keys move automatically")
            Button { model.page = .about } label: { Label("About", systemImage: "info.circle") }.buttonStyle(.pill(Theme.info))
            Button { NSApplication.shared.terminate(nil) } label: { Label("Quit", systemImage: "power") }.buttonStyle(.pill(Theme.danger))
        }
    }
}
