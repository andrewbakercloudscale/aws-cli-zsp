import AppKit
import SwiftUI
import ZSPCore

struct KeysView: View {
    @EnvironmentObject var model: Model

    var body: some View {
        VStack(spacing: 10) {
            if model.profiles.isEmpty {
                Card(title: "No keys yet", symbol: "key", tint: Theme.accent) {
                    Text("Run Setup to choose which keys in ~/.aws move into the vault, or add one with `aws-cli-zsp add --profile NAME`.")
                        .font(.callout).foregroundStyle(.secondary)
                    Button { model.page = .setup } label: { Label("Open Setup", systemImage: "wand.and.stars") }.buttonStyle(.pill(Theme.violet, filled: true))
                }
            }
            ForEach(model.profiles) { KeyCard(profile: $0) }
            if !model.keptPlaintext.isEmpty {
                Card(title: "Kept in plain text by choice", symbol: "doc.plaintext", tint: Theme.warn) {
                    ForEach(model.keptPlaintext, id: \.profile) { f in
                        Text("\(f.profile)  \(maskKeyId(f.accessKeyId))  in \((f.file as NSString).lastPathComponent)").font(.callout)
                    }
                    Text("Never moved automatically. Change that in Setup.").font(.caption).foregroundStyle(.secondary)
                }
            }
        }
    }
}

struct KeyCard: View {
    @EnvironmentObject var model: Model
    let profile: ProfileMeta
    /// The last requester is a whole command line, often far wider than the card.
    @State private var expanded = false

    var body: some View {
        Card {
            HStack(alignment: .top, spacing: 12) {
                SymbolTile(symbol: profile.sessionActive() ? "key.fill" : "key", color: profile.sessionActive() ? Theme.safe : Theme.accent, size: 38)
                VStack(alignment: .leading, spacing: 4) {
                    HStack(spacing: 8) {
                        Text(profile.profile).font(.title3.weight(.semibold))
                        Text(profile.maskedKeyId).font(.system(.callout, design: .monospaced)).foregroundStyle(.secondary)
                        if let s = profile.keyStatus, s != "Active" { Pill(text: s, color: Theme.danger) }
                        if profile.temporary { Pill(text: "temporary", color: Theme.warn) }
                    }
                    HStack(spacing: 6) {
                        if let exp = profile.sessionExpiresAt, exp > Date() {
                            Pill(text: "session until \(exp.formatted(date: .omitted, time: .shortened))", symbol: "clock.fill", color: Theme.safe)
                        } else {
                            Pill(text: "no session · Touch ID next", symbol: "touchid", color: Theme.slate)
                        }
                        if profile.mfaEnforced == true { Pill(text: "MFA enforced", symbol: "checkmark.shield.fill", color: Theme.violet) }
                        else if profile.mfaSerial != nil { Pill(text: "MFA", symbol: "lock.iphone", color: Theme.violet) }
                        if profile.remoteSerial != nil { Pill(text: "phone approval", symbol: "iphone", color: Theme.info) }
                        if let a = profile.pinnedAccount { Pill(text: "pinned to \(a)", symbol: "pin.fill", color: Theme.accent) }
                        if profile.readOnly { Pill(text: "read-only · client's key", symbol: "eye", color: Theme.slate) }
                        else if IAMPermission.allCases.contains(where: profile.cannot) { Pill(text: "limited IAM", symbol: "eye", color: Theme.slate) }
                    }
                    Button { withAnimation(.easeInOut(duration: 0.15)) { expanded.toggle() } } label: {
                        HStack(alignment: .firstTextBaseline, spacing: 4) {
                            Image(systemName: "chevron.right").font(.caption2.weight(.semibold))
                                .rotationEffect(.degrees(expanded ? 90 : 0))
                            VStack(alignment: .leading, spacing: 4) {
                                Text(usedLine).font(.callout).foregroundStyle(.secondary)
                                if let arn = profile.arn { Text(arn).font(.caption).foregroundStyle(.tertiary) }
                            }
                            .lineLimit(expanded ? nil : 1).truncationMode(.middle)
                            .fixedSize(horizontal: false, vertical: expanded)
                            .textSelection(.enabled)
                        }
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain).foregroundStyle(.secondary)
                    .help(expanded ? "Collapse" : "Show the full command and ARN")
                    if expanded {
                        HStack(spacing: 8) {
                            if let r = profile.lastRequester { CopyButton(title: "Copy command", text: r) }
                            if let arn = profile.arn { CopyButton(title: "Copy ARN", text: arn) }
                        }
                        .padding(.leading, 16)
                    }
                }
                Spacer(minLength: 0)
            }
            HStack(spacing: 8) {
                Button { model.test(profile.profile) } label: { Label("Test", systemImage: "play.fill") }.buttonStyle(.pill(Theme.safe))
                    .help("A real AWS call (GetCallerIdentity) with this profile: Touch ID if there is no session")
                Button { model.perform(.inspect, on: profile.profile) } label: { Label("Check in AWS", systemImage: "magnifyingglass") }.buttonStyle(.pill(Theme.info))
                    .help("Who the key belongs to, and when AWS last saw each of its keys used")
                if !profile.cannot(.keys) {
                    Button { model.perform(.rotate, on: profile.profile) } label: { Label("Rotate", systemImage: "arrow.triangle.2.circlepath") }.buttonStyle(.pill(Theme.accent))
                        .disabled(profile.temporary)
                }
                if !profile.cannot(.revoke) {
                    Button { model.perform(.revoke, on: profile.profile) } label: { Label("Revoke", systemImage: "xmark.shield") }.buttonStyle(.pill(Theme.danger))
                        .disabled(profile.temporary)
                }
                Spacer()
                Menu {
                    ForEach(menu, id: \.self) { a in
                        if [.disable, .forget].contains(a) || (a == .markReadOnly || a == .markAuto) { Divider() }
                        Button { model.perform(a, on: profile.profile) } label: { Label(a.title, systemImage: a.symbol) }
                            .disabled(profile.temporary && [.disable, .delete].contains(a))
                    }
                } label: { Image(systemName: "ellipsis.circle.fill").font(.title3) }
                    .menuStyle(.borderlessButton).fixedSize()
            }
            .disabled(model.busy != nil)
            if let t = model.tests[profile.profile] {
                Label(t.text, systemImage: t.isError ? "xmark.circle.fill" : "checkmark.circle.fill")
                    .font(.callout).foregroundStyle(t.isError ? Theme.danger : Theme.safe).textSelection(.enabled)
            }
            if let r = model.inspect, r.profile == profile.profile { InspectView(report: r) }
        }
    }

    /// A client's key that IAM will not let change itself offers only what works.
    var menu: [Action] {
        let limited = IAMPermission.allCases.contains(where: profile.cannot)
        return [.clearSession] + (profile.cannot(.keys) ? [] : [.disable, .delete]) + [.forget]
            + (profile.temporary ? [] : [limited ? .markAuto : .markReadOnly])
    }

    var usedLine: String {
        guard let used = profile.lastUsedAt else { return "Not used since it was moved here" }
        return "Used \(used.formatted(.relative(presentation: .named)))" + (profile.lastRequester.map { " by \($0)" } ?? "")
    }
}

/// Puts `text` on the clipboard and says so for a moment.
struct CopyButton: View {
    let title: String
    let text: String
    @State private var copied = false

    var body: some View {
        Button {
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(text, forType: .string)
            copied = true
            DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { copied = false }
        } label: { Label(copied ? "Copied" : title, systemImage: copied ? "checkmark" : "doc.on.doc").font(.caption) }
            .buttonStyle(.borderless)
    }
}

struct InspectView: View {
    @EnvironmentObject var model: Model
    let report: InspectReport

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text("In AWS").font(.callout.weight(.semibold))
                Spacer()
                Button { model.inspect = nil } label: { Image(systemName: "xmark") }.buttonStyle(.borderless)
            }
            Text(report.identity.arn).font(.caption).textSelection(.enabled)
            ForEach(report.keys, id: \.accessKeyId) { k in
                let used = k.lastUsed?.lastUsedDate.map {
                    "last used \($0.formatted(date: .abbreviated, time: .shortened)) · \(k.lastUsed?.serviceName ?? "?") · \(k.lastUsed?.region ?? "?")"
                } ?? "never used"
                Text("\(maskKeyId(k.accessKeyId)) \(k.status)\(k.thisProfile ? " (this profile)" : "") · \(used)")
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(k.thisProfile ? .primary : .secondary)
            }
            Text("A last use you don't recognise means someone else has the key: rotate it, then revoke sessions.")
                .font(.caption).foregroundStyle(.secondary)
        }
        .padding(10)
        .background(RoundedRectangle(cornerRadius: 10).fill(Theme.info.opacity(0.08)))
    }
}
