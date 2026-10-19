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
            Text(banner.text).font(.callout).textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
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

// MARK: Overview

struct OverviewView: View {
    @EnvironmentObject var model: Model

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Hero()
            if !model.exposed.isEmpty { PlaintextCard() }
            ChecksCard()
            Card(title: "Recent activity", symbol: "list.bullet.clipboard.fill", tint: Theme.teal,
                 trailing: AnyView(Button("All") { model.tab = .audit }.buttonStyle(.pill(Theme.teal)))) {
                let recent = Array(model.visibleAudit.prefix(5))
                if recent.isEmpty { Text("Nothing yet.").font(.callout).foregroundStyle(.secondary) }
                ForEach(recent) { AuditRow(entry: $0) }
            }
        }
    }
}

struct Hero: View {
    @EnvironmentObject var model: Model

    var exposed: Bool { !model.exposed.isEmpty || model.verification?.intact == false }

    var title: String {
        if !model.exposed.isEmpty { return "Plaintext keys found" }
        if model.verification?.intact == false { return "Audit trail tampered with" }
        if model.profiles.isEmpty { return "No keys yet" }
        return "Protected"
    }

    var subtitle: String {
        if !model.exposed.isEmpty { return "\(model.exposed.map(\.profile).joined(separator: ", ")) readable by anything on this Mac" }
        if model.profiles.isEmpty { return "Run Setup to move your AWS keys into the vault" }
        return "\(model.profiles.count) key\(model.profiles.count == 1 ? "" : "s") sealed by the Secure Enclave · Touch ID on use"
    }

    var usesToday: Int {
        let start = Calendar.current.startOfDay(for: Date())
        return model.audit.filter { ($0.event == "session.issued" || $0.event == "session.served") && ($0.date ?? .distantPast) >= start }.count
    }

    var body: some View {
        HStack(spacing: 18) {
            ZStack {
                Circle().stroke(.white.opacity(0.25), lineWidth: 8)
                Circle().trim(from: 0, to: exposed ? 0.35 : 1).stroke(.white, style: StrokeStyle(lineWidth: 8, lineCap: .round))
                    .rotationEffect(.degrees(-90))
                Image(systemName: exposed ? "exclamationmark.shield.fill" : "lock.shield.fill").font(.system(size: 34, weight: .semibold))
            }
            .frame(width: 84, height: 84)
            VStack(alignment: .leading, spacing: 6) {
                Text(title).font(.title2.weight(.bold))
                Text(subtitle).font(.callout).opacity(0.9).fixedSize(horizontal: false, vertical: true)
                HStack(spacing: 6) {
                    Label(model.settings.watching ? "Auto-move on" : "Auto-move off", systemImage: model.settings.watching ? "eye.fill" : "eye.slash.fill")
                    Text("·")
                    Label(durationText, systemImage: "timer")
                }
                .font(.caption.weight(.semibold))
                .padding(.horizontal, 10).padding(.vertical, 4)
                .background(Capsule().fill(.white.opacity(0.18)))
            }
            Spacer(minLength: 0)
            HStack(spacing: 8) {
                StatTile(value: "\(model.profiles.count)", label: "keys")
                StatTile(value: "\(model.profiles.filter { $0.sessionActive() }.count)", label: "sessions")
                StatTile(value: "\(usesToday)", label: "uses today")
            }
        }
        .foregroundStyle(.white)
        .padding(18)
        .background(RoundedRectangle(cornerRadius: 18, style: .continuous).fill(exposed ? Theme.exposedGradient : Theme.protectedGradient))
    }

    var durationText: String {
        let m = model.settings.sessionSeconds / 60
        return m % 60 == 0 ? "\(m / 60)h sessions" : "\(m)m sessions"
    }
}

struct StatTile: View {
    let value: String
    let label: String

    var body: some View {
        VStack(spacing: 2) {
            Text(value).font(.title2.weight(.bold)).monospacedDigit()
            Text(label).font(.caption.weight(.medium)).opacity(0.85)
        }
        .frame(width: 70, height: 58)
        .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(.white.opacity(0.16)))
    }
}

struct PlaintextCard: View {
    @EnvironmentObject var model: Model

    var body: some View {
        Card(title: "Plaintext keys in ~/.aws", symbol: "exclamationmark.triangle.fill", tint: Theme.danger,
             trailing: AnyView(Button { model.importNow() } label: { Label("Move to vault", systemImage: "lock.fill") }
                .buttonStyle(.pill(Theme.danger, filled: true)))) {
            ForEach(model.exposed, id: \.profile) { f in
                HStack(spacing: 10) {
                    SymbolTile(symbol: "key.fill", color: Theme.danger, size: 26)
                    Text(f.profile).font(.callout.weight(.semibold))
                    Text(maskKeyId(f.accessKeyId)).font(.system(.caption, design: .monospaced)).foregroundStyle(.secondary)
                    Spacer()
                    Text((f.file as NSString).lastPathComponent + (f.complete ? "" : " · half written")).font(.caption).foregroundStyle(.secondary)
                }
            }
            Text(model.settings.watching ? "The watcher moves these within seconds. If they stay, move them now."
                 : "Automatic move is off: these stay readable until you move them.")
                .font(.caption).foregroundStyle(.secondary)
        }
    }
}

/// Every test in one place: `doctor` for the state of things, then the tests that do something real.
struct ChecksCard: View {
    @EnvironmentObject var model: Model

    var body: some View {
        Card(title: "Health checks", symbol: "stethoscope", tint: Theme.violet,
             trailing: AnyView(Button { model.runChecks() } label: {
                 if model.checking { HStack(spacing: 6) { ProgressView().controlSize(.small); Text("Checking…") } }
                 else { Label(model.checks.isEmpty ? "Run checks" : "Run again", systemImage: "play.fill") }
             }.buttonStyle(.pill(Theme.violet)).disabled(model.checking))) {
            if model.checks.isEmpty {
                Text("Checks the enclave, the vault, ~/.aws, the AWS CLI wiring, the watcher and the audit chain, with no prompt.")
                    .font(.callout).foregroundStyle(.secondary)
            }
            ForEach(model.checks) { c in
                HStack(alignment: .top, spacing: 8) {
                    Image(systemName: !c.ok ? "xmark.circle.fill" : c.warn ? "exclamationmark.circle.fill" : "checkmark.circle.fill")
                        .foregroundStyle(!c.ok ? Theme.danger : c.warn ? Theme.warn : Theme.safe)
                    Text(c.name).font(.callout.weight(.semibold)).frame(width: 170, alignment: .leading)
                    Text(c.detail).font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                }
            }
            Divider()
            HStack(spacing: 8) {
                Button { model.testTouchID() } label: { Label("Test Touch ID", systemImage: "touchid") }.buttonStyle(.pill(Theme.accent))
                    .help("Shows the Touch ID prompt and unlocks nothing")
                Button { model.testWatcher() } label: { Label("Test auto-move", systemImage: "arrow.down.doc.fill") }.buttonStyle(.pill(Theme.info))
                    .help("Writes AWS's published example key into ~/.aws/credentials, times the watcher moving it, then removes it")
                Button { model.verify(report: true) } label: { Label("Verify audit chain", systemImage: "checkmark.seal.fill") }.buttonStyle(.pill(Theme.teal))
                Spacer()
            }
            .disabled(model.busy != nil)
            Text("Each key has its own Test button on the Keys tab: a real AWS call.").font(.caption).foregroundStyle(.secondary)
        }
    }
}

// MARK: Keys

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
                    }
                    Text(usedLine).font(.callout).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                    if let arn = profile.arn { Text(arn).font(.caption).foregroundStyle(.tertiary).lineLimit(1).truncationMode(.middle) }
                }
                Spacer(minLength: 0)
            }
            HStack(spacing: 8) {
                Button { model.test(profile.profile) } label: { Label("Test", systemImage: "play.fill") }.buttonStyle(.pill(Theme.safe))
                    .help("A real AWS call (GetCallerIdentity) with this profile: Touch ID if there is no session")
                Button { model.perform(.inspect, on: profile.profile) } label: { Label("Check in AWS", systemImage: "magnifyingglass") }.buttonStyle(.pill(Theme.info))
                    .help("Who the key belongs to, and when AWS last saw each of its keys used")
                Button { model.perform(.rotate, on: profile.profile) } label: { Label("Rotate", systemImage: "arrow.triangle.2.circlepath") }.buttonStyle(.pill(Theme.accent))
                    .disabled(profile.temporary)
                Button { model.perform(.revoke, on: profile.profile) } label: { Label("Revoke", systemImage: "xmark.shield") }.buttonStyle(.pill(Theme.danger))
                    .disabled(profile.temporary)
                Spacer()
                Menu {
                    ForEach([Action.clearSession, .disable, .delete, .forget], id: \.self) { a in
                        if a == .disable { Divider() }
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

    var usedLine: String {
        guard let used = profile.lastUsedAt else { return "Not used since it was moved here" }
        return "Used \(used.formatted(.relative(presentation: .named)))" + (profile.lastRequester.map { " by \($0)" } ?? "")
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

// MARK: MFA & phone

struct ProtectionView: View {
    @EnvironmentObject var model: Model

    var body: some View {
        VStack(spacing: 10) {
            Card(title: "Make AWS itself demand MFA", symbol: "lock.iphone", tint: Theme.violet) {
                Text("Touch ID protects the key on this Mac, but AWS doesn't know about it. Three steps per key: this Mac becomes an MFA device (still one Touch ID), AWS refuses the key without MFA, and a code from your phone approves a session when you are away from the Mac, for example while driving Claude Code with Remote Control.")
                    .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            ForEach(model.profiles.filter { !$0.temporary }) { MFACard(profile: $0) }
        }
    }
}

struct MFACard: View {
    @EnvironmentObject var model: Model
    let profile: ProfileMeta

    var steps: [(n: Int, title: String, detail: String, done: Bool, action: Action)] {
        [(1, "MFA on this Mac", "Sessions carry MFA, still one Touch ID", profile.mfaSerial != nil, .mfaSetup),
         (2, "AWS requires MFA", "A copy of the key alone is worthless", profile.mfaEnforced == true, .mfaEnforce),
         (3, "Phone approval", "Away from the Mac, a code approves", profile.remoteSerial != nil, .remoteEnable)]
    }

    var next: Int? { steps.first { !$0.done }?.n }

    /// Each finished step can be undone from its tile: in case something stops working.
    func undo(_ n: Int) -> Action? { [1: .mfaRemove, 2: .mfaUnenforce, 3: .remoteDisable][n] }

    var body: some View {
        Card(title: profile.profile, symbol: "key.fill", tint: Theme.accent,
             trailing: AnyView(Text("\(steps.filter(\.done).count) of 3").font(.callout.weight(.semibold)).foregroundStyle(.secondary))) {
            HStack(spacing: 8) {
                ForEach(steps, id: \.n) { s in
                    VStack(alignment: .leading, spacing: 6) {
                        HStack(spacing: 6) {
                            ZStack {
                                Circle().fill(s.done ? Theme.safe : (s.n == next ? Theme.violet : Theme.slate.opacity(0.4)))
                                if s.done { Image(systemName: "checkmark").font(.caption.weight(.bold)) } else { Text("\(s.n)").font(.caption.weight(.bold)) }
                            }
                            .foregroundStyle(.white).frame(width: 22, height: 22)
                            Text(s.title).font(.callout.weight(.semibold))
                        }
                        Text(s.detail).font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                        if !s.done && s.n == 3 {
                            Button { model.addPhone(profile.profile) } label: { Text("Add phone…") }
                                .buttonStyle(.pill(Theme.violet, filled: s.n == next)).disabled(s.n != next)
                                .help("Shows a QR code for Google Authenticator or any authenticator app")
                            Button("Phone already in IAM…") { model.perform(.remoteEnable, on: profile.profile) }
                                .buttonStyle(.link).font(.caption).disabled(s.n != next)
                        } else if !s.done {
                            Button { model.perform(s.action, on: profile.profile) } label: { Text(s.action.title) }
                                .buttonStyle(.pill(Theme.violet, filled: s.n == next)).disabled(s.n != next)
                        } else if let undo = undo(s.n) {
                            Button(undo.title.replacingOccurrences(of: "…", with: "")) { model.perform(undo, on: profile.profile) }
                                .buttonStyle(.link).font(.caption)
                                .help(undo.explain(profile.profile) ?? "")
                        }
                    }
                    .padding(10)
                    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
                    .background(RoundedRectangle(cornerRadius: 10).fill((s.done ? Theme.safe : Theme.violet).opacity(0.07)))
                }
            }
            .fixedSize(horizontal: false, vertical: true)
            if profile.remoteSerial != nil {
                HStack(spacing: 8) {
                    Button { model.approveWithCode(profile.profile) } label: { Label("Approve with code…", systemImage: "number") }.buttonStyle(.pill(Theme.info))
                        .help("Test phone approval: type a code from your authenticator app")
                    Spacer()
                }
            }
        }
        .disabled(model.busy != nil)
    }
}

// MARK: Audit trail

struct AuditView: View {
    @EnvironmentObject var model: Model

    var body: some View {
        Card(title: "Audit trail", symbol: "list.bullet.clipboard.fill", tint: Theme.teal, trailing: AnyView(chainStatus)) {
            HStack(spacing: 8) {
                Toggle("Hide routine use", isOn: $model.hideRoutine).toggleStyle(.checkbox)
                    .help("Hide “session used” entries: one is written every time a command reuses a cached session")
                Spacer()
                Button { model.verify(report: true) } label: { Label("Verify chain", systemImage: "checkmark.seal") }.buttonStyle(.pill(Theme.teal))
                    .help("Recompute every entry's hash and compare the newest with the sealed copy in the vault")
                Button { model.revealLog() } label: { Label("Show log file", systemImage: "doc.text.magnifyingglass") }.buttonStyle(.pill(Theme.slate))
            }
            Divider()
            LazyVStack(alignment: .leading, spacing: 6) {
                ForEach(model.visibleAudit) { AuditRow(entry: $0) }
            }
        }
    }

    @ViewBuilder var chainStatus: some View {
        if let v = model.verification {
            Pill(text: v.intact ? "chain intact · \(v.entries) entries" : "chain broken", symbol: v.intact ? "checkmark.seal.fill" : "xmark.seal.fill",
                 color: v.intact ? Theme.safe : Theme.danger)
        } else {
            Pill(text: "checking…", symbol: "seal", color: Theme.slate)
        }
    }
}

struct AuditRow: View {
    let entry: AuditEntry

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            SymbolTile(symbol: symbol, color: entry.ok ? color : Theme.danger, size: 26)
            VStack(alignment: .leading, spacing: 1) {
                HStack {
                    Text(title).font(.callout.weight(.semibold))
                    if let p = entry.profile { Text(p).font(.callout).foregroundStyle(.secondary) }
                    Spacer()
                    Text(entry.date.map { $0.formatted(date: .abbreviated, time: .shortened) } ?? entry.ts)
                        .font(.caption).foregroundStyle(.secondary)
                }
                if let r = entry.requester {
                    Text("← \(r)").font(.caption).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                }
                if !detail.isEmpty { Text(detail).font(.caption).foregroundStyle(.tertiary).lineLimit(2) }
            }
        }
    }

    var detail: String {
        entry.detail.filter { $0.key != "expires" || entry.event != "session.served" }
            .sorted { $0.key < $1.key }.map { "\($0.key): \($0.value)" }.joined(separator: " · ")
    }

    var title: String {
        [
            "key.imported": "Key moved into the vault", "key.added": "Key added", "key.created": "New key created",
            "key.rotated": "Key rotated", "key.rotate.failed": "Rotation incomplete", "key.disabled": "Key deactivated",
            "key.deleted": "Key deleted", "key.forgotten": "Key removed from this Mac", "key.inspected": "Checked in AWS",
            "key.restored": "Key written back to file", "session.issued": "Session issued",
            "session.served": "Session used", "session.failed": "Session request failed", "sessions.revoked": "All sessions revoked",
            "sessions.cleared": "Cached sessions cleared", "auth.denied": "Touch ID declined", "settings.duration": "Session length changed",
            "zsp.installed": "Installed", "zsp.uninstalled": "Uninstalled",
            "mfa.setup": "This Mac added as an MFA device", "mfa.enforced": "AWS now requires MFA",
            "remote.enabled": "Phone approval turned on", "remote.disabled": "Phone approval turned off",
            "mfa.unenforced": "AWS no longer requires MFA", "mfa.removed": "This Mac's MFA device removed",
            "mfa.phone.created": "Phone MFA device created", "mfa.phone.cancelled": "Unused phone MFA device deleted",
            "session.away": "Nobody at the Mac: no session", "keys.migrated": "Keys migrated",
            "setup.done": "Setup", "profile.tested": "Profile tested", "watcher.tested": "Auto-move tested",
        ][entry.event] ?? entry.event
    }

    var symbol: String {
        switch entry.event {
        case "key.imported", "key.added": return "tray.and.arrow.down.fill"
        case "session.issued": return "touchid"
        case "session.served": return "arrow.right"
        case "key.rotated", "key.created": return "arrow.triangle.2.circlepath"
        case "sessions.revoked": return "xmark.shield.fill"
        case "mfa.setup": return "lock.iphone"
        case "mfa.enforced": return "checkmark.shield.fill"
        case "remote.enabled", "remote.disabled", "mfa.phone.created", "mfa.phone.cancelled": return "iphone"
        case "mfa.unenforced": return "shield.slash"
        case "mfa.removed": return "lock.open"
        case "session.away": return "moon.zzz.fill"
        case "auth.denied", "session.failed", "key.rotate.failed": return "exclamationmark.triangle.fill"
        case "key.deleted", "key.forgotten": return "trash.fill"
        case "setup.done": return "wand.and.stars"
        case "profile.tested", "watcher.tested": return "play.fill"
        default: return "circle.fill"
        }
    }

    var color: Color {
        switch entry.event {
        case "key.imported", "key.added", "setup.done": return Theme.info
        case "session.issued", "session.served": return Theme.safe
        case "key.rotated", "key.created": return Theme.accent
        case "mfa.setup", "mfa.enforced", "remote.enabled", "remote.disabled", "mfa.unenforced", "mfa.removed", "mfa.phone.created", "mfa.phone.cancelled": return Theme.violet
        case "sessions.revoked", "key.deleted", "key.forgotten": return Theme.danger
        default: return Theme.slate
        }
    }
}
