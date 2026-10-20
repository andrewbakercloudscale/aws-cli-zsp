import AppKit
import SwiftUI
import ZSPCore

struct OverviewView: View {
    @EnvironmentObject var model: Model

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Hero()
            if !model.exposed.isEmpty { PlaintextCard() }
            if !model.problems.isEmpty { ProblemsCard() }
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
        return model.audit.filter { [.sessionIssued, .sessionServed].contains($0.kind) && ($0.date ?? .distantPast) >= start }.count
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
                StatTile(value: "\(model.profiles.count)", label: "keys") { model.tab = .keys }
                StatTile(value: "\(model.profiles.filter { $0.sessionActive() }.count)", label: "sessions") { model.tab = .keys }
                StatTile(value: "\(usesToday)", label: "uses today") { model.tab = .audit }
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
    /// Opens the tab that lists what the number counts.
    let open: () -> Void

    var body: some View {
        Button(action: open) {
            VStack(spacing: 2) {
                Text(value).font(.title2.weight(.bold)).monospacedDigit()
                Text(label).font(.caption.weight(.medium)).opacity(0.85)
            }
            .frame(width: 70, height: 58)
            .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(.white.opacity(0.16)))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .help("Show \(label)")
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
                    Spacer(minLength: 0)
                    if let fix = c.fix, !c.ok {
                        Button(fix.title) { model.apply(fix) }.buttonStyle(.pill(Theme.danger, filled: true)).disabled(model.busy != nil)
                    }
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
            Divider()
            HStack(spacing: 8) {
                Button { model.saveDiagnostics() } label: { Label("Save diagnostics…", systemImage: "square.and.arrow.down") }.buttonStyle(.pill(Theme.slate))
                    .help("Writes a report for support to the Desktop: checks, settings, recent log lines and audit entries, with every secret removed")
                Button { model.openSupportLog() } label: { Label("Open support log", systemImage: "doc.text") }.buttonStyle(.pill(Theme.slate))
                Spacer()
            }
            .disabled(model.busy != nil)
        }
    }
}

/// Warnings and errors from the support log since you last dismissed them: an AWS error, a
/// Keychain refusal, a damaged file set aside.
struct ProblemsCard: View {
    @EnvironmentObject var model: Model

    var body: some View {
        Card(title: "Recent problems", symbol: "exclamationmark.bubble.fill", tint: Theme.warn,
             trailing: AnyView(Button("Dismiss") { model.dismissProblems() }.buttonStyle(.pill(Theme.slate)))) {
            ForEach(model.problems, id: \.self) { p in
                HStack(alignment: .top, spacing: 8) {
                    Image(systemName: p.level == .error ? "xmark.octagon.fill" : "exclamationmark.triangle.fill")
                        .foregroundStyle(p.level == .error ? Theme.danger : Theme.warn)
                    Text(p.date.formatted(.relative(presentation: .named))).font(.caption).foregroundStyle(.secondary).frame(width: 90, alignment: .leading)
                    Text(p.message).font(.callout).lineLimit(3).textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
                }
            }
            HStack(spacing: 8) {
                Button { model.runChecks() } label: { Label("Run checks", systemImage: "stethoscope") }.buttonStyle(.pill(Theme.violet))
                Button { model.saveDiagnostics() } label: { Label("Save diagnostics…", systemImage: "square.and.arrow.down") }.buttonStyle(.pill(Theme.slate))
                Button { model.openSupportLog() } label: { Label("Open support log", systemImage: "doc.text") }.buttonStyle(.pill(Theme.slate))
                Spacer()
            }
            .disabled(model.busy != nil)
        }
    }
}

extension Fix {
    var title: String {
        switch self {
        case .install: return "Repair"
        case .moveKeys: return "Move now"
        case .setup: return "Set up"
        }
    }
}
