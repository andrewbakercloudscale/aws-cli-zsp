import SwiftUI
import ZSPCore

struct ContentView: View {
    @EnvironmentObject var model: Model

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Header()
            if !model.findings.isEmpty { PlaintextWarning() }
            Picker("", selection: $model.tab) {
                Text("In use").tag(Tab.inUse)
                Text("Audit trail").tag(Tab.audit)
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            if model.tab == .inUse { ProfilesView() } else { AuditView() }
            if let r = model.inspect { InspectView(report: r) }
            if let b = model.banner {
                HStack(alignment: .top) {
                    Image(systemName: b.isError ? "exclamationmark.triangle.fill" : "checkmark.circle.fill")
                        .foregroundStyle(b.isError ? .red : .green)
                    Text(b.text).font(.caption).textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
                    Spacer()
                    Button { model.banner = nil } label: { Image(systemName: "xmark") }.buttonStyle(.borderless)
                }
                .padding(8)
                .background(RoundedRectangle(cornerRadius: 6).fill((b.isError ? Color.red : Color.green).opacity(0.12)))
            }
            Divider()
            HStack {
                Text("AWS CLI: ZSP").font(.caption).foregroundStyle(.secondary)
                Spacer()
                Button("Quit") { NSApplication.shared.terminate(nil) }.buttonStyle(.borderless).font(.caption)
            }
        }
        .padding(14)
        .frame(width: 460)
    }
}

struct Header: View {
    @EnvironmentObject var model: Model

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: model.findings.isEmpty ? "lock.shield.fill" : "exclamationmark.shield.fill")
                .font(.title)
                .foregroundStyle(model.findings.isEmpty ? .green : .red)
            VStack(alignment: .leading, spacing: 2) {
                Text(model.findings.isEmpty ? "No AWS keys in plain text" : "Plaintext AWS keys found").font(.headline)
                Text(summary).font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            if let busy = model.busy {
                ProgressView().controlSize(.small)
                Text(busy).font(.caption).foregroundStyle(.secondary)
            }
        }
    }

    var summary: String {
        let active = model.profiles.filter { $0.sessionActive() }.count
        return "\(model.profiles.count) key\(model.profiles.count == 1 ? "" : "s") in the vault · \(active) active session\(active == 1 ? "" : "s")"
    }
}

struct PlaintextWarning: View {
    @EnvironmentObject var model: Model

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            ForEach(model.findings, id: \.profile) { f in
                Text("“\(f.profile)” \(maskKeyId(f.accessKeyId)) in \((f.file as NSString).lastPathComponent)\(f.complete ? "" : " (half written)")")
                    .font(.caption)
            }
            HStack {
                Text("The watcher moves these within seconds. If they stay, move them now:").font(.caption2).foregroundStyle(.secondary)
                Spacer()
                Button("Move to vault") { model.importNow() }.controlSize(.small)
            }
        }
        .padding(8)
        .background(RoundedRectangle(cornerRadius: 6).fill(Color.red.opacity(0.12)))
    }
}

struct ProfilesView: View {
    @EnvironmentObject var model: Model

    var body: some View {
        if model.profiles.isEmpty {
            Text("No keys yet. Run `aws-cli-zsp add --profile NAME`, or `aws configure`: the key is moved here automatically.")
                .font(.caption).foregroundStyle(.secondary).padding(.vertical, 20)
        } else {
            ScrollView {
                VStack(spacing: 8) {
                    ForEach(model.profiles) { ProfileRow(profile: $0) }
                }
            }
            .frame(maxHeight: 380)
        }
    }
}

struct ProfileRow: View {
    @EnvironmentObject var model: Model
    let profile: ProfileMeta

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: profile.sessionActive() ? "key.fill" : "key")
                .foregroundStyle(profile.sessionActive() ? .green : .secondary)
                .frame(width: 18)
                .help(profile.sessionActive() ? "A session is cached: commands run without Touch ID until it expires" : "No session: the next command asks for Touch ID")
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(profile.profile).font(.headline)
                    Text(profile.maskedKeyId).font(.system(.caption, design: .monospaced)).foregroundStyle(.secondary)
                    if let s = profile.keyStatus, s != "Active" {
                        Text(s).font(.caption2.bold()).foregroundStyle(.white).padding(.horizontal, 4)
                            .background(Capsule().fill(.red))
                    }
                    if profile.temporary { Text("temporary").font(.caption2).foregroundStyle(.orange) }
                }
                Text(sessionLine).font(.caption)
                Text(usedLine).font(.caption).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                if let arn = profile.arn { Text(arn).font(.caption2).foregroundStyle(.tertiary).lineLimit(1).truncationMode(.middle) }
            }
            Spacer()
            Menu {
                ForEach(Action.allCases, id: \.self) { a in
                    if a == .disable { Divider() }
                    Button { model.perform(a, on: profile.profile) } label: { Label(a.title, systemImage: a.symbol) }
                        .disabled(profile.temporary && [.rotate, .revoke, .disable, .delete].contains(a))
                }
            } label: {
                Image(systemName: "ellipsis.circle")
            }
            .menuStyle(.borderlessButton)
            .fixedSize()
            .disabled(model.busy != nil)
            .help("Rotate, revoke, inspect or remove this key")
        }
        .padding(8)
        .background(RoundedRectangle(cornerRadius: 6).fill(Color.primary.opacity(0.05)))
    }

    var sessionLine: String {
        if let exp = profile.sessionExpiresAt, exp > Date() {
            return "Session until \(exp.formatted(date: .omitted, time: .shortened)) (\(exp.formatted(.relative(presentation: .named))))"
        }
        if let r = profile.rotatedAt { return "No session · key rotated \(r.formatted(.relative(presentation: .named)))" }
        return "No session · next use asks for Touch ID"
    }

    var usedLine: String {
        guard let used = profile.lastUsedAt else { return "Not used since it was moved here" }
        return "Used \(used.formatted(.relative(presentation: .named)))" + (profile.lastRequester.map { " by \($0)" } ?? "")
    }
}

struct AuditView: View {
    @EnvironmentObject var model: Model

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                chainStatus
                Spacer()
                Toggle("Hide routine use", isOn: $model.hideRoutine).toggleStyle(.checkbox).font(.caption)
                    .help("Hide “session used” entries: one is written every time a command reuses a cached session")
            }
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 4) {
                    ForEach(model.visibleAudit) { AuditRow(entry: $0) }
                }
            }
            .frame(height: 340)
            HStack {
                Button("Verify chain") { model.verify() }.controlSize(.small)
                    .help("Recompute every entry's hash and compare the newest with the sealed copy in the vault")
                Button("Show log file") { model.revealLog() }.controlSize(.small)
                Spacer()
            }
        }
    }

    @ViewBuilder var chainStatus: some View {
        if let v = model.verification {
            Label(v.intact ? "Chain intact · \(v.entries) entries" : "Chain broken: \(v.problem ?? "?")",
                  systemImage: v.intact ? "checkmark.seal.fill" : "xmark.seal.fill")
                .font(.caption)
                .foregroundStyle(v.intact ? .green : .red)
        } else {
            Label("Checking chain…", systemImage: "seal").font(.caption).foregroundStyle(.secondary)
        }
    }
}

struct AuditRow: View {
    let entry: AuditEntry

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: symbol).foregroundStyle(entry.ok ? Color.accentColor : .red).frame(width: 16)
            VStack(alignment: .leading, spacing: 1) {
                HStack {
                    Text(title).font(.caption.bold())
                    if let p = entry.profile { Text(p).font(.caption).foregroundStyle(.secondary) }
                    Spacer()
                    Text(entry.date.map { $0.formatted(date: .abbreviated, time: .standard) } ?? entry.ts)
                        .font(.caption2).foregroundStyle(.secondary)
                }
                if let r = entry.requester {
                    Text("← \(r)").font(.caption2).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                }
                if !detail.isEmpty { Text(detail).font(.caption2).foregroundStyle(.tertiary).lineLimit(2) }
            }
        }
        .padding(.vertical, 2)
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
            "key.restored": "Key written back to file", "session.issued": "Session issued (Touch ID)",
            "session.served": "Session used", "session.failed": "Session request failed", "sessions.revoked": "All sessions revoked",
            "sessions.cleared": "Cached sessions cleared", "auth.denied": "Touch ID declined", "settings.duration": "Session length changed",
            "zsp.installed": "Installed", "zsp.uninstalled": "Uninstalled",
        ][entry.event] ?? entry.event
    }

    var symbol: String {
        switch entry.event {
        case "key.imported", "key.added": return "tray.and.arrow.down"
        case "session.issued": return "touchid"
        case "session.served": return "arrow.right.circle"
        case "key.rotated", "key.created": return "arrow.triangle.2.circlepath"
        case "sessions.revoked": return "xmark.shield"
        case "auth.denied", "session.failed", "key.rotate.failed": return "exclamationmark.triangle"
        case "key.deleted", "key.forgotten": return "trash"
        default: return "circle"
        }
    }
}

struct InspectView: View {
    @EnvironmentObject var model: Model
    let report: InspectReport

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text("“\(report.profile)” in AWS").font(.caption.bold())
                Spacer()
                Button { model.inspect = nil } label: { Image(systemName: "xmark") }.buttonStyle(.borderless)
            }
            Text(report.identity.arn).font(.caption2).textSelection(.enabled)
            ForEach(report.keys, id: \.accessKeyId) { k in
                let used = k.lastUsed?.lastUsedDate.map {
                    "last used \($0.formatted(date: .abbreviated, time: .shortened)) · \(k.lastUsed?.serviceName ?? "?") · \(k.lastUsed?.region ?? "?")"
                } ?? "never used"
                Text("\(maskKeyId(k.accessKeyId)) \(k.status)\(k.thisProfile ? " (this profile)" : "") · \(used)")
                    .font(.system(.caption2, design: .monospaced))
                    .foregroundStyle(k.thisProfile ? .primary : .secondary)
            }
            Text("A last use you don't recognise means someone else has the key: rotate it, then revoke sessions.")
                .font(.caption2).foregroundStyle(.secondary)
        }
        .padding(8)
        .background(RoundedRectangle(cornerRadius: 6).fill(Color.blue.opacity(0.08)))
    }
}
