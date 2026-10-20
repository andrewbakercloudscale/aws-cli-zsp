import AppKit
import SwiftUI
import ZSPCore

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
                Button { model.revealAuditFile() } label: { Label("Show audit file", systemImage: "doc.text.magnifyingglass") }.buttonStyle(.pill(Theme.slate))
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
        entry.detail.filter { $0.key != "expires" || entry.kind != .sessionServed }
            .sorted { $0.key < $1.key }.map { "\($0.key): \($0.value)" }.joined(separator: " · ")
    }

    var title: String { entry.title }
    var symbol: String { entry.kind?.symbol ?? "circle.fill" }
    var color: Color { entry.kind?.color ?? Theme.slate }
}

/// How each event looks in the trail.
extension AuditEvent {
    var symbol: String {
        switch self {
        case .keyImported, .keyAdded: return "tray.and.arrow.down.fill"
        case .sessionIssued: return "touchid"
        case .sessionServed: return "arrow.right"
        case .keyRotated, .keyCreated: return "arrow.triangle.2.circlepath"
        case .sessionsRevoked: return "xmark.shield.fill"
        case .mfaSetup: return "lock.iphone"
        case .mfaEnforced: return "checkmark.shield.fill"
        case .remoteEnabled, .remoteDisabled, .phoneCreated, .phoneCancelled: return "iphone"
        case .mfaUnenforced: return "shield.slash"
        case .mfaRemoved: return "lock.open"
        case .sessionAway: return "moon.zzz.fill"
        case .pinSet, .pinReset: return "pin.fill"
        case .accessDenied, .accessSet: return "eye"
        case .keySwapped, .sessionSwapped: return "exclamationmark.octagon.fill"
        case .authDenied, .sessionFailed, .keyRotateFailed: return "exclamationmark.triangle.fill"
        case .keyDeleted, .keyForgotten: return "trash.fill"
        case .setupDone: return "wand.and.stars"
        case .profileTested, .watcherTested: return "play.fill"
        default: return "circle.fill"
        }
    }

    var color: Color {
        switch self {
        case .keyImported, .keyAdded, .setupDone: return Theme.info
        case .sessionIssued, .sessionServed: return Theme.safe
        case .keyRotated, .keyCreated, .pinSet, .pinReset: return Theme.accent
        case .mfaSetup, .mfaEnforced, .remoteEnabled, .remoteDisabled, .mfaUnenforced, .mfaRemoved, .phoneCreated, .phoneCancelled: return Theme.violet
        case .sessionsRevoked, .keyDeleted, .keyForgotten, .keySwapped, .sessionSwapped: return Theme.danger
        default: return Theme.slate
        }
    }
}
