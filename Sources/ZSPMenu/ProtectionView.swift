import AppKit
import SwiftUI
import ZSPCore

struct ProtectionView: View {
    @EnvironmentObject var model: Model

    var body: some View {
        VStack(spacing: 10) {
            Card(title: "Make AWS itself demand MFA", symbol: "lock.iphone", tint: Theme.violet) {
                Text("Touch ID protects the key on this Mac, but AWS doesn't know about it. Three steps per key: this Mac becomes an MFA device (still one Touch ID), AWS refuses the key without MFA, and a code from your phone approves a session when you are away from the Mac, for example while driving Claude Code with Remote Control.")
                    .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            ForEach(model.profiles.filter { !$0.temporary }) { p in
                if p.cannot(.mfa) && p.mfaSerial == nil { ReadOnlyMFACard(profile: p) } else { MFACard(profile: p) }
            }
        }
    }
}

/// A client's key whose IAM user may not add MFA devices: nothing to set up, and why.
struct ReadOnlyMFACard: View {
    let profile: ProfileMeta

    var body: some View {
        Card(title: profile.profile, symbol: "eye", tint: Theme.slate,
             trailing: AnyView(Text(profile.access == .readOnly ? "read-only" : "IAM refuses").font(.callout.weight(.semibold)).foregroundStyle(.secondary))) {
            Text("This IAM user is managed by its account's owner and may not add MFA devices, so AWS-side MFA is up to them. Touch ID still guards the key on this Mac, and sessions work as normal.")
                .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
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
