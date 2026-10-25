import SwiftUI
import ZSPCore

/// A walk through phone approval for one key, from nothing to a tested code: what each step
/// does, what it needs, and the one button that does it. Progress comes from the key's state,
/// so the guide moves on by itself as each step finishes, and can be left and picked up again.
struct PhoneGuideView: View {
    @EnvironmentObject var model: Model
    let selected: String

    /// The keys phone approval can cover: long-lived, with an IAM user that may have MFA.
    var keys: [ProfileMeta] { model.profiles.filter { !$0.temporary && !($0.cannot(.mfa) && $0.mfaSerial == nil) } }
    var profile: ProfileMeta? { keys.first { $0.profile == selected } ?? keys.first }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                if let profile {
                    GuideHero(profile: profile, keys: keys)
                    GuideSteps(profile: profile)
                } else {
                    Card(title: "No key to set up", symbol: "key.slash", tint: Theme.slate) {
                        Text("Phone approval needs a long-lived key in the vault whose IAM user may add MFA devices. Move a key in with Setup first.")
                            .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
        }
        .frame(maxHeight: 600)
    }
}

/// Where this key is on the way: the four stages as a bar, and a key picker.
struct GuideHero: View {
    @EnvironmentObject var model: Model
    let profile: ProfileMeta
    let keys: [ProfileMeta]

    var body: some View {
        let stage = GuideStage.current(profile, model.audit)
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 14) {
                Image(systemName: "iphone.radiowaves.left.and.right").font(.system(size: 32, weight: .semibold))
                VStack(alignment: .leading, spacing: 4) {
                    Text(stage == .done ? "Phone approval is on" : "Set up phone approval").font(.title2.weight(.bold))
                    Text("Away from the Mac (Claude Code over Remote Control, a locked screen), a 6-digit code from your phone approves an AWS session instead of Touch ID.")
                        .font(.callout).opacity(0.9).fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 0)
                if keys.count > 1 {
                    Picker("", selection: Binding(get: { profile.profile }, set: { model.page = .phoneGuide($0) })) {
                        ForEach(keys) { Text($0.profile).tag($0.profile) }
                    }
                    .labelsHidden().frame(width: 140)
                }
            }
            HStack(spacing: 6) {
                ForEach(GuideStage.steps, id: \.self) { s in
                    VStack(alignment: .leading, spacing: 4) {
                        Capsule().fill(.white.opacity(s.rawValue < stage.rawValue ? 1 : s == stage ? 0.6 : 0.22)).frame(height: 5)
                        Text(s.short).font(.caption2.weight(.semibold)).opacity(s.rawValue <= stage.rawValue ? 1 : 0.6)
                    }
                }
            }
        }
        .foregroundStyle(.white)
        .padding(18)
        .background(RoundedRectangle(cornerRadius: 18, style: .continuous)
            .fill(LinearGradient(colors: stage == .done ? [Color(hex: "#16a34a"), Color(hex: "#0d9488")] : [Color(hex: "#7c3aed"), Color(hex: "#4f46e5")],
                                 startPoint: .topLeading, endPoint: .bottomTrailing)))
    }
}

/// The steps, in order. Each is derived from what the key already has.
enum GuideStage: Int, CaseIterable {
    case mac, enforce, phone, test, done

    static let steps: [GuideStage] = [.mac, .enforce, .phone, .test]

    /// `audit` tells whether a code has approved a session yet, the proof step 4 asks for.
    static func current(_ p: ProfileMeta, _ audit: [AuditEntry]) -> GuideStage {
        if p.mfaSerial == nil { return .mac }
        if p.mfaEnforced != true { return .enforce }
        if p.remoteSerial == nil { return .phone }
        let tested = audit.contains { $0.kind == .sessionIssued && $0.profile == p.profile && $0.detail["approved"] == "mfa-code" }
        return tested ? .done : .test
    }

    var short: String {
        switch self {
        case .mac: return "1 · MFA on this Mac"
        case .enforce: return "2 · AWS requires MFA"
        case .phone: return "3 · Your phone"
        case .test: return "4 · Try a code"
        case .done: return "Done"
        }
    }
}

struct GuideSteps: View {
    @EnvironmentObject var model: Model
    let profile: ProfileMeta

    var body: some View {
        let stage = GuideStage.current(profile, model.audit)
        let p = profile.profile
        VStack(alignment: .leading, spacing: 10) {
            GuideCard(n: 0, title: "Before you start", state: .info) {
                bullet("iphone", "An authenticator app on your phone: Google Authenticator, Microsoft Authenticator, 1Password, Authy or any other.")
                bullet("person.badge.key", "The IAM user behind “\(p)” may manage its own MFA: iam:CreateVirtualMFADevice, iam:EnableMFADevice, iam:ListMFADevices, iam:PutUserPolicy and iam:GetUserPolicy.")
                bullet("exclamationmark.triangle", "Step 2 makes AWS refuse this key without MFA. Anything using the key directly (CI, another machine, a script with the key in it) stops working.")
                bullet("touchid", "Every step asks for Touch ID. Each can be undone here or on the MFA & phone tab.")
            }
            GuideCard(n: 1, title: "Make this Mac an MFA device", state: state(.mac, stage),
                      detail: "AWS creates a virtual MFA device for the IAM user, and its secret is sealed with the key in the vault. Every session then carries MFA, still with one Touch ID. Nothing else changes yet.") {
                stepButtons(.mac, stage, primary: .mfaSetup, undo: .mfaRemove)
            }
            GuideCard(n: 2, title: "Make AWS require MFA", state: state(.enforce, stage),
                      detail: "Attaches the aws-cli-zsp-require-mfa policy to the IAM user, so the key alone, copied or stolen, is refused. This is what makes a copy that opens without Touch ID safe to keep for step 3.") {
                stepButtons(.enforce, stage, primary: .mfaEnforce, undo: .mfaUnenforce)
            }
            GuideCard(n: 3, title: "Add your phone", state: state(.phone, stage),
                      detail: "AWS creates a second MFA device for your phone. Scan the QR code with your authenticator app, then type the code it shows and the next one. That enables the device and turns on approval by code.") {
                if stage == .phone {
                    HStack(spacing: 8) {
                        Button { model.addPhone(p) } label: { Label("Show QR code…", systemImage: "qrcode") }
                            .buttonStyle(.pill(Theme.violet, filled: true))
                        Button("My phone is already an MFA device in IAM…") { model.perform(.remoteEnable, on: p) }
                            .buttonStyle(.link).font(.caption)
                    }
                } else if stage.rawValue > GuideStage.phone.rawValue {
                    undoLink(.remoteDisable)
                }
            }
            GuideCard(n: 4, title: "Try a code", state: state(.test, stage),
                      detail: "Type a code from your phone: AWS checks it and issues a session with no Touch ID. This is what happens when you are away.") {
                if stage.rawValue >= GuideStage.test.rawValue {
                    Button { model.approveWithCode(p) } label: { Label("Approve with a code…", systemImage: "number") }
                        .buttonStyle(.pill(Theme.info, filled: stage == .test))
                }
            }
            if stage == .done || stage == .test {
                Card(title: "When you are away", symbol: "message.fill", tint: Theme.safe) {
                    Text("An AWS command for “\(p)” with nobody at the Mac fails with what to do. Claude Code asks you for the code, then runs:")
                        .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                    HStack {
                        Text("aws-cli-zsp approve --profile \(p) 123456").font(.system(.callout, design: .monospaced)).textSelection(.enabled)
                        Spacer()
                        CopyButton(title: "Copy command", text: "aws-cli-zsp approve --profile \(p) ")
                    }
                    .padding(8)
                    .background(RoundedRectangle(cornerRadius: 8).fill(Color.primary.opacity(0.05)))
                    Text("Each code works once, and only for 30 seconds.").font(.caption).foregroundStyle(.secondary)
                }
            }
        }
        .disabled(model.busy != nil)
    }

    func state(_ step: GuideStage, _ stage: GuideStage) -> GuideState {
        step.rawValue < stage.rawValue ? .done : step == stage ? .current : .locked
    }

    @ViewBuilder
    func stepButtons(_ step: GuideStage, _ stage: GuideStage, primary: Action, undo: Action) -> some View {
        if step == stage {
            Button { model.perform(primary, on: profile.profile) } label: { Label(primary.title, systemImage: primary.symbol) }
                .buttonStyle(.pill(Theme.violet, filled: true))
        } else if step.rawValue < stage.rawValue {
            undoLink(undo)
        }
    }

    func undoLink(_ action: Action) -> some View {
        Button(action.title.replacingOccurrences(of: "…", with: "")) { model.perform(action, on: profile.profile) }
            .buttonStyle(.link).font(.caption)
            .help(action.explain(profile.profile) ?? "")
    }

    func bullet(_ symbol: String, _ text: String) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: symbol).foregroundStyle(Theme.violet).frame(width: 18)
            Text(text).font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
        }
    }
}

/// One step: a numbered badge (a tick once done), what it does, and its buttons. Steps not
/// reached yet are dimmed.
enum GuideState { case info, done, current, locked }

struct GuideCard<Content: View>: View {

    let n: Int
    let title: String
    let state: GuideState
    var detail: String?
    @ViewBuilder var content: Content

    init(n: Int, title: String, state: GuideState, detail: String? = nil, @ViewBuilder content: () -> Content) {
        self.n = n
        self.title = title
        self.state = state
        self.detail = detail
        self.content = content()
    }

    var color: Color {
        switch state {
        case .info: return Theme.info
        case .done: return Theme.safe
        case .current: return Theme.violet
        case .locked: return Theme.slate.opacity(0.5)
        }
    }

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            ZStack {
                Circle().fill(color)
                switch state {
                case .info: Image(systemName: "checklist").font(.caption.weight(.bold))
                case .done: Image(systemName: "checkmark").font(.caption.weight(.bold))
                default: Text("\(n)").font(.callout.weight(.bold))
                }
            }
            .foregroundStyle(.white).frame(width: 28, height: 28)
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    Text(title).font(.headline)
                    Spacer()
                    switch state {
                    case .done: Pill(text: "done", color: Theme.safe)
                    case .current: Pill(text: "next", color: Theme.violet)
                    case .locked: Text("after step \(n - 1)").font(.caption).foregroundStyle(.secondary)
                    case .info: EmptyView()
                    }
                }
                if let detail { Text(detail).font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true) }
                content
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .topLeading)
        .background(RoundedRectangle(cornerRadius: 14, style: .continuous).fill(Theme.cardFill))
        .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).stroke(state == .current ? Theme.violet.opacity(0.6) : Theme.cardStroke,
                                                                              lineWidth: state == .current ? 1.5 : 1))
        .opacity(state == .locked ? 0.6 : 1)
    }
}
