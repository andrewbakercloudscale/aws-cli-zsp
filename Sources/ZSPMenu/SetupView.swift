import AppKit
import SwiftUI
import ZSPCore

/// The first run, and any run after: what is in ~/.aws, which keys move into the vault, which
/// stay, whether new keys move automatically, and how long sessions last. Nothing moves until
/// you press the button.
struct SetupView: View {
    @EnvironmentObject var model: Model
    @State private var selected: Set<String> = []
    @State private var autoMove = true
    @State private var seconds = 3600
    @State private var loaded = false

    /// One row per profile found in plain text, config and credentials merged.
    var found: [Finding] {
        var seen: Set<String> = []
        return model.findings.filter { seen.insert($0.profile).inserted }
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                intro
                analysis
                options
                if !phoneKeys.isEmpty { phone }
                HStack {
                    Spacer()
                    Button {
                        let keep = found.map(\.profile).filter { !selected.contains($0) }
                        model.finishSetup(move: selected.sorted(), keep: keep, autoMove: autoMove, seconds: seconds)
                    } label: {
                        Label(selected.isEmpty ? "Save settings" : "Move \(selected.count) key\(selected.count == 1 ? "" : "s") and finish",
                              systemImage: "lock.fill")
                    }
                    .buttonStyle(.pill(Theme.violet, filled: true))
                    .disabled(model.busy != nil)
                }
            }
        }
        .frame(maxHeight: 600)
        .onAppear(perform: load)
    }

    func load() {
        guard !loaded else { return }
        loaded = true
        let s = model.settings
        selected = Set(found.map(\.profile)).subtracting(s.kept)
        autoMove = s.autoImport != false
        seconds = s.sessionSeconds
    }

    var intro: some View {
        HStack(spacing: 16) {
            Image(systemName: "wand.and.stars").font(.system(size: 34, weight: .semibold))
            VStack(alignment: .leading, spacing: 4) {
                Text("Set up AWS CLI: ZSP").font(.title2.weight(.bold))
                Text("Your AWS keys move out of ~/.aws into a vault sealed by this Mac's Secure Enclave. The AWS CLI keeps working: it asks for Touch ID and gets a short session instead of the key.")
                    .font(.callout).opacity(0.9).fixedSize(horizontal: false, vertical: true)
            }
        }
        .foregroundStyle(.white)
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(18)
        .background(RoundedRectangle(cornerRadius: 18, style: .continuous)
            .fill(LinearGradient(colors: [Color(hex: "#7c3aed"), Color(hex: "#4f46e5")], startPoint: .topLeading, endPoint: .bottomTrailing)))
    }

    var analysis: some View {
        Card(title: "1. What is in ~/.aws", symbol: "doc.text.magnifyingglass", tint: Theme.info,
             trailing: AnyView(Text("\(found.count) found").font(.callout.weight(.semibold)).foregroundStyle(.secondary))) {
            if found.isEmpty {
                Label(model.profiles.isEmpty ? "No access keys in ~/.aws/credentials or ~/.aws/config." : "No plaintext keys: \(model.profiles.count) already in the vault.",
                      systemImage: "checkmark.circle.fill").font(.callout).foregroundStyle(Theme.safe)
            } else {
                Text("Tick the keys to move into the vault. Unticked keys stay in plain text and are never moved automatically.")
                    .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                ForEach(found, id: \.profile) { f in
                    Toggle(isOn: Binding(get: { selected.contains(f.profile) }, set: { on in
                        if on { selected.insert(f.profile) } else { selected.remove(f.profile) }
                    })) {
                        HStack(spacing: 10) {
                            SymbolTile(symbol: "key.fill", color: selected.contains(f.profile) ? Theme.violet : Theme.slate, size: 26)
                            Text(f.profile).font(.callout.weight(.semibold))
                            Text(maskKeyId(f.accessKeyId)).font(.system(.caption, design: .monospaced)).foregroundStyle(.secondary)
                            if !f.complete { Pill(text: "half written", color: Theme.warn) }
                            Spacer()
                            Text((f.file as NSString).lastPathComponent).font(.caption).foregroundStyle(.secondary)
                        }
                    }
                    .toggleStyle(.checkbox)
                }
                HStack(spacing: 8) {
                    Button("Select all") { selected = Set(found.map(\.profile)) }.buttonStyle(.pill(Theme.info))
                    Button("Select none") { selected = [] }.buttonStyle(.pill(Theme.slate))
                }
            }
            if !model.profiles.isEmpty {
                Text("Already in the vault: \(model.profiles.map(\.profile).joined(separator: ", "))").font(.caption).foregroundStyle(.secondary)
            }
        }
    }

    var options: some View {
        Card(title: "2. From now on", symbol: "gearshape.fill", tint: Theme.accent) {
            Toggle(isOn: $autoMove) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Move new keys automatically").font(.callout.weight(.semibold))
                    Text("When `aws configure`, a paste or a script writes a key to ~/.aws, it is moved into the vault within seconds. Off: it stays until you move it, and the menu bar turns red.")
                        .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                }
            }
            .toggleStyle(.switch)
            Divider()
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Session length").font(.callout.weight(.semibold))
                    Text("How long one Touch ID lasts before the next command asks again.").font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                Picker("", selection: $seconds) {
                    Text("15 minutes").tag(900)
                    Text("1 hour").tag(3600)
                    Text("4 hours").tag(14_400)
                    Text("8 hours").tag(28_800)
                    Text("12 hours").tag(43_200)
                }
                .labelsHidden().frame(width: 130)
            }
        }
    }

    /// The vault's long-lived keys whose IAM user may have MFA: the ones phone approval can cover.
    var phoneKeys: [ProfileMeta] { model.profiles.filter { !$0.temporary && !($0.cannot(.mfa) && $0.mfaSerial == nil) } }

    var phone: some View {
        let done = phoneKeys.filter { $0.remoteSerial != nil }.count
        return Card(title: "3. Phone approval, per key", symbol: "iphone.radiowaves.left.and.right", tint: Theme.violet,
                    trailing: AnyView(Text("\(done) of \(phoneKeys.count) on").font(.callout.weight(.semibold)).foregroundStyle(.secondary))) {
            Text("Lets a 6-digit code from your phone approve a session when nobody is at the Mac (aws-cli-zsp remote enable). Each key gets there in three steps: MFA on this Mac, AWS requires MFA, then your phone. The button shows the next one; each asks for Touch ID.")
                .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            ForEach(phoneKeys) { PhoneSetupRow(profile: $0) }
            Text("Each step can be undone on the MFA & phone tab.").font(.caption).foregroundStyle(.secondary)
        }
        .disabled(model.busy != nil)
    }
}

/// One key's way to phone approval: where it is, and the next step as a button.
struct PhoneSetupRow: View {
    @EnvironmentObject var model: Model
    let profile: ProfileMeta

    /// The next of the three steps, nil once phone approval is on.
    var next: Action? {
        if profile.mfaSerial == nil { return .mfaSetup }
        if profile.mfaEnforced != true { return .mfaEnforce }
        return profile.remoteSerial == nil ? .remoteEnable : nil
    }

    var stepsDone: Int { [profile.mfaSerial != nil, profile.mfaEnforced == true, profile.remoteSerial != nil].filter { $0 }.count }

    var body: some View {
        HStack(spacing: 10) {
            SymbolTile(symbol: "key.fill", color: next == nil ? Theme.safe : Theme.violet, size: 26)
            Text(profile.profile).font(.callout.weight(.semibold))
            Text("\(stepsDone) of 3").font(.caption).foregroundStyle(.secondary)
            Spacer()
            if next != nil {
                Button("Guide…") { model.page = .phoneGuide(profile.profile) }.buttonStyle(.link).font(.caption)
                    .help("Step by step: what each step does and what it needs")
            }
            switch next {
            case nil:
                Label("Phone approval on", systemImage: "checkmark.circle.fill").font(.callout).foregroundStyle(Theme.safe)
            case .remoteEnable:
                Button("Phone already in IAM…") { model.perform(.remoteEnable, on: profile.profile) }.buttonStyle(.link).font(.caption)
                Button { model.addPhone(profile.profile) } label: { Text("Add phone…") }
                    .buttonStyle(.pill(Theme.violet, filled: true))
                    .help("Shows a QR code for Google Authenticator or any authenticator app")
            case let step?:
                Button { model.perform(step, on: profile.profile) } label: { Text(step.title) }
                    .buttonStyle(.pill(Theme.violet, filled: true))
                    .help(step.explain(profile.profile) ?? "")
            }
        }
    }
}

/// Who made it, what it does, and where it lives.
struct AboutView: View {
    static let repo = URL(string: "https://github.com/andrewbakercloudscale/aws-cli-zsp")!
    static let issues = URL(string: "https://github.com/andrewbakercloudscale/aws-cli-zsp/issues")!
    static let licence = URL(string: "https://github.com/andrewbakercloudscale/aws-cli-zsp/blob/main/LICENSE")!
    static let linkedIn = URL(string: "https://www.linkedin.com/in/andrew-baker-ninja/")!
    static let blog = URL(string: "https://andrewbaker.ninja/")!
    static let cloudScale = URL(string: "https://cloudscale.consulting/")!

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 16) {
                    Image(nsImage: NSApp.applicationIconImage).resizable().frame(width: 80, height: 80)
                    VStack(alignment: .leading, spacing: 4) {
                        Text("AWS CLI: ZSP").font(.largeTitle.weight(.bold))
                        Text("Version \(Model.appVersion)").font(.title3.weight(.medium)).monospacedDigit()
                        Text("Zero Standing Permissions for AWS on macOS: no plaintext keys in ~/.aws, Touch ID before a key is used, and sessions that end on their own.")
                            .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                    }
                }
                Card(title: "How it protects you", symbol: "lock.shield.fill", tint: Theme.safe) {
                    bullet("lock.fill", "Keys are sealed by the Secure Enclave: useless on any other Mac, and unsealed only after Touch ID.")
                    bullet("arrow.down.doc.fill", "Keys written to ~/.aws are moved into the vault within seconds (if you leave that on).")
                    bullet("clock.fill", "The AWS CLI gets a session that expires (1 hour by default), never the key itself.")
                    bullet("checkmark.shield.fill", "Optionally, AWS itself refuses the key without MFA, and your phone approves when you are away.")
                    bullet("list.bullet.clipboard.fill", "Every use is in a hash-chained audit trail, with the program that asked.")
                }
                Card(title: "Made by", symbol: "person.fill", tint: Theme.info) {
                    Text("Andrew Baker, CloudScale Consulting").font(.callout.weight(.semibold))
                    HStack(spacing: 8) {
                        link("LinkedIn", "person.crop.square", Self.linkedIn, Theme.info)
                        link("Blog", "text.book.closed", Self.blog, Theme.violet)
                        link("CloudScale", "cloud", Self.cloudScale, Theme.teal)
                    }
                }
                Card(title: "Project", symbol: "chevron.left.forwardslash.chevron.right", tint: Theme.accent) {
                    HStack(spacing: 8) {
                        link("Source on GitHub", "arrow.up.right.square", Self.repo, Theme.accent)
                        link("Report an issue", "exclamationmark.bubble", Self.issues, Theme.danger)
                        link("MIT licence", "doc.text", Self.licence, Theme.slate)
                    }
                    Text("Built from scratch on the ideas behind aws-vault (ByteNess). Free and open source: use it, change it, share it.")
                        .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                }
                Text("Copyright © 2026 Andrew Baker.").font(.caption).foregroundStyle(.secondary)
            }
        }
        .frame(maxHeight: 600)
    }

    func bullet(_ symbol: String, _ text: String) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: symbol).foregroundStyle(Theme.safe).frame(width: 18)
            Text(text).font(.callout).fixedSize(horizontal: false, vertical: true)
        }
    }

    func link(_ title: String, _ symbol: String, _ url: URL, _ color: Color) -> some View {
        Button { NSWorkspace.shared.open(url) } label: { Label(title, systemImage: symbol) }.buttonStyle(.pill(color))
    }
}
