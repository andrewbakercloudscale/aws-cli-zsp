import AppKit
import SwiftUI
import UserNotifications
import ZSPCore

enum Tab: Hashable { case inUse, audit }

struct Banner: Equatable {
    var text: String
    var isError: Bool
}

/// What a profile's menu can do. Every action but clearing the local session needs Touch ID,
/// which zsp asks for itself.
enum Action: CaseIterable {
    case inspect, clearSession, rotate, revoke, disable, delete, forget

    var title: String {
        switch self {
        case .inspect: return "Check last use in AWS"
        case .clearSession: return "Clear cached session"
        case .rotate: return "Rotate key…"
        case .revoke: return "Revoke all sessions…"
        case .disable: return "Deactivate key…"
        case .delete: return "Delete key…"
        case .forget: return "Remove from this Mac…"
        }
    }

    var symbol: String {
        switch self {
        case .inspect: return "magnifyingglass"
        case .clearSession: return "clock.arrow.circlepath"
        case .rotate: return "arrow.triangle.2.circlepath"
        case .revoke: return "xmark.shield"
        case .disable: return "pause.circle"
        case .delete: return "trash"
        case .forget: return "minus.circle"
        }
    }

    /// The explanation shown before anything happens: what it does, and what it breaks.
    func explain(_ p: String) -> String? {
        switch self {
        case .inspect, .clearSession: return nil
        case .rotate:
            return "Creates a new access key for the IAM user behind “\(p)”, seals it in the vault, waits until AWS accepts it, then deletes the old key.\n\nAnything else still using the old key (CI, another machine) stops working. Touch ID is asked first."
        case .revoke:
            return "Attaches a deny-all policy to the IAM user that applies to every session token issued before now, on every machine, including any minted from a leaked key.\n\nThe key itself keeps working and your next command gets a fresh session. Touch ID is asked first."
        case .disable:
            return "Marks the key Inactive in AWS. Everything using it stops at once.\n\nAWS CLI: ZSP cannot turn it back on, because the key was its only way in: re-enable it in the IAM console."
        case .delete:
            return "Deletes the key in AWS, then removes it from the vault and from ~/.aws/config.\n\nThis cannot be undone."
        case .forget:
            return "Removes the key from this Mac only. AWS still has it and it keeps working wherever else it is used.\n\nIf this was your only copy of the secret, it is gone for good."
        }
    }

    var destructive: Bool { [.disable, .delete, .forget].contains(self) }

    func args(_ p: String) -> [String] {
        switch self {
        case .inspect: return ["inspect", "--profile", p]
        case .clearSession: return ["clear-sessions", "--profile", p]
        case .rotate: return ["rotate", "--profile", p, "--yes"]
        case .revoke: return ["revoke-sessions", "--profile", p, "--yes"]
        case .disable: return ["disable-key", "--profile", p, "--yes"]
        case .delete: return ["delete-key", "--profile", p, "--yes"]
        case .forget: return ["forget", "--profile", p, "--yes"]
        }
    }
}

@MainActor
final class Model: ObservableObject {
    @Published var profiles: [ProfileMeta] = []
    @Published var findings: [Finding] = []
    @Published var audit: [AuditEntry] = []
    @Published var verification: AuditVerification?
    @Published var busy: String?
    @Published var banner: Banner?
    @Published var inspect: InspectReport?
    @Published var tab = Tab.inUse
    @Published var hideRoutine = true

    let paths = Paths.standard()
    private var timer: Timer?
    private var lastSeq = 0
    private let canNotify = Bundle.main.bundleIdentifier != nil

    /// The CLI is a helper app inside this bundle, so macOS names it "AWS CLI: ZSP" in Touch ID
    /// and Keychain dialogs. It is the only thing that opens the vault.
    var cliPath: String {
        let helper = Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/aws-cli-zsp.app/Contents/MacOS/aws-cli-zsp")
        if FileManager.default.isExecutableFile(atPath: helper.path) { return helper.path }
        return Bundle.main.executableURL!.deletingLastPathComponent().appendingPathComponent("zsp").path   // swift run
    }

    var statusSymbol: String {
        if busy != nil { return "hourglass" }
        if !findings.isEmpty || verification?.intact == false { return "exclamationmark.shield.fill" }
        return "lock.shield"
    }

    init() {
        refresh(initial: true)
        timer = Timer.scheduledTimer(withTimeInterval: 3, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.refresh() }
        }
        if canNotify { UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { _, _ in } }
        verify()
    }

    func refresh(initial: Bool = false) {
        profiles = Vault.statuses(meta: MetadataStore(paths: paths).all(), keychain: nil)
        findings = Scanner.scan(paths)
        let entries = AuditLog(paths: paths, anchor: nil).entries(limit: 300)
        if !initial {
            for e in entries where e.seq > lastSeq {
                if e.event == "key.imported" { notify("Moved an AWS key into the vault", "Profile “\(e.profile ?? "?")” no longer has a plaintext key in \(e.detail["from"] ?? "~/.aws").") }
                if e.event == "auth.denied" { notify("AWS key use declined", "\(e.requester ?? "Something") asked for “\(e.profile ?? "?")”.") }
            }
        }
        if let last = entries.last?.seq, last != lastSeq {
            lastSeq = last
            if !initial { verify() }
        }
        audit = entries.reversed()
    }

    var visibleAudit: [AuditEntry] {
        hideRoutine ? audit.filter { $0.event != "session.served" } : audit
    }

    func notify(_ title: String, _ body: String) {
        guard canNotify else { return }
        let c = UNMutableNotificationContent()
        c.title = title
        c.body = body
        UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: UUID().uuidString, content: c, trigger: nil))
    }

    // MARK: Talking to zsp

    nonisolated static func exec(_ path: String, _ args: [String]) -> (status: Int32, out: Data, err: String) {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: path)
        p.arguments = args
        let out = Pipe(), err = Pipe()
        p.standardOutput = out
        p.standardError = err
        p.standardInput = FileHandle.nullDevice
        do { try p.run() } catch { return (127, Data(), "cannot run aws-cli-zsp: \(error.localizedDescription)") }
        let data = out.fileHandleForReading.readDataToEndOfFile()
        let e = String(decoding: err.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        p.waitUntilExit()
        return (p.terminationStatus, data, e)
    }

    struct Envelope<T: Decodable>: Decodable {
        let ok: Bool
        let result: T?
        let error: String?
    }

    struct Ignored: Decodable {}

    nonisolated static func decode<T: Decodable>(_ type: T.Type, _ data: Data) -> T? {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .iso8601
        return try? d.decode(type, from: data)
    }

    /// Runs zsp with --json off the main thread and hands back its decoded result.
    func call<T: Decodable>(_ args: [String], label: String, as: T.Type, then: @escaping (T?) -> String?) {
        busy = label
        banner = nil
        let path = cliPath
        Task.detached {
            let r = Self.exec(path, args + ["--json"])
            let env = Self.decode(Envelope<T>.self, r.out)
            await MainActor.run {
                self.busy = nil
                if let env, env.ok {
                    if let text = then(env.result) { self.banner = Banner(text: text, isError: false) }
                } else {
                    let why = env?.error ?? (r.err.isEmpty ? "aws-cli-zsp exited with \(r.status)" : r.err)
                    self.banner = Banner(text: why.trimmingCharacters(in: .whitespacesAndNewlines), isError: true)
                }
                self.refresh()
                self.verify()
            }
        }
    }

    func verify() {
        let path = cliPath
        Task.detached {
            let r = Self.exec(path, ["audit", "--verify", "--json"])
            let env = Self.decode(Envelope<AuditVerification>.self, r.out)
            await MainActor.run { self.verification = env?.result }
        }
    }

    func importNow() {
        call(["import"], label: "Moving keys…", as: ImportReport.self) { r in
            guard let r else { return nil }
            return r.imported.isEmpty ? "No complete key pairs to move yet." : "Moved \(r.imported.joined(separator: ", ")) into the vault."
        }
    }

    func perform(_ action: Action, on profile: String) {
        if let text = action.explain(profile), !confirm(action.title.replacingOccurrences(of: "…", with: "") + " for “\(profile)”?", text,
                                                         button: action.title.replacingOccurrences(of: "…", with: ""), destructive: action.destructive) {
            return
        }
        inspect = nil
        switch action {
        case .inspect:
            call(action.args(profile), label: "Asking AWS…", as: InspectReport.self) { [weak self] r in
                self?.inspect = r
                return nil
            }
        case .rotate:
            call(action.args(profile), label: "Rotating \(profile)…", as: RotateResult.self) { r in
                r.map { "Rotated \(profile): \(maskKeyId($0.oldKeyId)) \($0.oldKey), now using \(maskKeyId($0.newKeyId))." }
            }
        default:
            call(action.args(profile), label: "\(action.title.replacingOccurrences(of: "…", with: ""))…", as: Ignored.self) { _ in
                "\(action.title.replacingOccurrences(of: "…", with: "")): done for \(profile)."
            }
        }
    }

    func confirm(_ title: String, _ text: String, button: String, destructive: Bool) -> Bool {
        NSApp.activate(ignoringOtherApps: true)
        let a = NSAlert()
        a.messageText = title
        a.informativeText = text
        a.alertStyle = destructive ? .critical : .warning
        a.addButton(withTitle: button)
        a.addButton(withTitle: "Cancel")
        if destructive { a.buttons.first?.hasDestructiveAction = true }
        return a.runModal() == .alertFirstButtonReturn
    }

    func revealLog() {
        NSWorkspace.shared.activateFileViewerSelecting([paths.auditFile])
    }
}
