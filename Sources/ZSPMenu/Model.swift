import AppKit
import CoreImage
import SwiftUI
import UserNotifications
import ZSPCore

enum Page: Equatable {
    case main, setup, about
    /// The step-by-step guide to phone approval, for one key.
    case phoneGuide(String)
}

struct Banner: Equatable {
    var text: String
    var isError: Bool
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
    @Published var tab = Tab.overview
    @Published var page = Page.main
    @Published var checks: [Check] = []
    /// Warnings and errors from the support log the user has not dismissed.
    @Published var problems: [LogLine] = []
    @Published var checking = false
    @Published var settings = Settings()
    /// Last test result per profile: what AWS said, or why it failed.
    @Published var tests: [String: Banner] = [:]

    static var appVersion: String { Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "dev" }

    var exposed: [Finding] { findings.filter { !settings.kept.contains($0.profile) } }
    var keptPlaintext: [Finding] { findings.filter { settings.kept.contains($0.profile) } }
    var needsSetup: Bool { settings.onboarded != true && profiles.isEmpty }
    @Published var hideRoutine = true

    let paths = Paths.standard()
    private var timer: Timer?
    /// When the support log last changed, so it is re-read only then.
    var logModified: Date?
    private var lastSeq = 0
    /// A refresh reading files off the main thread, so the timer does not stack them up.
    private var refreshing = false
    /// The verify waiting for a burst of new audit entries (a script's loop) to settle.
    private var pendingVerify: Task<Void, Never>?
    private let canNotify = Bundle.main.bundleIdentifier != nil

    var statusSymbol: String {
        if busy != nil { return "hourglass" }
        if !exposed.isEmpty || verification?.intact == false { return "exclamationmark.shield.fill" }
        return "lock.shield"
    }

    init() {
        Log.configure(paths, process: "menu")
        refresh(initial: true)
        timer = Timer.scheduledTimer(withTimeInterval: 3, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.refresh() }
        }
        if canNotify { UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { _, _ in } }
        verify()
    }

    /// What refresh reads, gathered off the main thread: the audit file can be megabytes.
    struct Snapshot: Sendable {
        var profiles: [ProfileMeta]
        var findings: [Finding]
        var settings: ZSPCore.Settings
        var entries: [AuditEntry]
    }

    nonisolated static func snapshot(_ paths: Paths) -> Snapshot {
        Snapshot(profiles: Vault.statuses(meta: MetadataStore(paths: paths).all(), keychain: nil),
                 findings: Scanner.scan(paths), settings: Settings.load(paths),
                 entries: AuditLog(paths: paths, anchor: nil).entries(limit: 300))
    }

    func refresh(initial: Bool = false) {
        if initial {
            apply(Self.snapshot(paths), initial: true)
            return
        }
        guard !refreshing else { return }
        refreshing = true
        let paths = paths
        Task.detached {
            let snap = Self.snapshot(paths)
            await MainActor.run {
                self.refreshing = false
                self.apply(snap, initial: false)
            }
        }
    }

    func apply(_ snap: Snapshot, initial: Bool) {
        profiles = snap.profiles
        findings = snap.findings
        settings = snap.settings
        if initial && needsSetup { page = .setup }
        let entries = snap.entries
        if !initial {
            for e in entries where e.seq > lastSeq {
                if e.kind == .keyImported { notify("Moved an AWS key into the vault", "Profile “\(e.profile ?? "?")” no longer has a plaintext key in \(e.detail["from"] ?? "~/.aws").") }
                if e.kind == .authDenied { notify("AWS key use declined", "\(e.requester ?? "Something") asked for “\(e.profile ?? "?")”.") }
            }
        }
        if let last = entries.last?.seq, last != lastSeq {
            lastSeq = last
            if !initial { verifySoon() }
        }
        audit = entries.reversed()
        loadProblems()
    }

    /// Verifies once new entries stop arriving for a few seconds: each verify re-hashes the
    /// whole log, and a script can add an entry per command.
    func verifySoon() {
        pendingVerify?.cancel()
        pendingVerify = Task { @MainActor [weak self] in
            try? await Task.sleep(nanoseconds: 5_000_000_000)
            guard !Task.isCancelled else { return }
            self?.verify()
        }
    }

    var visibleAudit: [AuditEntry] {
        hideRoutine ? audit.filter { $0.kind != .sessionServed } : audit
    }

    func notify(_ title: String, _ body: String) {
        guard canNotify else { return }
        let c = UNMutableNotificationContent()
        c.title = title
        c.body = body
        UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: UUID().uuidString, content: c, trigger: nil))
    }

    /// Runs zsp with --json off the main thread and hands back its decoded result.
    func call<T: Decodable>(_ args: [String], label: String, as: T.Type, then: @escaping (T?) -> String?) {
        call(args, label: label, as: T.self, banner: true) { r, _ in then(r) }
    }

    /// With `banner: false` the caller shows the outcome itself; `then` gets the error text on failure.
    func call<T: Decodable>(_ args: [String], label: String, as: T.Type, banner: Bool, then: @escaping (T?, String?) -> String?) {
        busy = label
        self.banner = nil
        let path = CLI.path
        Task.detached {
            let r = CLI.exec(path, args + ["--json"])
            let env = CLI.decode(CLI.Envelope<T>.self, r.out)
            await MainActor.run {
                self.busy = nil
                if let env, env.ok {
                    if let text = then(env.result, nil), banner { self.banner = Banner(text: text, isError: false) }
                } else {
                    let why = (env?.error ?? (r.err.isEmpty ? "aws-cli-zsp exited with \(r.status)" : r.err)).trimmingCharacters(in: .whitespacesAndNewlines)
                    _ = then(nil, why)
                    if banner { self.banner = Banner(text: why, isError: true) }
                }
                self.refresh()
                self.verify()
                if !self.checks.isEmpty { self.runChecks() }
            }
        }
    }

    /// `report` is for the buttons: the pill alone did not change when the chain was already
    /// intact, so a click looked like it did nothing.
    func verify(report: Bool = false) {
        let path = CLI.path
        if report { busy = "Verifying the audit chain…"; banner = nil }
        Task.detached {
            let r = CLI.exec(path, ["audit", "--verify", "--json"])
            let env = CLI.decode(CLI.Envelope<AuditVerification>.self, r.out)
            await MainActor.run {
                self.verification = env?.result
                guard report else { return }
                self.busy = nil
                if let v = env?.result {
                    let checked = Date().formatted(date: .omitted, time: .standard)
                    self.banner = v.intact
                        ? Banner(text: "Audit chain verified at \(checked): all \(v.entries) entries hash-link, and the newest matches the copy sealed in the vault\(v.anchored == nil ? " (no sealed copy to compare)" : "").", isError: false)
                        : Banner(text: "Audit chain broken: \(v.problem ?? "an entry was changed or removed").", isError: true)
                } else {
                    self.banner = Banner(text: env?.error ?? "aws-cli-zsp audit --verify did not run", isError: true)
                }
            }
        }
    }

    struct TestResult: Decodable { let arn: String; let usedCachedSession: Bool }

    func test(_ profile: String) {
        tests[profile] = nil
        call(["test", "--profile", profile], label: "Testing \(profile)…", as: TestResult.self, banner: false) { [weak self] (r: TestResult?, error: String?) -> String? in
            if let r {
                self?.tests[profile] = Banner(text: "Works: \(r.arn)\(r.usedCachedSession ? " (cached session)" : " (new session, Touch ID)")", isError: false)
            } else {
                self?.tests[profile] = Banner(text: error ?? "failed", isError: true)
            }
            return nil
        }
    }

    func testTouchID() {
        call(["check-touch-id"], label: "Waiting for Touch ID…", as: CLI.Ignored.self) { _ in "Touch ID works for AWS CLI: ZSP." }
    }

    struct WatcherResult: Decodable { let moved: Bool; let seconds: Double; let autoMove: Bool }

    func testWatcher() {
        call(["selftest-watcher"], label: "Writing a test key to ~/.aws…", as: WatcherResult.self) { r in
            guard let r else { return nil }
            if r.moved { return "Automatic move works: a test key (AWS's published example) was moved out of ~/.aws/credentials in \(String(format: "%.1f", r.seconds)) s, then removed." }
            return r.autoMove ? "The watcher did not move the test key." : "Automatic move is off, so the test key stayed where it was written (removed again)."
        }
    }

    /// The setup screen's choices, in one `aws-cli-zsp setup` call.
    func finishSetup(move: [String], keep: [String], autoMove: Bool, seconds: Int) {
        var args = ["setup", "--auto", autoMove ? "on" : "off", "--duration", "\(seconds)s"]
        if !move.isEmpty { args += ["--move", move.joined(separator: ",")] }
        if !keep.isEmpty { args += ["--keep", keep.joined(separator: ",")] }
        call(args, label: "Setting up…", as: ImportReport.self) { [weak self] r in
            self?.page = .main
            self?.tab = .overview
            let moved = r?.imported ?? []
            return moved.isEmpty ? "Set up. Nothing was moved." : "Set up. Moved \(moved.joined(separator: ", ")) into the vault."
        }
    }

    func importNow() {
        call(["import", "--profiles", exposed.map(\.profile).joined(separator: ",")], label: "Moving keys…", as: ImportReport.self) { r in
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
            call(action.args(profile), label: "\(action.title.replacingOccurrences(of: "…", with: ""))…", as: CLI.Ignored.self) { _ in
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

    func revealAuditFile() {
        NSWorkspace.shared.activateFileViewerSelecting([paths.auditFile])
    }
}
