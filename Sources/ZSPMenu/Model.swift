import AppKit
import CoreImage
import SwiftUI
import UserNotifications
import ZSPCore

/// One line of `aws-cli-zsp doctor`.
struct CheckResult: Decodable, Identifiable, Equatable {
    let name: String
    let ok: Bool
    let detail: String
    let warn: Bool
    var id: String { name }
}

enum Page: Equatable { case main, setup, about }

struct Banner: Equatable {
    var text: String
    var isError: Bool
}

/// What a profile's menu can do. Every action but clearing the local session needs Touch ID,
/// which zsp asks for itself.
enum Action: CaseIterable {
    case inspect, clearSession, rotate, revoke, disable, delete, forget
    /// The three steps to MFA enforced by AWS and approval from your phone, in order.
    case mfaSetup, mfaEnforce, remoteEnable, remoteDisable
    /// Undoing them: enforcement alone, or everything including this Mac's MFA device.
    case mfaUnenforce, mfaRemove
    /// A client's key: hide rotate, revoke and MFA, or offer them again.
    case markReadOnly, markAuto

    /// What the ⋯ menu lists; the MFA steps have their own buttons on the row.
    static let keyMenu: [Action] = [.inspect, .clearSession, .rotate, .revoke, .disable, .delete, .forget]

    var title: String {
        switch self {
        case .inspect: return "Check last use in AWS"
        case .clearSession: return "Clear cached session"
        case .rotate: return "Rotate key…"
        case .revoke: return "Revoke all sessions…"
        case .disable: return "Deactivate key…"
        case .delete: return "Delete key…"
        case .forget: return "Remove from this Mac…"
        case .mfaSetup: return "Set up MFA…"
        case .mfaEnforce: return "Require MFA…"
        case .remoteEnable: return "Allow phone approval…"
        case .remoteDisable: return "Turn off phone approval…"
        case .mfaUnenforce: return "Stop requiring MFA…"
        case .mfaRemove: return "Remove MFA…"
        case .markReadOnly: return "Mark read-only (client's key)…"
        case .markAuto: return "Offer IAM changes again"
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
        case .mfaSetup: return "lock.iphone"
        case .mfaEnforce: return "checkmark.shield"
        case .remoteEnable: return "iphone.radiowaves.left.and.right"
        case .remoteDisable: return "iphone.slash"
        case .mfaUnenforce: return "shield.slash"
        case .mfaRemove: return "lock.open"
        case .markReadOnly: return "eye"
        case .markAuto: return "arrow.uturn.backward"
        }
    }

    /// The explanation shown before anything happens: what it does, and what it breaks.
    func explain(_ p: String) -> String? {
        switch self {
        case .inspect, .clearSession, .markAuto: return nil
        case .markReadOnly:
            return "For a key a client gave you with read-only IAM access: rotate, revoke, deactivate, delete and MFA are no longer offered for “\(p)”, so nothing fails after a Touch ID.\n\nSessions work exactly as before. Nothing changes in AWS. Undo from the same menu."
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
        case .mfaSetup:
            return "Step 1 of 3. Adds this Mac as a virtual MFA device for the IAM user behind “\(p)”, and seals its secret with the key in the vault.\n\nFrom then on every session carries MFA, still with one Touch ID. Nothing else changes yet. The IAM user needs iam:CreateVirtualMFADevice and iam:EnableMFADevice on itself. Touch ID is asked first."
        case .mfaEnforce:
            return "Step 2 of 3. Attaches a policy (aws-cli-zsp-require-mfa) to the IAM user: AWS then refuses everything the key does without MFA, so a copy of the key alone is worthless.\n\nAnything that uses this key directly rather than through AWS CLI: ZSP (CI, another machine, a script with the key in it) stops working. To undo, delete that inline policy in the IAM console. Touch ID is asked first."
        case .remoteEnable:
            return "Step 3 of 3, with a phone that is already an MFA device on this IAM user (added in the IAM console). Lets a 6-digit code from it approve a session when nobody is at the Mac, for example while you drive Claude Code with Remote Control: Claude asks you for the code.\n\nA copy of the key without this Mac's MFA secret is kept for it, which AWS refuses without your phone's code. Touch ID is asked first."
        case .remoteDisable:
            return "Deletes the copy of the key kept for phone approval. Away from the Mac, AWS commands for “\(p)” then wait until you are back at it.\n\nNothing changes in AWS: MFA stays required."
        case .mfaUnenforce:
            return "Undoes step 2: removes the aws-cli-zsp-require-mfa policy, so AWS accepts the “\(p)” key without MFA again, everywhere. Phone approval is turned off with it.\n\nUse this if something that needs the key stopped working. This Mac stays an MFA device, so step 2 can be turned on again in one click. Touch ID is asked first."
        case .mfaRemove:
            return "Undoes all three steps: turns off phone approval and MFA enforcement, then deactivates and deletes this Mac's MFA device in AWS. Sessions are plain Touch ID ones again.\n\nA phone device you added stays in IAM (delete it in the IAM console if you no longer want it). Touch ID is asked first."
        }
    }

    var destructive: Bool { [.disable, .delete, .forget, .mfaEnforce, .mfaRemove].contains(self) }

    func args(_ p: String) -> [String] {
        switch self {
        case .inspect: return ["inspect", "--profile", p]
        case .clearSession: return ["clear-sessions", "--profile", p]
        case .rotate: return ["rotate", "--profile", p, "--yes"]
        case .revoke: return ["revoke-sessions", "--profile", p, "--yes"]
        case .disable: return ["disable-key", "--profile", p, "--yes"]
        case .delete: return ["delete-key", "--profile", p, "--yes"]
        case .forget: return ["forget", "--profile", p, "--yes"]
        case .mfaSetup: return ["mfa", "setup", "--profile", p]
        case .mfaEnforce: return ["mfa", "enforce", "--profile", p, "--yes"]
        case .remoteEnable: return ["remote", "enable", "--profile", p]
        case .remoteDisable: return ["remote", "disable", "--profile", p]
        case .mfaUnenforce: return ["mfa", "unenforce", "--profile", p]
        case .mfaRemove: return ["mfa", "remove", "--profile", p, "--yes"]
        case .markReadOnly: return ["access", "--profile", p, "read-only"]
        case .markAuto: return ["access", "--profile", p, "auto"]
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
    @Published var tab = Tab.overview
    @Published var page = Page.main
    @Published var checks: [CheckResult] = []
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
        if !exposed.isEmpty || verification?.intact == false { return "exclamationmark.shield.fill" }
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
        settings = Settings.load(paths)
        if initial && needsSetup { page = .setup }
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
        call(args, label: label, as: T.self, banner: true) { r, _ in then(r) }
    }

    /// With `banner: false` the caller shows the outcome itself; `then` gets the error text on failure.
    func call<T: Decodable>(_ args: [String], label: String, as: T.Type, banner: Bool, then: @escaping (T?, String?) -> String?) {
        busy = label
        self.banner = nil
        let path = cliPath
        Task.detached {
            let r = Self.exec(path, args + ["--json"])
            let env = Self.decode(Envelope<T>.self, r.out)
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
        let path = cliPath
        if report { busy = "Verifying the audit chain…"; banner = nil }
        Task.detached {
            let r = Self.exec(path, ["audit", "--verify", "--json"])
            let env = Self.decode(Envelope<AuditVerification>.self, r.out)
            await MainActor.run {
                self.verification = env?.result
                guard report else { return }
                self.busy = nil
                if let v = env?.result {
                    let checked = Date().formatted(date: .omitted, time: .standard)
                    self.banner = v.intact
                        ? Banner(text: "Audit chain verified at \(checked): all \(v.entries) entries hash-link, and the newest matches the copy sealed in the vault\(v.anchored == false ? " (no sealed copy yet)" : "").", isError: false)
                        : Banner(text: "Audit chain broken: \(v.problem ?? "an entry was changed or removed").", isError: true)
                } else {
                    self.banner = Banner(text: env?.error ?? "aws-cli-zsp audit --verify did not run", isError: true)
                }
            }
        }
    }

    // MARK: Checks and tests

    func runChecks() {
        checking = true
        let path = cliPath
        Task.detached {
            let r = Self.exec(path, ["doctor", "--json"])
            let env = Self.decode(Envelope<[CheckResult]>.self, r.out)
            await MainActor.run {
                self.checking = false
                self.checks = env?.result ?? [CheckResult(name: "aws-cli-zsp doctor", ok: false, detail: r.err.isEmpty ? "did not run" : r.err, warn: false)]
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
        call(["check-touch-id"], label: "Waiting for Touch ID…", as: Ignored.self) { _ in "Touch ID works for AWS CLI: ZSP." }
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
            call(action.args(profile), label: "\(action.title.replacingOccurrences(of: "…", with: ""))…", as: Ignored.self) { _ in
                "\(action.title.replacingOccurrences(of: "…", with: "")): done for \(profile)."
            }
        }
    }

    /// Approval by phone code from the panel: the same as `aws-cli-zsp approve`, for when Touch
    /// ID is not an option (a broken sensor, a closed lid on a monitor without Touch ID).
    func approveWithCode(_ profile: String) {
        NSApp.activate(ignoringOtherApps: true)
        let a = NSAlert()
        a.messageText = "Approve “\(profile)” with a code"
        a.informativeText = "Type the 6-digit code from your phone's authenticator app. AWS checks it and issues a session; no Touch ID."
        let field = NSTextField(frame: NSRect(x: 0, y: 0, width: 120, height: 24))
        field.placeholderString = "123456"
        a.accessoryView = field
        a.window.initialFirstResponder = field
        a.addButton(withTitle: "Approve")
        a.addButton(withTitle: "Cancel")
        guard a.runModal() == .alertFirstButtonReturn else { return }
        let code = field.stringValue.filter(\.isNumber)
        call(["approve", "--profile", profile, code], label: "Asking AWS…", as: Ignored.self) { _ in
            "Approved: “\(profile)” has a session."
        }
    }

    /// Step 3 without the IAM console: AWS creates a device, the phone scans its QR code, and
    /// two codes from the phone enable it and turn on approval by code. Cancel deletes it again.
    func addPhone(_ profile: String) {
        guard confirm("Add your phone for “\(profile)”?",
                      "Step 3 of 3. Creates an MFA device in AWS for your phone and shows its QR code. Scan it with Google Authenticator, Microsoft Authenticator, 1Password or any authenticator app, then type two codes in a row.\n\nAfter that, when nobody is at the Mac (Claude Code over Remote Control), a code from your phone approves a session. AWS has no push approval for IAM keys: you read the code and send it. Touch ID is asked first, and again to confirm.",
                      button: "Continue", destructive: false) else { return }
        call(["mfa", "add-phone", "--profile", profile], label: "Creating the MFA device…", as: Vault.PhoneDevice.self) { [weak self] d in
            guard let d, let self else { return nil }
            DispatchQueue.main.async { self.askForPhoneCodes(profile, d) }
            return nil
        }
    }

    func askForPhoneCodes(_ profile: String, _ d: Vault.PhoneDevice, retry: String? = nil) {
        NSApp.activate(ignoringOtherApps: true)
        let (a, first, second) = Self.phoneAlert(d, retry: retry)
        guard a.runModal() == .alertFirstButtonReturn else {
            call(["mfa", "cancel-phone", "--profile", profile, "--serial", d.serial], label: "Removing the unused device…", as: Ignored.self) { _ in
                "Cancelled: the phone device was deleted from AWS again."
            }
            return
        }
        let c1 = first.stringValue.filter(\.isNumber), c2 = second.stringValue.filter(\.isNumber)
        call(["mfa", "confirm-phone", "--profile", profile, "--serial", d.serial, c1, c2], label: "Enabling your phone…", as: Ignored.self, banner: false) { [weak self] r, error in
            guard let self else { return nil }
            if r != nil {
                self.banner = Banner(text: "Your phone is set up for “\(profile)”. Away from the Mac, Claude asks you for a code from it.", isError: false)
            } else {
                DispatchQueue.main.async { self.askForPhoneCodes(profile, d, retry: "That did not work: \(error ?? "AWS refused the codes"). Try two fresh codes.") }
            }
            return nil
        }
    }

    /// The QR code and two code fields; separate so `--snapshot --qr` can draw it.
    static func phoneAlert(_ d: Vault.PhoneDevice, retry: String?) -> (NSAlert, NSTextField, NSTextField) {
        let a = NSAlert()
        a.messageText = "Scan this with your authenticator app"
        a.informativeText = (retry.map { "\($0)\n\n" } ?? "")
            + "Then type the code it shows, wait for the next one, and type that too.\n\nCan't scan? Add a key by hand with this secret:\n\(d.seed)"
        let qr = NSImageView(image: Self.qrCode(d.uri) ?? NSImage())
        qr.frame = NSRect(x: 0, y: 64, width: 220, height: 220)
        let first = NSTextField(frame: NSRect(x: 0, y: 32, width: 220, height: 24))
        first.placeholderString = "First code"
        let second = NSTextField(frame: NSRect(x: 0, y: 0, width: 220, height: 24))
        second.placeholderString = "Next code"
        let box = NSView(frame: NSRect(x: 0, y: 0, width: 220, height: 284))
        [qr, first, second].forEach(box.addSubview)
        a.accessoryView = box
        a.window.initialFirstResponder = first
        a.addButton(withTitle: "Enable")
        a.addButton(withTitle: "Cancel")
        return (a, first, second)
    }

    static func qrCode(_ text: String) -> NSImage? {
        guard let f = CIFilter(name: "CIQRCodeGenerator") else { return nil }
        f.setValue(Data(text.utf8), forKey: "inputMessage")
        f.setValue("M", forKey: "inputCorrectionLevel")
        guard let out = f.outputImage?.transformed(by: CGAffineTransform(scaleX: 8, y: 8)) else { return nil }
        let rep = NSCIImageRep(ciImage: out)
        let image = NSImage(size: rep.size)
        image.addRepresentation(rep)
        return image
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
