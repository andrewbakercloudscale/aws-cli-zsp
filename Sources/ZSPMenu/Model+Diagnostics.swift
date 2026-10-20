import AppKit
import ZSPCore

/// Health checks with their fixes, recent problems from the support log, and the diagnostics
/// report for support.
extension Model {
    func runChecks() {
        checking = true
        let path = CLI.path
        Task.detached {
            let r = CLI.exec(path, ["doctor", "--json"])
            let env = CLI.decode(CLI.Envelope<[Check]>.self, r.out)
            await MainActor.run {
                self.checking = false
                self.checks = env?.result ?? [Check(name: "aws-cli-zsp doctor", ok: false, detail: r.err.isEmpty ? "did not run" : r.err)]
            }
        }
    }

    func apply(_ fix: Fix) {
        switch fix {
        case .install:
            call(["install"], label: "Repairing the install…", as: CLI.Ignored.self) { _ in
                "Repaired: the watcher, the login item and every profile's credential_process line point at this copy of the app."
            }
        case .moveKeys: importNow()
        case .setup: page = .setup
        }
    }

    static let dismissedKey = "problemsDismissedAt"

    /// Warnings and errors of the last week, newer than the last dismissal. Re-read only when
    /// the log file changes, since refresh runs every few seconds.
    func loadProblems(force: Bool = false) {
        let modified = (try? paths.logFile.resourceValues(forKeys: [.contentModificationDateKey]))?.contentModificationDate
        guard force || modified != logModified else { return }
        logModified = modified
        let dismissed = UserDefaults.standard.object(forKey: Self.dismissedKey) as? Date ?? .distantPast
        let since = max(dismissed, Date().addingTimeInterval(-7 * 86_400))
        problems = Log.recent(paths, limit: 500, atLeast: .warning).filter { $0.date > since }.suffix(5).reversed()
    }

    func dismissProblems() {
        UserDefaults.standard.set(Date(), forKey: Self.dismissedKey)
        loadProblems(force: true)
    }

    /// Writes the redacted report to the Desktop and shows it in Finder.
    func saveDiagnostics() {
        call(["diagnostics"], label: "Collecting diagnostics…", as: [String: String].self) { r in
            guard let file = r?["file"] else { return nil }
            NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: file)])
            return "Saved \((file as NSString).lastPathComponent) to the Desktop. Secrets are removed: attach it to a support request."
        }
    }

    func openSupportLog() {
        if FileManager.default.fileExists(atPath: paths.logFile.path) {
            NSWorkspace.shared.open(paths.logFile)
        } else {
            banner = Banner(text: "No support log yet: nothing has been logged.", isError: false)
        }
    }
}
