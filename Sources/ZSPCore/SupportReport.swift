import Foundation

/// One text file with everything support needs, and no secret: `aws-cli-zsp diagnostics`
/// writes it, the app's "Save diagnostics…" button calls that. Every line passes through
/// `Redact`; key ids are masked and account ids keep only their last four digits.
public struct SupportReport {
    public var version: String
    public var checks: [Check]
    let vault: Vault

    public init(version: String, checks: [Check], vault: Vault) {
        self.version = version
        self.checks = checks
        self.vault = vault
    }

    var paths: Paths { vault.paths }

    /// 12-digit AWS account ids, wherever they appear (ARNs, messages).
    static let accountId = try! NSRegularExpression(pattern: "(?<![0-9])[0-9]{12}(?![0-9])")

    /// The redaction every line of the report goes through.
    public static func clean(_ text: String) -> String {
        let scrubbed = Redact.home(Redact.scrub(text))
        return Redact.replace(accountId, in: scrubbed) { m, s in Redact.account(s.substring(with: m.range)) }
    }

    public func text(now: Date = Date()) -> String {
        var out: [String] = []
        func section(_ title: String, _ lines: [String]) {
            out.append("")
            out.append("== \(title) ==")
            out += lines.isEmpty ? ["(none)"] : lines
        }
        out.append("aws-cli-zsp diagnostics, \(LogLine.formatter.string(from: now))")
        out.append("Secrets are removed; key ids are masked and account ids show only their last 4 digits.")
        section("This Mac", system())
        section("Checks", checks.map { "\($0.symbol) \($0.name): \($0.detail)" })
        section("Settings", settings())
        section("Profiles", profiles())
        section("credential_process wiring", wiring())
        section("Support log (last 200 lines)", Log.recent(paths, limit: 200).map(\.text))
        section("Audit trail (last 200 entries)", audit())
        section("Watcher output (last 40 lines)", tail(paths.watchLog, 40))
        return out.map(Self.clean).joined(separator: "\n") + "\n"
    }

    /// Writes the report readable by you only, and returns where.
    @discardableResult
    public func write(to url: URL) throws -> URL {
        try writeAtomically(text(), to: url)
        Log.info("support", "diagnostics written to \(url.path)")
        return url
    }

    public static func defaultURL(now: Date = Date()) -> URL {
        let f = DateFormatter()
        f.dateFormat = "yyyy-MM-dd-HHmm"
        return FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Desktop/aws-cli-zsp-diagnostics-\(f.string(from: now)).txt")
    }

    func system() -> [String] {
        let os = ProcessInfo.processInfo.operatingSystemVersionString
        return ["aws-cli-zsp \(version)", "macOS \(os)", "hardware \(sysctl("hw.model"))\(sysctl("machdep.cpu.brand_string").isEmpty ? "" : ", \(sysctl("machdep.cpu.brand_string"))")",
                "Secure Enclave \(EnclaveStore.isAvailable ? "available" : "not available")",
                "support folder \(paths.supportDir.path)"]
    }

    func settings() -> [String] {
        let s = Settings.load(paths)
        return ["set up: \(s.onboarded == true ? "yes" : "no")", "automatic move: \(s.watching ? "on" : "off")",
                "kept in plain text: \(s.kept.sorted().joined(separator: ", "))",
                "session length: \(s.sessionSeconds / 60) min" + s.profileSessionSeconds.sorted { $0.key < $1.key }.map { ", \($0.key) \($0.value / 60) min" }.joined()]
    }

    func profiles() -> [String] {
        vault.list().map { p in
            var parts = [p.profile, p.maskedKeyId, p.keyStatus ?? "status unknown"]
            if let a = p.account { parts.append("account \(Redact.account(a))") }
            if p.temporary { parts.append("temporary") }
            if p.inKeychain == false { parts.append("NOT IN VAULT") }
            if p.mfaSerial != nil { parts.append(p.mfaEnforced == true ? "MFA enforced" : "MFA") }
            if p.remoteSerial != nil { parts.append("phone approval") }
            if p.pinnedAccount != nil { parts.append("pinned") }
            if p.readOnly { parts.append("read-only") }
            parts.append(p.sessionActive() ? "session active" : "no session")
            parts.append("imported \(LogLine.formatter.string(from: p.importedAt)) from \(p.source)")
            return parts.joined(separator: " | ")
        }
    }

    /// Each profile section's credential_process line, as the AWS CLI sees it.
    func wiring() -> [String] {
        let config = INIDocument((try? paths.text(paths.configFile)) ?? "")
        return vault.list().map { p in
            "\(p.profile): \(config.value("credential_process", in: AWSFiles.configSection(for: p.profile)) ?? "(not set)")"
        }
    }

    func audit() -> [String] {
        vault.audit.entries(limit: 200).map { e in
            let detail = e.detail.sorted { $0.key < $1.key }.map { "\($0.key)=\($0.value)" }.joined(separator: " ")
            return "\(e.ts) \(e.ok ? " " : "!")\(e.event) \(e.profile ?? "-") \(detail)"
        }
    }

    func tail(_ url: URL, _ n: Int) -> [String] {
        Array(((try? paths.text(url)) ?? "").split(separator: "\n").suffix(n).map(String.init))
    }

    func sysctl(_ name: String) -> String {
        var size = 0
        guard sysctlbyname(name, nil, &size, nil, 0) == 0, size > 0 else { return "" }
        var buf = [CChar](repeating: 0, count: size)
        guard sysctlbyname(name, &buf, &size, nil, 0) == 0 else { return "" }
        return String(cString: buf)
    }
}
