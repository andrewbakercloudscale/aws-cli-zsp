import Foundation
import LocalAuthentication

/// One line of `aws-cli-zsp doctor`.
public struct Check: Codable, Equatable, Identifiable, Sendable {
    public var name: String
    public var ok: Bool
    public var detail: String
    /// Not a failure, but worth knowing (auto-move off, nobody at the Mac).
    public var warn: Bool
    /// What would put it right, when one command can: the app shows it as a Fix button.
    public var fix: Fix?

    public var id: String { name }

    public init(name: String, ok: Bool, detail: String, warn: Bool = false, fix: Fix? = nil) {
        self.name = name
        self.ok = ok
        self.detail = detail
        self.warn = warn
        self.fix = fix
    }

    public var symbol: String { !ok ? "✗" : warn ? "!" : "✓" }
}

/// A repair the app can run for a failed check.
public enum Fix: String, Codable, Sendable {
    /// `aws-cli-zsp install`: the watcher, the login item and every credential_process line.
    case install
    /// `aws-cli-zsp import`: move the plaintext keys now.
    case moveKeys = "import"
    /// The setup screen.
    case setup
}

/// What the doctor cannot work out from the files alone: the CLI fills these in.
public struct DoctorProbes {
    /// The binary every credential_process line should run.
    public var binary: String
    public var watcherLoaded: () -> Bool
    public var menuAtLogin: () -> Bool
    public var someoneAtMac: () -> Bool
    /// Where pins are kept; nil in a sandbox.
    public var pins: SecretStore?
    /// Whether to ask AWS (reachability and the clock). Off in tests.
    public var network: Bool = true
    public var environment: [String: String] = ProcessInfo.processInfo.environment
    public var home: URL = FileManager.default.homeDirectoryForCurrentUser

    public init(binary: String, watcherLoaded: @escaping () -> Bool, menuAtLogin: @escaping () -> Bool,
                someoneAtMac: @escaping () -> Bool, pins: SecretStore?) {
        self.binary = binary
        self.watcherLoaded = watcherLoaded
        self.menuAtLogin = menuAtLogin
        self.someoneAtMac = someoneAtMac
        self.pins = pins
    }
}

/// Everything that has to be true for aws-cli-zsp to protect you, and the problems people
/// actually run into, checked without a prompt.
public struct Doctor {
    let vault: Vault
    let probes: DoctorProbes

    public init(vault: Vault, probes: DoctorProbes) {
        self.vault = vault
        self.probes = probes
    }

    var paths: Paths { vault.paths }

    public func run() -> [Check] {
        let settings = Settings.load(paths)
        let profiles = vault.list()
        var checks = [enclave(), touchID(), vaultKeys(profiles), plaintext(settings)]
        checks += shellKeys()
        checks += [wiring(profiles), awsCLI(), watcher(settings),
                   Check(name: "Menu bar app at login", ok: probes.menuAtLogin(),
                         detail: probes.menuAtLogin() ? "starts at login" : "not set to start at login", fix: probes.menuAtLogin() ? nil : .install),
                   auditTrail()]
        if probes.network { checks.append(awsReachable()) }
        checks += [keysActive(profiles), presence(), mfa(profiles)]
        if let pins = probes.pins { checks.append(pinned(profiles, pins)) }
        checks.append(recentErrors())
        return checks
    }

    func enclave() -> Check {
        Check(name: "Secure Enclave", ok: EnclaveStore.isAvailable,
              detail: EnclaveStore.isAvailable ? "available: keys are sealed to this Mac's chip" : "not available on this Mac")
    }

    func touchID() -> Check {
        var error: NSError?
        let ok = LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
        return Check(name: "Touch ID", ok: true,
                     detail: ok ? "ready" : "not available right now (lid closed, no sensor, or too many tries): macOS asks for your login password instead",
                     warn: !ok)
    }

    func vaultKeys(_ profiles: [ProfileMeta]) -> Check {
        let missing = profiles.filter { $0.inKeychain == false }.map(\.profile)
        let detail = profiles.isEmpty ? "no keys yet"
            : missing.isEmpty ? "\(profiles.count) sealed: \(profiles.map(\.profile).joined(separator: ", "))"
            : "not in the vault: \(missing.joined(separator: ", ")) (run aws-cli-zsp migrate)"
        return Check(name: "Keys in the vault", ok: missing.isEmpty && !profiles.isEmpty, detail: detail, fix: profiles.isEmpty ? .setup : nil)
    }

    func plaintext(_ s: Settings) -> Check {
        let findings = Scanner.scan(paths)
        let exposed = findings.filter { !s.kept.contains($0.profile) }
        let detail = !exposed.isEmpty ? "in plain text: \(exposed.map(\.profile).joined(separator: ", "))"
            : findings.isEmpty ? "none in ~/.aws/credentials or ~/.aws/config"
            : "only the ones you chose to keep: \(findings.map(\.profile).joined(separator: ", "))"
        return Check(name: "No plaintext keys", ok: exposed.isEmpty, detail: detail, warn: exposed.isEmpty && !findings.isEmpty,
                     fix: exposed.isEmpty ? nil : .moveKeys)
    }

    /// Shell startup files that export a key: the AWS CLI prefers those variables to any
    /// profile, so the vault is bypassed and the key sits in plain text.
    static let shellFiles = [".zshrc", ".zprofile", ".zshenv", ".bashrc", ".bash_profile", ".profile", ".config/fish/config.fish"]
    static let exportedKey = try! NSRegularExpression(pattern: "^\\s*(export\\s+|set\\s+-x\\s+|setenv\\s+)?AWS_(ACCESS_KEY_ID|SECRET_ACCESS_KEY)[\\s=]")

    func shellKeys() -> [Check] {
        var hits: [String] = []
        for name in Self.shellFiles {
            let url = probes.home.appendingPathComponent(name)
            guard let text = try? String(contentsOf: url, encoding: .utf8) else { continue }
            for (n, line) in text.split(separator: "\n", omittingEmptySubsequences: false).enumerated() {
                let l = String(line)
                if Self.exportedKey.firstMatch(in: l, range: NSRange(l.startIndex..., in: l)) != nil { hits.append("~/\(name):\(n + 1)") }
            }
        }
        var checks = [Check(name: "No keys in shell files", ok: hits.isEmpty,
                            detail: hits.isEmpty ? "no AWS_ACCESS_KEY_ID exported in ~/.zshrc and the like"
                                : "exported in \(hits.joined(separator: ", ")): the AWS CLI uses it instead of the vault, and it is plain text. Delete the line and add the key with aws-cli-zsp add")]
        if probes.environment["AWS_ACCESS_KEY_ID"] != nil {
            checks.append(Check(name: "This shell", ok: true,
                                detail: "AWS_ACCESS_KEY_ID is set here, so the AWS CLI ignores profiles in this shell (unset it, or check where it comes from)",
                                warn: true))
        }
        return checks
    }

    func wiring(_ profiles: [ProfileMeta]) -> Check {
        let config = INIDocument(paths.text(paths.configFile))
        let unwired = profiles.filter { p in
            let cp = config.value("credential_process", in: AWSFiles.configSection(for: p.profile)) ?? ""
            return !cp.contains(probes.binary) || !cp.contains("credential-process")
        }.map(\.profile)
        return Check(name: "AWS CLI wired to the vault", ok: unwired.isEmpty,
                     detail: unwired.isEmpty ? "every profile's credential_process runs this aws-cli-zsp"
                         : "not wired to this copy of the app: \(unwired.joined(separator: ", ")) (the app moved, or the config was edited)",
                     fix: unwired.isEmpty ? nil : .install)
    }

    /// The AWS CLI itself: the app is launched without your shell's PATH, so the usual places
    /// are looked at too.
    func awsCLI() -> Check {
        let dirs = (probes.environment["PATH"] ?? "").split(separator: ":").map(String.init)
            + ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin"]
        guard let aws = dirs.lazy.map({ "\($0)/aws" }).first(where: { FileManager.default.isExecutableFile(atPath: $0) }) else {
            return Check(name: "AWS CLI", ok: true, detail: "not found: install it (brew install awscli); the vault works with any SDK that reads ~/.aws/config", warn: true)
        }
        let version = Self.run(aws, ["--version"]).split(separator: " ").first.map(String.init) ?? "unknown version"
        let v1 = version.hasPrefix("aws-cli/1.")
        return Check(name: "AWS CLI", ok: true, detail: "\(version) at \(aws)\(v1 ? ": version 1 works, version 2 is recommended" : "")", warn: v1)
    }

    func watcher(_ s: Settings) -> Check {
        let loaded = probes.watcherLoaded()
        let detail = !s.watching ? "off: new keys stay where they are written until you move them"
            : loaded ? "on: the watcher moves new keys within seconds" : "on, but the watcher is not running"
        return Check(name: "Automatic move", ok: !s.watching || loaded, detail: detail, warn: !s.watching,
                     fix: s.watching && !loaded ? .install : nil)
    }

    func auditTrail() -> Check {
        let v = vault.audit.verify()
        return Check(name: "Audit trail", ok: v.intact, detail: v.intact ? "chain intact, \(v.entries) entries" : "broken: \(v.problem ?? "?")")
    }

    func awsReachable() -> Check {
        switch AWSProbe.check() {
        case let .ok(skew):
            let off = abs(skew)
            if off > 240 {
                return Check(name: "AWS reachable", ok: false,
                             detail: "yes, but this Mac's clock is \(Int(off / 60)) min \(skew > 0 ? "ahead" : "behind"): AWS refuses signed requests 5 minutes off. Set the time automatically in System Settings › General › Date & Time")
            }
            return Check(name: "AWS reachable", ok: true, detail: "STS answers, and this Mac's clock agrees with AWS's (\(Int(off.rounded())) s apart)")
        case let .failed(message):
            return Check(name: "AWS reachable", ok: false, detail: message)
        }
    }

    func keysActive(_ profiles: [ProfileMeta]) -> Check {
        let inactive = profiles.filter { $0.keyStatus != nil && $0.keyStatus != "Active" }.map(\.profile)
        return Check(name: "Keys active in AWS", ok: inactive.isEmpty,
                     detail: inactive.isEmpty ? "no key is known to be deactivated (Check in AWS refreshes this)"
                         : "deactivated in AWS: \(inactive.joined(separator: ", ")). Re-enable it in the IAM console, or add a new key")
    }

    func presence() -> Check {
        let here = probes.someoneAtMac()
        return Check(name: "Someone at the Mac", ok: true,
                     detail: here ? "yes: a new session asks for Touch ID" : "no: a new session fails at once (phone approval or wait)", warn: !here)
    }

    func mfa(_ profiles: [ProfileMeta]) -> Check {
        let enforced = profiles.filter { $0.mfaEnforced == true }.map(\.profile)
        return Check(name: "MFA enforced by AWS", ok: true,
                     detail: enforced.isEmpty ? "not yet for any profile (MFA & phone tab)" : "for \(enforced.joined(separator: ", "))",
                     warn: enforced.isEmpty)
    }

    func pinned(_ profiles: [ProfileMeta], _ pins: SecretStore) -> Check {
        let unpinned = profiles.filter { !$0.temporary && pins.peek(.pin, $0.profile) == nil }.map(\.profile)
        return Check(name: "Accounts pinned", ok: true,
                     detail: unpinned.isEmpty ? "every key is checked against its AWS account before a session is handed out"
                         : "not yet: \(unpinned.joined(separator: ", ")) (pinned at the next session)",
                     warn: !unpinned.isEmpty)
    }

    func recentErrors() -> Check {
        let since = Date().addingTimeInterval(-86_400)
        let errors = Log.recent(paths, limit: 1000, atLeast: .error).filter { $0.date > since }
        guard let last = errors.last else {
            return Check(name: "Errors in the last day", ok: true, detail: "none in the support log")
        }
        return Check(name: "Errors in the last day", ok: true,
                     detail: "\(errors.count), the latest at \(last.date.formatted(date: .omitted, time: .shortened)): \(last.message)", warn: true)
    }

    /// A short command's output, for version strings.
    static func run(_ path: String, _ args: [String]) -> String {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: path)
        p.arguments = args
        let out = Pipe()
        p.standardOutput = out
        p.standardError = out
        p.standardInput = FileHandle.nullDevice
        do { try p.run() } catch { return "" }
        let data = out.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
    }
}

/// An unsigned request to STS: it is refused, but the answer proves AWS is reachable and its
/// Date header shows how far this Mac's clock is off.
enum AWSProbe {
    enum Result { case ok(skew: TimeInterval), failed(String) }

    static func check(host: String = "sts.us-east-1.amazonaws.com", timeout: TimeInterval = 6) -> Result {
        guard let url = URL(string: "https://\(host)/") else { return .failed("bad host \(host)") }
        final class Box: @unchecked Sendable { var result: Result = .failed("no answer from AWS") }
        let box = Box()
        let done = DispatchSemaphore(value: 0)
        // Never from a cache: a cached answer carries an old Date header.
        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalAndRemoteCacheData, timeoutInterval: timeout)
        request.httpMethod = "GET"
        let sent = Date()
        URLSession(configuration: .ephemeral).dataTask(with: request) { _, response, error in
            if let error {
                box.result = .failed(networkMessage(error, host: host))
            } else if let date = (response as? HTTPURLResponse)?.value(forHTTPHeaderField: "Date").flatMap(httpDate) {
                // Against the middle of the round trip.
                box.result = .ok(skew: Date(timeInterval: Date().timeIntervalSince(sent) / 2, since: sent).timeIntervalSince(date))
            } else {
                box.result = .ok(skew: 0)
            }
            done.signal()
        }.resume()
        if done.wait(timeout: .now() + timeout + 1) == .timedOut { return .failed("cannot reach \(host): no answer in \(Int(timeout)) s") }
        Log.debug("doctor", "AWS probe: \(box.result)")
        return box.result
    }

    static func httpDate(_ s: String) -> Date? {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(identifier: "GMT")
        f.dateFormat = "EEE, dd MMM yyyy HH:mm:ss zzz"
        return f.date(from: s)
    }
}
