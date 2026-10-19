import Darwin
import Foundation
import ZSPCore

let version = "0.2.0"

let usage = """
aws-cli-zsp \(version) (AWS CLI: ZSP): AWS keys sealed by the Secure Enclave, Touch ID to use them, never in ~/.aws in plain text.

Keys
  aws-cli-zsp import [--auto]              move every key in ~/.aws/credentials and ~/.aws/config into the vault
  aws-cli-zsp scan                         list plaintext keys without moving them (exit 1 if any)
  aws-cli-zsp add --profile P              type a key in (secret not echoed); it never touches a file
  aws-cli-zsp list                         profiles, keys, sessions, last use
  aws-cli-zsp inspect --profile P          who the key belongs to and when AWS last saw each key used

Using them
  aws-cli-zsp credential-process --profile P   what ~/.aws/config calls; prints a short-lived session
  aws-cli-zsp exec --profile P -- CMD...       run CMD with a session in its environment
  aws-cli-zsp duration [--profile P] 1h        session length (15m to 12h, default 1h)

Rotate and revoke
  aws-cli-zsp rotate --profile P [--keep-old]  new key, verified, old one deleted (or deactivated)
  aws-cli-zsp revoke-sessions --profile P      invalidate every session issued so far, in AWS
  aws-cli-zsp clear-sessions [--profile P]     drop cached sessions on this Mac
  aws-cli-zsp disable-key --profile P          deactivate the key in AWS (re-enable in the IAM console)
  aws-cli-zsp delete-key --profile P           delete the key in AWS and on this Mac
  aws-cli-zsp forget --profile P               remove the key from this Mac only

Audit and setup
  aws-cli-zsp audit [--limit N] [--verify]     the hash-chained audit trail
  aws-cli-zsp migrate                          move keys stored by 0.1.x into the Secure Enclave vault
  aws-cli-zsp check-touch-id                   show a Touch ID prompt and nothing else
  aws-cli-zsp ui                               open the panel in a window (when the menu bar icon is hidden)
  aws-cli-zsp install                          watcher, menu bar app at login, ~/.local/bin/aws-cli-zsp, first import
  aws-cli-zsp uninstall [--restore-plaintext]  remove the agents; optionally put the keys back in the file

  --json for machine output, --yes to skip confirmations.
"""

// MARK: Arguments

struct Options {
    var command = ""
    var values: [String: String] = [:]
    var flags: Set<String> = []
    var rest: [String] = []

    static let takesValue: Set<String> = ["--profile", "--limit", "--access-key-id"]

    init(_ argv: [String]) {
        var i = 0
        while i < argv.count {
            let a = argv[i]
            if a == "--" { rest += argv[(i + 1)...]; break }
            if Self.takesValue.contains(a), i + 1 < argv.count {
                values[a] = argv[i + 1]
                i += 2
                continue
            }
            if a.hasPrefix("--"), let eq = a.firstIndex(of: "="), Self.takesValue.contains(String(a[..<eq])) {
                values[String(a[..<eq])] = String(a[a.index(after: eq)...])
            } else if a.hasPrefix("-") {
                flags.insert(a)
            } else if command.isEmpty {
                command = a
            } else {
                rest.append(a)
            }
            i += 1
        }
    }

    var json: Bool { flags.contains("--json") }
    var yes: Bool { flags.contains("--yes") || flags.contains("-y") }
    var profile: String? { values["--profile"] }
}

let opts = Options(Array(CommandLine.arguments.dropFirst()))

// MARK: Output

struct Envelope<T: Encodable>: Encodable {
    let ok: Bool
    let result: T?
    let error: String?
}

func printJSON<T: Encodable>(_ value: T) {
    let e = JSONEncoder()
    e.dateEncodingStrategy = .iso8601
    e.outputFormatting = [.sortedKeys, .prettyPrinted]
    FileHandle.standardOutput.write((try? e.encode(value)) ?? Data("{}".utf8))
    FileHandle.standardOutput.write(Data("\n".utf8))
}

/// Prints a command's result. Commands return after it and main exits 0. (Commands used to be
/// `-> Never` and exit here; Swift 6.2's optimiser miscompiles that shape in release builds.)
func done<T: Encodable>(_ result: T, _ text: String) {
    if opts.json { printJSON(Envelope(ok: true, result: result, error: nil)) } else if !text.isEmpty {
        print(text)
    }
}

func fail(_ message: String, code: Int32 = 1) -> Never {
    if opts.json { printJSON(Envelope<String>(ok: false, result: nil, error: message)) } else {
        FileHandle.standardError.write(Data("aws-cli-zsp: \(message)\n".utf8))
    }
    exit(code)
}

func requireProfile() -> String {
    guard let p = opts.profile, !p.isEmpty else { fail("--profile is required") }
    return p
}

func confirm(_ question: String) {
    if opts.yes { return }
    guard isatty(STDIN_FILENO) != 0 else { fail("\(question) Add --yes to confirm.") }
    print("\(question) [y/N] ", terminator: "")
    guard let answer = readLine()?.lowercased(), answer == "y" || answer == "yes" else { fail("cancelled") }
}

func ago(_ d: Date?) -> String {
    guard let d else { return "never" }
    let f = RelativeDateTimeFormatter()
    f.unitsStyle = .short
    return f.localizedString(for: d, relativeTo: Date())
}

func clock(_ d: Date) -> String {
    let f = DateFormatter()
    f.dateFormat = "yyyy-MM-dd HH:mm:ss"
    return f.string(from: d)
}

// MARK: Wiring

/// The real path of this binary: what credential_process lines and launch agents point at.
func selfPath() -> String {
    var buf = [CChar](repeating: 0, count: 4096)
    let path = proc_pidpath(getpid(), &buf, UInt32(buf.count)) > 0 ? String(cString: buf) : CommandLine.arguments[0]
    return URL(fileURLWithPath: path).resolvingSymlinksInPath().path
}

let paths = Paths.standard()

func makeVault() -> Vault {
    // Sealed to the Secure Enclave under ZSP_HOME, so a sandbox (another ZSP_HOME) is separate.
    let store = EnclaveStore(dir: paths.supportDir.appendingPathComponent("vault"))
    let presence = DeviceOwnerPresence(enclaveGated: true)
    store.context = { presence.context }
    return Vault(paths: paths, store: store, auth: presence, aws: AWSQueryService(), commandPath: selfPath())
}

func run(_ body: () throws -> Void) {
    do { try body() } catch { fail(error.localizedDescription) }
}

// MARK: Commands

func cmdImport() throws {
    let auto = opts.flags.contains("--auto")
    let report = try makeVault().importPlaintext(origin: auto ? "watcher" : "aws-cli-zsp import")
    var lines: [String] = []
    for p in report.imported { lines.append("moved \(p) into the vault\(report.replaced.contains(p) ? " (replaced its previous key)" : "")") }
    for f in report.incomplete { lines.append("waiting: \(f.profile) in \(f.file) has only half a key pair") }
    if auto && lines.isEmpty { return }
    if auto { lines = lines.map { "\(clock(Date())) \($0)" } }
    done(report, lines.isEmpty ? "no plaintext keys found" : lines.joined(separator: "\n"))
}

func cmdScan() {
    let findings = Scanner.scan(paths)
    if opts.json {
        printJSON(Envelope(ok: findings.isEmpty, result: findings, error: findings.isEmpty ? nil : "plaintext keys found"))
        exit(findings.isEmpty ? 0 : 1)
    }
    if findings.isEmpty { print("no plaintext keys in \(paths.credentialsFile.path) or \(paths.configFile.path)"); exit(0) }
    for f in findings { print("PLAINTEXT  \(f.profile)  \(maskKeyId(f.accessKeyId))  \(f.file)") }
    print("run `aws-cli-zsp import` to move them into the vault")
    exit(1)
}

func readKeyId(given: String?, tty: Bool) -> String {
    if let given { return given }
    if tty { print("AWS Access Key ID: ", terminator: "") }
    return (readLine() ?? "").trimmingCharacters(in: .whitespaces)
}

/// The secret, without echo at a terminal; one line of stdin otherwise (`pbpaste | aws-cli-zsp add`).
func readSecret(tty: Bool) -> String {
    guard tty else { return (readLine() ?? "").trimmingCharacters(in: .whitespaces) }
    var buf = [CChar](repeating: 0, count: 256)
    var secret = ""
    if let p = readpassphrase("AWS Secret Access Key (hidden): ", &buf, buf.count, 0) { secret = String(cString: p) }
    memset_s(&buf, buf.count, 0, buf.count)
    return secret
}

func cmdAdd() throws {
    let profile = requireProfile()
    let tty = isatty(STDIN_FILENO) != 0
    let keyId = readKeyId(given: opts.values["--access-key-id"], tty: tty)
    let secret = readSecret(tty: tty)
    if keyId.count < 16 || secret.isEmpty { fail("an access key id and a secret are both needed") }
    try makeVault().add(profile: profile, accessKeyId: keyId, secretAccessKey: secret)
    let message = "stored \(maskKeyId(keyId)) for \(profile) in the vault; `aws --profile \(profile) ...` now asks for Touch ID"
    done(["profile": profile, "accessKeyId": keyId], message)
}

func cmdList() {
    let profiles = makeVault().list()
    let findings = Scanner.scan(paths)
    struct ListResult: Encodable { let profiles: [ProfileMeta]; let plaintext: [Finding] }
    var lines: [String] = []
    if profiles.isEmpty { lines.append("no keys in the vault yet: run `aws-cli-zsp import` or `aws-cli-zsp add --profile NAME`") }
    for p in profiles {
        let session = p.sessionActive() ? "session until \(clock(p.sessionExpiresAt!))" : "no session"
        let status = p.keyStatus.map { " [\($0)]" } ?? ""
        let missing = p.inKeychain == false ? " (NOT in the vault: run aws-cli-zsp migrate)" : ""
        lines.append("\(p.profile)  \(p.maskedKeyId)\(status)\(missing)  \(session)  used \(ago(p.lastUsedAt))\(p.lastRequester.map { " by \($0)" } ?? "")")
    }
    for f in findings { lines.append("PLAINTEXT  \(f.profile)  \(maskKeyId(f.accessKeyId))  \(f.file)") }
    done(ListResult(profiles: profiles, plaintext: findings), lines.joined(separator: "\n"))
}

func cmdCredentialProcess() {
    let profile = requireProfile()
    do {
        let c = try makeVault().credentials(for: profile, requester: Requester.describe())
        var out: [String: Any] = ["Version": 1, "AccessKeyId": c.accessKeyId, "SecretAccessKey": c.secretAccessKey]
        if let t = c.sessionToken { out["SessionToken"] = t }
        if let e = c.expiration { out["Expiration"] = iso8601(e) }
        let data = try JSONSerialization.data(withJSONObject: out, options: [.sortedKeys])
        FileHandle.standardOutput.write(data)
        exit(0)
    } catch {
        FileHandle.standardError.write(Data("aws-cli-zsp: \(error.localizedDescription)\n".utf8))
        exit(1)
    }
}

func cmdExec() throws {
    let profile = requireProfile()
    guard !opts.rest.isEmpty else { fail("nothing to run: aws-cli-zsp exec --profile \(profile) -- aws s3 ls") }
    let c = try makeVault().credentials(for: profile, requester: Requester.describe(pid: getpid()))
    setenv("AWS_ACCESS_KEY_ID", c.accessKeyId, 1)
    setenv("AWS_SECRET_ACCESS_KEY", c.secretAccessKey, 1)
    if let t = c.sessionToken { setenv("AWS_SESSION_TOKEN", t, 1) } else { unsetenv("AWS_SESSION_TOKEN") }
    if let e = c.expiration { setenv("AWS_CREDENTIAL_EXPIRATION", iso8601(e), 1) }
    // The environment now carries the credentials; a profile would send the SDK back to us.
    unsetenv("AWS_PROFILE")
    unsetenv("AWS_DEFAULT_PROFILE")
    setenv("ZSP_PROFILE", profile, 1)
    let argv = opts.rest.map { strdup($0) } + [nil]
    execvp(opts.rest[0], argv)
    fail("cannot run \(opts.rest[0]): \(String(cString: strerror(errno)))", code: 127)
}

func cmdDuration() throws {
    guard let raw = opts.rest.first, let seconds = parseDuration(raw) else {
        let s = Settings.load(paths)
        done(s, "default \(s.sessionSeconds)s" + s.profileSessionSeconds.map { "\n\($0.key) \($0.value)s" }.sorted().joined())
        return
    }
    guard (Settings.minSeconds...Settings.maxSeconds).contains(seconds) else { fail("sessions last 15m to 12h") }
    var s = Settings.load(paths)
    if let p = opts.profile { s.profileSessionSeconds[p] = seconds } else { s.sessionSeconds = seconds }
    try s.save(paths)
    try makeVault().audit.append("settings.duration", profile: opts.profile, detail: ["seconds": String(seconds)])
    done(s, "sessions for \(opts.profile ?? "every profile") now last \(seconds / 60) minutes (from the next one issued)")
}

func cmdRotate() throws {
    let profile = requireProfile()
    let keep = opts.flags.contains("--keep-old")
    confirm("Create a new key for \(profile) and \(keep ? "deactivate" : "delete") the current one in AWS?")
    let r = try makeVault().rotate(profile, keepOld: keep)
    done(r, "rotated \(profile): \(maskKeyId(r.oldKeyId)) \(r.oldKey), \(maskKeyId(r.newKeyId)) is now in the vault")
}

func cmdRevokeSessions() throws {
    let profile = requireProfile()
    confirm("Invalidate every session issued for \(profile) until now, on every machine?")
    let cutoff = try makeVault().revokeSessions(profile)
    done(["profile": profile, "revokedBefore": iso8601(cutoff)],
         "sessions for \(profile) issued before \(clock(cutoff)) are denied (policy \(Vault.revokePolicyName)); the next command gets a fresh one")
}

func cmdDisable() throws {
    let profile = requireProfile()
    confirm("Deactivate the AWS key for \(profile)? AWS CLI: ZSP cannot reactivate it: that needs the IAM console.")
    try makeVault().disableKey(profile)
    done(["profile": profile], "deactivated the key for \(profile) in AWS")
}

func cmdDelete() throws {
    let profile = requireProfile()
    confirm("Delete the AWS key for \(profile) in AWS and on this Mac? This cannot be undone.")
    try makeVault().deleteKey(profile)
    done(["profile": profile], "deleted the key for \(profile) in AWS and removed it from this Mac")
}

func cmdForget() throws {
    let profile = requireProfile()
    confirm("Remove the key for \(profile) from this Mac? AWS keeps it; without a copy elsewhere it is lost to you.")
    try makeVault().forget(profile)
    done(["profile": profile], "removed \(profile) from this Mac")
}

func cmdClearSessions() throws {
    let names = try makeVault().clearSessions(opts.profile)
    done(names, names.isEmpty ? "no cached sessions" : "cleared cached sessions: \(names.joined(separator: ", "))")
}

func cmdInspect() throws {
    let r = try makeVault().inspect(requireProfile())
    var lines = ["\(r.profile): \(r.identity.arn) (account \(r.identity.account))"]
    for k in r.keys {
        let used = k.lastUsed?.lastUsedDate.map { "last used \(clock($0)) \(k.lastUsed?.serviceName ?? "") \(k.lastUsed?.region ?? "")" } ?? "never used"
        lines.append("  \(maskKeyId(k.accessKeyId)) \(k.status)\(k.thisProfile ? " (this profile)" : "") created \(k.createDate.map(clock) ?? "?"), \(used)")
    }
    done(r, lines.joined(separator: "\n"))
}

func cmdAudit() {
    let log = makeVault().audit
    if opts.flags.contains("--verify") {
        let v = log.verify()
        if opts.json { printJSON(Envelope(ok: v.intact, result: v, error: v.problem)); exit(v.intact ? 0 : 1) }
        if v.intact {
            print("audit trail intact: \(v.entries) entries\(v.anchored == true ? ", newest matches the sealed anchor" : "")")
            exit(0)
        }
        fail("audit trail BROKEN after \(v.entries) good entries: \(v.problem ?? "?")")
    }
    let entries = log.entries(limit: Int(opts.values["--limit"] ?? "") ?? 50)
    done(entries, entries.map { e in
        let detail = e.detail.sorted { $0.key < $1.key }.map { "\($0.key)=\($0.value)" }.joined(separator: " ")
        return "\(e.date.map(clock) ?? e.ts)  \(e.ok ? " " : "!")\(e.event)  \(e.profile ?? "-")  \(detail)\(e.requester.map { "  ← \($0)" } ?? "")"
    }.joined(separator: "\n"))
}

/// Moves keys stored by 0.1.x (plain login-Keychain items) into the Secure Enclave vault.
/// Those items are bound to the exact build that made them, so macOS asks for your login
/// password once per key: this is the last time it does.
func cmdMigrate() throws {
    let legacy = KeychainStore(prefix: ProcessInfo.processInfo.environment["ZSP_KEYCHAIN_PREFIX"] ?? "consulting.cloudscale.zsp")
    let vault = makeVault()
    var moved: [String] = []
    var failed: [String: String] = [:]
    for p in try legacy.accounts(.master) {
        do {
            guard let data = try legacy.read(.master, p) else { continue }
            try vault.storeMaster(raw: data, profile: p)
            try legacy.delete(.master, p)
            moved.append(p)
        } catch {
            failed[p] = error.localizedDescription
        }
    }
    for p in (try? legacy.accounts(.session)) ?? [] { try? legacy.delete(.session, p) }
    try? legacy.delete(.auditHead, "head")
    if !moved.isEmpty || !failed.isEmpty {
        try vault.audit.append("keys.migrated", ok: failed.isEmpty, detail: ["moved": moved.joined(separator: ","), "failed": failed.keys.sorted().joined(separator: ",")])
    }
    struct Result: Encodable { let moved: [String]; let failed: [String: String] }
    var lines = moved.map { "moved \($0) into the Secure Enclave vault" }
    lines += failed.sorted { $0.key < $1.key }.map { "NOT moved \($0.key): \($0.value) (run migrate again and click Allow)" }
    done(Result(moved: moved, failed: failed), lines.isEmpty ? "nothing to migrate" : lines.joined(separator: "\n"))
}

func cmdCheckTouchID() throws {
    try DeviceOwnerPresence().confirm("check that Touch ID works for AWS CLI: ZSP (nothing is unlocked)")
    done(["ok": true], "Touch ID works")
}

func cmdUI() throws {
    let bin = selfPath()
    guard let range = bin.range(of: ".app/Contents/Helpers/") else {
        fail("not inside the app bundle (bash scripts/build-app.sh installs it): \(bin)")
    }
    let p = Process()
    p.executableURL = URL(fileURLWithPath: "/usr/bin/open")
    p.arguments = [String(bin[..<range.lowerBound]) + ".app"]
    try p.run()
    p.waitUntilExit()
    if p.terminationStatus != 0 { fail("open failed (\(p.terminationStatus))") }
}

// MARK: Install

let watchLabel = "consulting.cloudscale.zsp.watch"
let menuLabel = "consulting.cloudscale.zsp.menu"
let agentsDir = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/LaunchAgents")

func launchctl(_ args: [String]) -> Int32 {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: "/bin/launchctl")
    p.arguments = args
    p.standardOutput = FileHandle.nullDevice
    p.standardError = FileHandle.nullDevice
    try? p.run()
    p.waitUntilExit()
    return p.terminationStatus
}

func load(_ label: String, _ plist: [String: Any]) throws {
    let url = agentsDir.appendingPathComponent("\(label).plist")
    try FileManager.default.createDirectory(at: agentsDir, withIntermediateDirectories: true)
    let data = try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
    try data.write(to: url)
    let domain = "gui/\(getuid())"
    _ = launchctl(["bootout", "\(domain)/\(label)"])
    guard launchctl(["bootstrap", domain, url.path]) == 0 else { throw ZSPError.io("launchctl could not load \(url.path)") }
}

func cmdInstall() throws {
    let bin = selfPath()
    // The CLI lives in aws-cli-zsp.app/Contents/Helpers/aws-cli-zsp.app, a helper bundle so
    // macOS names it "AWS CLI: ZSP" in Touch ID and Keychain dialogs.
    guard let range = bin.range(of: ".app/Contents/Helpers/") else {
        fail("run install from the app bundle (bash scripts/build-app.sh installs it): \(bin) is not inside one")
    }
    let app = String(bin[..<range.lowerBound]) + ".app"
    let menuBin = app + "/Contents/MacOS/ZSPMenu"
    try paths.ensureSupportDir()

    let localBin = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".local/bin")
    try FileManager.default.createDirectory(at: localBin, withIntermediateDirectories: true)
    let link = localBin.appendingPathComponent("aws-cli-zsp")
    try? FileManager.default.removeItem(at: link)
    // The command was called zsp before 0.2.0.
    let oldLink = localBin.appendingPathComponent("zsp")
    if (try? FileManager.default.destinationOfSymbolicLink(atPath: oldLink.path))?.contains("aws-cli-zsp") == true {
        try? FileManager.default.removeItem(at: oldLink)
    }
    try FileManager.default.createSymbolicLink(atPath: link.path, withDestinationPath: bin)

    var env: [String: String] = [:]
    for k in ["AWS_SHARED_CREDENTIALS_FILE", "AWS_CONFIG_FILE", "ZSP_HOME"] { env[k] = ProcessInfo.processInfo.environment[k] }
    let awsDir = paths.credentialsFile.deletingLastPathComponent()
    try FileManager.default.createDirectory(at: awsDir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    // launchd runs the import whenever either file or the folder changes, and every five
    // minutes in case a change slipped past (an editor that swaps the file, a sleeping Mac).
    try load(watchLabel, [
        "Label": watchLabel,
        "ProgramArguments": [bin, "import", "--auto"],
        "WatchPaths": [paths.credentialsFile.path, paths.configFile.path, awsDir.path],
        "StartInterval": 300,
        "RunAtLoad": true,
        "ThrottleInterval": 2,
        "ProcessType": "Background",
        "EnvironmentVariables": env,
        "StandardOutPath": paths.watchLog.path,
        "StandardErrorPath": paths.watchLog.path,
    ])
    var menuLoaded = false
    if FileManager.default.isExecutableFile(atPath: menuBin) {
        try load(menuLabel, ["Label": menuLabel, "ProgramArguments": [menuBin, "--background"], "RunAtLoad": true,
                             "LimitLoadToSessionType": "Aqua", "ProcessType": "Interactive", "EnvironmentVariables": env])
        menuLoaded = true
    }
    let rewired = try makeVault().rewire()
    let report = try makeVault().importPlaintext(origin: "aws-cli-zsp install")
    try makeVault().audit.append("zsp.installed", detail: ["binary": bin, "rewired": rewired.joined(separator: ",")])
    var lines = ["installed: watcher \(watchLabel)\(menuLoaded ? ", menu bar app at login" : ""), \(link.path) → \(bin)"]
    lines += report.imported.map { "moved \($0) into the vault" }
    if report.imported.isEmpty { lines.append("no plaintext keys to move") }
    done(report, lines.joined(separator: "\n"))
}

func cmdUninstall() throws {
    let domain = "gui/\(getuid())"
    for label in [watchLabel, menuLabel] {
        _ = launchctl(["bootout", "\(domain)/\(label)"])
        try? FileManager.default.removeItem(at: agentsDir.appendingPathComponent("\(label).plist"))
    }
    for name in ["aws-cli-zsp", "zsp"] {
        let link = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".local/bin/\(name)")
        if (try? FileManager.default.destinationOfSymbolicLink(atPath: link.path))?.contains("aws-cli-zsp") == true {
            try? FileManager.default.removeItem(at: link)
        }
    }
    var restored: [String] = []
    if opts.flags.contains("--restore-plaintext") {
        confirm("Write every key back into \(paths.credentialsFile.path) in plain text?")
        restored = try makeVault().restorePlaintext()
    }
    _ = try? makeVault().audit.append("zsp.uninstalled", detail: ["restored": restored.joined(separator: ",")])
    done(restored, restored.isEmpty
        ? "agents removed; keys stay in the vault and profiles still use aws-cli-zsp (remove the app last, or run with --restore-plaintext)"
        : "agents removed; wrote \(restored.joined(separator: ", ")) back to \(paths.credentialsFile.path)")
}

// MARK: Main

run {
    switch opts.command {
    case "import": try cmdImport()
    case "scan": cmdScan()
    case "add": try cmdAdd()
    case "list", "ls", "status": cmdList()
    case "credential-process": cmdCredentialProcess()
    case "exec": try cmdExec()
    case "duration": try cmdDuration()
    case "rotate": try cmdRotate()
    case "revoke-sessions", "revoke": try cmdRevokeSessions()
    case "disable-key": try cmdDisable()
    case "delete-key": try cmdDelete()
    case "forget": try cmdForget()
    case "clear-sessions": try cmdClearSessions()
    case "inspect": try cmdInspect()
    case "audit": cmdAudit()
    case "install": try cmdInstall()
    case "migrate": try cmdMigrate()
    case "check-touch-id": try cmdCheckTouchID()
    case "ui", "open": try cmdUI()
    case "uninstall": try cmdUninstall()
    case "version", "--version": print(version)
    case "", "help", "--help", "-h": print(usage)
    default: fail("unknown command \(opts.command)\n\n\(usage)", code: 2)
    }
}
exit(0)
