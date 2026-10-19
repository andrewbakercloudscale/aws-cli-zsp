import CoreGraphics
import Darwin
import Foundation
import ZSPCore

let version = "0.3.0"

let usage = """
aws-cli-zsp \(version) (AWS CLI: ZSP, Zero Standing Permissions): AWS keys sealed by the Secure Enclave, Touch ID to use them, never in ~/.aws in plain text.

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

MFA, and approval when nobody is at the Mac (Claude Code Remote Control)
  aws-cli-zsp mfa setup --profile P            make this Mac an MFA device: every session carries MFA, still one Touch ID
  aws-cli-zsp mfa enforce --profile P          AWS refuses the key without MFA, so a copy of it alone is worthless
  aws-cli-zsp remote enable --profile P [--serial ARN]   let a code from your phone approve a session
  aws-cli-zsp approve --profile P CODE         issue a session with that code, no Touch ID
  aws-cli-zsp remote disable --profile P

Rotate and revoke
  aws-cli-zsp rotate --profile P [--keep-old]  new key, verified, old one deleted (or deactivated)
  aws-cli-zsp revoke-sessions --profile P      invalidate every session issued so far, in AWS
  aws-cli-zsp clear-sessions [--profile P]     drop cached sessions on this Mac
  aws-cli-zsp disable-key --profile P          deactivate the key in AWS (re-enable in the IAM console)
  aws-cli-zsp delete-key --profile P           delete the key in AWS and on this Mac
  aws-cli-zsp forget --profile P               remove the key from this Mac only

Setup and tests
  aws-cli-zsp setup [--move a,b] [--keep c] [--auto on|off] [--duration 1h]   first run: what moves, what stays, auto-move
  aws-cli-zsp import [--profiles a,b] [--all]   move keys now (profiles kept in plain text stay unless named or --all)
  aws-cli-zsp doctor                           check everything, with no prompt
  aws-cli-zsp test --profile P                 a real AWS call with the profile (Touch ID if no session)
  aws-cli-zsp selftest-watcher                 write AWS's example key to ~/.aws and time the automatic move

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

    static let takesValue: Set<String> = ["--profile", "--limit", "--access-key-id", "--serial", "--name", "--profiles", "--move", "--keep", "--auto", "--duration"]

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
    let vault = Vault(paths: paths, store: store, auth: presence, aws: AWSQueryService(), commandPath: selfPath())
    vault.someoneAtMac = someoneAtMac
    return vault
}

/// Someone can answer Touch ID: the screen is unlocked and the keyboard, mouse or trackpad was
/// used in the last 5 minutes (ZSP_AWAY_AFTER seconds). Claude Code's own commands are not
/// input events, so under Remote Control this is false and nothing waits on a hidden prompt.
func someoneAtMac() -> Bool {
    let env = ProcessInfo.processInfo.environment
    if env["ZSP_ASSUME_PRESENT"] == "1" { return true }
    if let session = CGSessionCopyCurrentDictionary() as? [String: Any],
       (session["CGSSessionScreenIsLocked"] as? Bool) == true { return false }
    let limit = env["ZSP_AWAY_AFTER"].flatMap(Double.init) ?? 300
    guard let any = CGEventType(rawValue: UInt32.max) else { return true }
    return CGEventSource.secondsSinceLastEventType(.combinedSessionState, eventType: any) < limit
}

func run(_ body: () throws -> Void) {
    do { try body() } catch { fail(error.localizedDescription) }
}

// MARK: Commands

func list(_ key: String) -> [String] {
    (opts.values[key] ?? "").split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
}

func cmdImport() throws {
    let auto = opts.flags.contains("--auto")
    var settings = Settings.load(paths)
    // Keys moved in before setup existed (0.2.x): that was setup, with the watcher on.
    if settings.onboarded == nil, !MetadataStore(paths: paths).all().isEmpty {
        settings.onboarded = true
        try settings.save(paths)
    }
    if auto && !settings.watching { return }
    let only = list("--profiles")
    // Profiles you chose to keep in plain text stay put, unless you name them.
    let report = try makeVault().importPlaintext(origin: auto ? "watcher" : "aws-cli-zsp import",
                                                  only: only.isEmpty ? nil : Set(only),
                                                  skip: only.isEmpty && !opts.flags.contains("--all") ? settings.kept : [])
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
        var mfa = ""
        if p.mfaSerial != nil { mfa += p.mfaEnforced == true ? " [MFA enforced]" : " [MFA]" }
        if let r = p.remoteSerial { mfa += " [remote: \(r.split(separator: "/").last ?? "")]" }
        lines.append("\(p.profile)  \(p.maskedKeyId)\(status)\(mfa)\(missing)  \(session)  used \(ago(p.lastUsedAt))\(p.lastRequester.map { " by \($0)" } ?? "")")
    }
    for f in findings { lines.append("PLAINTEXT  \(f.profile)  \(maskKeyId(f.accessKeyId))  \(f.file)") }
    done(ListResult(profiles: profiles, plaintext: findings), lines.joined(separator: "\n"))
}

func cmdCredentialProcess() {
    let profile = requireProfile()
    do {
        let c = try makeVault().credentials(for: profile, requester: Requester.describe(), asker: Requester.summary())
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
    let c = try makeVault().credentials(for: profile, requester: Requester.describe(pid: getpid()), asker: Requester.summary(pid: getpid()))
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
    var leftovers: [String] = []
    for p in try legacy.accounts(.master) {
        do {
            // Already sealed by an earlier run whose clean-up was not allowed: only the old
            // copy is left to remove, so there is nothing to read (and no dialog for it).
            if !vault.hasMaster(p) {
                guard let data = try legacy.read(.master, p) else { continue }
                try vault.storeMaster(raw: data, profile: p)
                moved.append(p)
            }
        } catch {
            failed[p] = error.localizedDescription
            continue
        }
        // Deleting needs its own Allow. The key is already safe in the vault, so a refusal
        // leaves an encrypted Keychain copy behind, not a failure.
        if (try? legacy.delete(.master, p)) == nil { leftovers.append(p) }
    }
    for p in (try? legacy.accounts(.session)) ?? [] { try? legacy.delete(.session, p) }
    try? legacy.delete(.auditHead, "head")
    if !moved.isEmpty || !failed.isEmpty {
        try vault.audit.append("keys.migrated", ok: failed.isEmpty, detail: ["moved": moved.joined(separator: ","), "failed": failed.keys.sorted().joined(separator: ","),
                                                                      "oldCopyLeft": leftovers.joined(separator: ",")])
    }
    struct Result: Encodable { let moved: [String]; let failed: [String: String]; let oldCopyLeft: [String] }
    var lines = moved.map { "moved \($0) into the Secure Enclave vault" }
    if !leftovers.isEmpty {
        lines.append("in the vault, old Keychain copy not removed: \(leftovers.joined(separator: ", ")). These are encrypted, not plaintext; "
            + "run migrate again and click Allow, or delete the \"\(legacy.prefix).master\" items in Keychain Access")
    }
    lines += failed.sorted { $0.key < $1.key }.map { "NOT moved \($0.key): \($0.value) (run migrate again and click Allow)" }
    done(Result(moved: moved, failed: failed, oldCopyLeft: leftovers), lines.isEmpty ? "nothing to migrate" : lines.joined(separator: "\n"))
}

func cmdCheckTouchID() throws {
    try DeviceOwnerPresence().confirm("check that Touch ID works for AWS CLI: ZSP (nothing is unlocked)")
    done(["ok": true], "Touch ID works")
}

// MARK: MFA and approval by code

func cmdMFA() throws {
    let profile = requireProfile()
    let vault = makeVault()
    switch opts.rest.first ?? "" {
    case "setup":
        let host = (Host.current().localizedName ?? "mac").lowercased()
        let raw = opts.values["--name"] ?? "aws-cli-zsp-\(host)-\(profile)"
        let name = String(raw.map { $0.isLetter || $0.isNumber || "+=,.@-_".contains($0) ? $0 : "-" }.prefix(64))
        let serial = try vault.setupMFA(profile, deviceName: name)
        done(["profile": profile, "serial": serial], """
            this Mac is now an MFA device for \(profile): \(serial)
            every session it issues carries MFA, still with one Touch ID. Next: aws-cli-zsp mfa enforce --profile \(profile)
            """)
    case "enforce":
        confirm("Make AWS refuse the \(profile) key unless MFA is present? Scripts that use this key directly, not through aws-cli-zsp, stop working.")
        try vault.enforceMFA(profile)
        done(["profile": profile], """
            AWS now refuses the \(profile) key without MFA (inline policy \(Vault.requireMFAPolicyName)); a copy of the key alone is worth nothing.
            To approve from your phone when away from the Mac: aws-cli-zsp remote enable --profile \(profile)
            """)
    default:
        fail("usage: aws-cli-zsp mfa setup|enforce --profile P")
    }
}

func cmdRemote() throws {
    let profile = requireProfile()
    let vault = makeVault()
    switch opts.rest.first ?? "" {
    case "enable":
        let serial = try vault.enableRemote(profile, serial: opts.values["--serial"])
        done(["profile": profile, "serial": serial], """
            away from the Mac, a code from \(serial) approves \(profile):
              aws-cli-zsp approve --profile \(profile) 123456
            Claude Code asks you for the code when it needs one.
            """)
    case "disable":
        try vault.disableRemote(profile)
        done(["profile": profile], "approval by MFA code is off for \(profile): only Touch ID at the Mac unlocks it")
    default:
        fail("usage: aws-cli-zsp remote enable|disable --profile P [--serial ARN]")
    }
}

func cmdApprove() throws {
    let profile = requireProfile()
    guard let code = opts.rest.first else { fail("usage: aws-cli-zsp approve --profile \(profile) CODE (the 6 digits from your MFA app)") }
    let c = try makeVault().approve(profile, code: code, requester: Requester.describe(pid: getpid()))
    let until = c.expiration.map { " until \(clock($0))" } ?? ""
    done(["profile": profile, "expires": c.expiration.map(iso8601) ?? ""], "approved: \(profile) has a session\(until); aws commands with --profile \(profile) now work")
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

// MARK: Setup, checks and tests

/// The first run: which keys move, which stay in plain text, whether the watcher moves new
/// ones by itself, and how long sessions last. The app's setup screen runs this.
func cmdSetup() throws {
    let move = list("--move"), keep = list("--keep")
    var s = Settings.load(paths)
    if let d = opts.values["--duration"] {
        guard let seconds = parseDuration(d), (Settings.minSeconds...Settings.maxSeconds).contains(seconds) else { fail("sessions last 15m to 12h") }
        s.sessionSeconds = seconds
    }
    if let a = opts.values["--auto"] {
        guard ["on", "off"].contains(a) else { fail("--auto on|off") }
        s.autoImport = a == "on"
    }
    s.keepPlaintext = Array(s.kept.union(keep).subtracting(move)).sorted()
    s.onboarded = true
    try s.save(paths)
    let vault = makeVault()
    let report = move.isEmpty ? ImportReport() : try vault.importPlaintext(origin: "aws-cli-zsp setup", only: Set(move))
    let watcher = try setWatcher(s.watching)
    try vault.audit.append("setup.done", detail: ["moved": report.imported.joined(separator: ","), "kept": (s.keepPlaintext ?? []).joined(separator: ","),
                                                  "autoMove": s.autoImport == false ? "off" : "on", "seconds": String(s.sessionSeconds)])
    var lines = report.imported.map { "moved \($0) into the vault" }
    if !(s.keepPlaintext ?? []).isEmpty { lines.append("left in plain text by choice: \((s.keepPlaintext ?? []).joined(separator: ", "))") }
    lines.append(s.watching ? "new keys written to ~/.aws are moved in automatically (\(watcher))" : "new keys are NOT moved automatically: the menu bar shows them in red")
    lines.append("sessions last \(s.sessionSeconds / 60) minutes")
    done(report, lines.joined(separator: "\n"))
}

/// Loads or unloads the watcher agent. Returns what it did.
@discardableResult
func setWatcher(_ on: Bool) throws -> String {
    // A sandbox (ZSP_HOME set) must never replace or stop the real login watcher.
    if ProcessInfo.processInfo.environment["ZSP_HOME"] != nil { return "watcher left alone: ZSP_HOME is set (sandbox)" }
    if !on {
        _ = launchctl(["bootout", "gui/\(getuid())/\(watchLabel)"])
        return "watcher stopped"
    }
    guard selfPath().contains(".app/Contents/Helpers/") else { return "watcher not loaded: run from the app bundle" }
    try loadWatcher(bin: selfPath())
    return "watcher running"
}

struct Check: Encodable {
    let name: String
    let ok: Bool
    let detail: String
    /// Not a failure, but worth knowing (auto-move off, nobody at the Mac).
    var warn = false
}

func agentLoaded(_ label: String) -> Bool { launchctl(["print", "gui/\(getuid())/\(label)"]) == 0 }

/// Everything that has to be true for aws-cli-zsp to protect you, checked without a prompt.
func cmdDoctor() {
    let vault = makeVault()
    let s = Settings.load(paths)
    let profiles = vault.list()
    var checks: [Check] = []
    checks.append(Check(name: "Secure Enclave", ok: EnclaveStore.isAvailable,
                        detail: EnclaveStore.isAvailable ? "available: keys are sealed to this Mac's chip" : "not available on this Mac"))
    let missing = profiles.filter { $0.inKeychain == false }.map(\.profile)
    checks.append(Check(name: "Keys in the vault", ok: missing.isEmpty && !profiles.isEmpty,
                        detail: profiles.isEmpty ? "no keys yet" : missing.isEmpty ? "\(profiles.count) sealed: \(profiles.map(\.profile).joined(separator: ", "))"
                            : "not in the vault: \(missing.joined(separator: ", ")) (run aws-cli-zsp migrate)"))
    let findings = Scanner.scan(paths)
    let exposed = findings.filter { !s.kept.contains($0.profile) }
    checks.append(Check(name: "No plaintext keys", ok: exposed.isEmpty,
                        detail: exposed.isEmpty ? (findings.isEmpty ? "none in ~/.aws/credentials or ~/.aws/config" : "only the ones you chose to keep: \(findings.map(\.profile).joined(separator: ", "))")
                            : "in plain text: \(exposed.map(\.profile).joined(separator: ", "))", warn: exposed.isEmpty && !findings.isEmpty))
    let text = (try? String(contentsOf: paths.configFile, encoding: .utf8)) ?? ""
    let config = INIDocument(text)
    let bin = selfPath()
    let unwired = profiles.filter { p in
        let cp = config.value("credential_process", in: AWSFiles.configSection(for: p.profile)) ?? ""
        return !cp.contains(bin) || !cp.contains("credential-process")
    }.map(\.profile)
    checks.append(Check(name: "AWS CLI wired to the vault", ok: unwired.isEmpty,
                        detail: unwired.isEmpty ? "every profile's credential_process runs this aws-cli-zsp" : "not wired: \(unwired.joined(separator: ", ")) (run aws-cli-zsp install)"))
    let watcher = agentLoaded(watchLabel)
    checks.append(Check(name: "Automatic move", ok: !s.watching || watcher,
                        detail: !s.watching ? "off: new keys stay where they are written until you move them" : watcher ? "on: the watcher moves new keys within seconds" : "on, but the watcher is not running (run aws-cli-zsp install)",
                        warn: !s.watching))
    checks.append(Check(name: "Menu bar app at login", ok: agentLoaded(menuLabel), detail: agentLoaded(menuLabel) ? "starts at login" : "not set to start at login"))
    let v = AuditLog(paths: paths, anchor: EnclaveStore(dir: paths.supportDir.appendingPathComponent("vault"))).verify()
    checks.append(Check(name: "Audit trail", ok: v.intact, detail: v.intact ? "chain intact, \(v.entries) entries" : "broken: \(v.problem ?? "?")"))
    let here = someoneAtMac()
    checks.append(Check(name: "Someone at the Mac", ok: true,
                        detail: here ? "yes: a new session asks for Touch ID" : "no: a new session fails at once (phone approval or wait)", warn: !here))
    let mfa = profiles.filter { $0.mfaEnforced == true }.map(\.profile)
    checks.append(Check(name: "MFA enforced by AWS", ok: true,
                        detail: mfa.isEmpty ? "not yet for any profile (MFA & phone tab)" : "for \(mfa.joined(separator: ", "))", warn: mfa.isEmpty))
    let failed = checks.filter { !$0.ok }.count
    done(checks, checks.map { "\($0.ok ? ($0.warn ? "!" : "✓") : "✗") \($0.name): \($0.detail)" }.joined(separator: "\n")
         + "\n\(failed == 0 ? "all checks pass" : "\(failed) check(s) failed")")
}

/// A real AWS call with the profile's credentials: Touch ID if there is no session.
func cmdTest() throws {
    let profile = requireProfile()
    let vault = makeVault()
    let hadSession = vault.list().first { $0.profile == profile }?.sessionActive() ?? false
    let c = try vault.credentials(for: profile, requester: Requester.describe(pid: getpid()), asker: "a test from the AWS CLI: ZSP app")
    let identity = try AWSQueryService().getCallerIdentity(c)
    try vault.audit.append("profile.tested", profile: profile, detail: ["arn": identity.arn])
    struct R: Encodable { let profile: String; let arn: String; let account: String; let expires: Date?; let usedCachedSession: Bool }
    done(R(profile: profile, arn: identity.arn, account: identity.account, expires: c.expiration, usedCachedSession: hadSession),
         "\(profile) works: \(identity.arn) (\(hadSession ? "cached session" : "new session"))")
}

/// Writes AWS's documented example key into ~/.aws/credentials and times the watcher moving
/// it, then removes it again. Proves automatic moving works without risking a real key.
func cmdSelfTestWatcher() throws {
    let s = Settings.load(paths)
    let vault = makeVault()
    let profile = Vault.selfTestProfile
    let original = (try? String(contentsOf: paths.credentialsFile, encoding: .utf8)) ?? ""
    var doc = INIDocument(original)
    doc.set("aws_access_key_id", "AKIAIOSFODNN7EXAMPLE", in: profile)
    doc.set("aws_secret_access_key", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", in: profile)
    try writeAtomically(doc.text, to: paths.credentialsFile)
    let start = Date()
    var moved = false
    while Date().timeIntervalSince(start) < (s.watching ? 20 : 3) {
        Thread.sleep(forTimeInterval: 0.5)
        if !Scanner.scan(paths).contains(where: { $0.profile == profile }) { moved = true; break }
    }
    let seconds = Date().timeIntervalSince(start)
    if !moved {
        // Take the example key back out of the file ourselves.
        var d = INIDocument((try? String(contentsOf: paths.credentialsFile, encoding: .utf8)) ?? "")
        d.remove(keys: AWSFiles.secretKeys, in: profile)
        d.removeHeaderIfEmpty(profile)
        try writeAtomically(d.text, to: paths.credentialsFile)
    }
    try vault.removeSelfTest()
    try vault.audit.append("watcher.tested", ok: moved || !s.watching, detail: ["moved": moved ? "yes" : "no", "seconds": String(format: "%.1f", seconds)])
    struct R: Encodable { let moved: Bool; let seconds: Double; let autoMove: Bool }
    let text = moved ? "the watcher moved a test key out of ~/.aws/credentials in \(String(format: "%.1f", seconds)) s (removed again)"
        : s.watching ? "the watcher did NOT move the test key within 20 s: run aws-cli-zsp install" : "automatic move is off, so the test key stayed (removed again)"
    done(R(moved: moved, seconds: seconds, autoMove: s.watching), text)
    if !moved && s.watching { exit(1) }
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

    try loadWatcher(bin: bin)
    var menuLoaded = false
    if FileManager.default.isExecutableFile(atPath: menuBin) {
        try load(menuLabel, ["Label": menuLabel, "ProgramArguments": [menuBin, "--background"], "RunAtLoad": true,
                             "LimitLoadToSessionType": "Aqua", "ProcessType": "Interactive", "EnvironmentVariables": agentEnv()])
        menuLoaded = true
    }
    let rewired = try makeVault().rewire()
    // Before setup has run, nothing moves: the app's setup screen asks first.
    let s = Settings.load(paths)
    let report = s.onboarded == true ? try makeVault().importPlaintext(origin: "aws-cli-zsp install", skip: s.kept) : ImportReport()
    try makeVault().audit.append("zsp.installed", detail: ["binary": bin, "rewired": rewired.joined(separator: ",")])
    var lines = ["installed: watcher \(watchLabel)\(menuLoaded ? ", menu bar app at login" : ""), \(link.path) → \(bin)"]
    lines += report.imported.map { "moved \($0) into the vault" }
    if s.onboarded != true {
        lines.append("next: open AWS CLI: ZSP to choose which keys to move (or aws-cli-zsp setup --move a,b --auto on)")
    } else if report.imported.isEmpty { lines.append("no plaintext keys to move") }
    done(report, lines.joined(separator: "\n"))
}

func agentEnv() -> [String: String] {
    var env: [String: String] = [:]
    for k in ["AWS_SHARED_CREDENTIALS_FILE", "AWS_CONFIG_FILE", "ZSP_HOME"] { env[k] = ProcessInfo.processInfo.environment[k] }
    return env
}

func loadWatcher(bin: String) throws {
    let env = agentEnv()
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
    case "mfa": try cmdMFA()
    case "setup": try cmdSetup()
    case "doctor", "check": cmdDoctor()
    case "test": try cmdTest()
    case "selftest-watcher": try cmdSelfTestWatcher()
    case "remote": try cmdRemote()
    case "approve": try cmdApprove()
    case "uninstall": try cmdUninstall()
    case "version", "--version": print(version)
    case "", "help", "--help", "-h": print(usage)
    default: fail("unknown command \(opts.command)\n\n\(usage)", code: 2)
    }
}
exit(0)
