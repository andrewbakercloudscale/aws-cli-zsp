import Darwin
import Foundation
import ZSPCore

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
    // A file that cannot be read may hold keys: never report it as clean.
    let unreadable = Scanner.unreadable(paths)
    if !unreadable.isEmpty { fail("cannot read \(unreadable.joined(separator: ", ")) (not UTF-8 text, or no permission), so it was not scanned") }
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
        if let a = p.pinnedAccount { mfa += " [pinned: \(a)]" }
        if p.readOnly { mfa += " [read-only]" }
        else if let d = p.iamDenied, !d.isEmpty, p.access == nil { mfa += " [IAM refuses: \(d.map(\.rawValue).joined(separator: ","))]" }
        lines.append("\(p.profile)  \(p.maskedKeyId)\(status)\(mfa)\(missing)  \(session)  used \(ago(p.lastUsedAt))\(p.lastRequester.map { " by \($0)" } ?? "")")
    }
    for f in findings { lines.append("PLAINTEXT  \(f.profile)  \(maskKeyId(f.accessKeyId))  \(f.file)") }
    done(ListResult(profiles: profiles, plaintext: findings), lines.joined(separator: "\n"))
}

func cmdCredentialProcess() {
    let profile = requireProfile()
    if inSandbox {
        FileHandle.standardError.write(Data("aws-cli-zsp: ZSP_HOME is set, so the vault in \(paths.supportDir.path) is used, without account pins\n".utf8))
    }
    do {
        let c = try makeVault().credentials(for: profile, requester: Requester.describe(), asker: Requester.summary())
        var out: [String: Any] = ["Version": 1, "AccessKeyId": c.accessKeyId, "SecretAccessKey": c.secretAccessKey]
        if let t = c.sessionToken { out["SessionToken"] = t }
        if let e = c.expiration { out["Expiration"] = iso8601(e) }
        let data = try JSONSerialization.data(withJSONObject: out, options: [.sortedKeys])
        FileHandle.standardOutput.write(data)
        exit(0)
    } catch {
        // An error, not a warning: the AWS CLI shows the user nothing else, and Doctor's
        // "Errors in the last day" counts only errors.
        Log.error("credential-process", "\(profile): \(error.localizedDescription)")
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
    try makeVault().audit.append(.settingsDuration, profile: opts.profile, detail: ["seconds": String(seconds)])
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
        try vault.audit.append(.keysMigrated, ok: failed.isEmpty, detail: ["moved": moved.joined(separator: ","), "failed": failed.keys.sorted().joined(separator: ","),
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

func cmdAccess() throws {
    let profile = requireProfile()
    let word = opts.rest.first ?? ""
    let level: AccessLevel?
    switch word {
    case "read-only", "readonly": level = .readOnly
    case "full": level = .full
    case "auto": level = nil
    default: fail("usage: aws-cli-zsp access --profile P read-only|full|auto")
    }
    try makeVault().setAccess(profile, level)
    let text: String
    switch level {
    case .readOnly?: text = "\(profile) is read-only: rotate, revoke and MFA are not offered; sessions work as normal"
    case .full?: text = "\(profile): rotate, revoke and MFA are offered again"
    case nil: text = "\(profile): offered again until IAM refuses (Check in AWS asks IAM first)"
    }
    done(["profile": profile, "access": level?.rawValue ?? "auto"], text)
}

func cmdPin() throws {
    let profile = requireProfile()
    let vault = makeVault()
    switch opts.rest.first ?? "show" {
    case "show":
        guard let p = try vault.pin(profile) else {
            done(["profile": profile], vault.pins == nil ? "pinning is off (ZSP_HOME is set)" : "\(profile) is not pinned yet: its next session pins it")
            return
        }
        done(p, "\(profile) is pinned to \(p.arn) (account \(p.account)) since \(clock(p.pinnedAt))")
    case "reset":
        try vault.resetPin(profile)
        done(["profile": profile], "pin removed: the next session for \(profile) pins whatever account its key is in")
    default:
        fail("usage: aws-cli-zsp pin show|reset --profile P")
    }
}

func cmdApprove() throws {
    let profile = requireProfile()
    guard let code = opts.rest.first else { fail("usage: aws-cli-zsp approve --profile \(profile) CODE (the 6 digits from your MFA app)") }
    // The code is spent once used, but it still stays out of the audit trail and the support log.
    let requester = Requester.describe(pid: getpid()).replacingOccurrences(of: code, with: "[code]")
    let c = try makeVault().approve(profile, code: code, requester: requester)
    let until = c.expiration.map { " until \(clock($0))" } ?? ""
    done(["profile": profile, "expires": c.expiration.map(iso8601) ?? ""], "approved: \(profile) has a session\(until); aws commands with --profile \(profile) now work")
}
