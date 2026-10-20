import Foundation
import ZSPCore

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
    try vault.audit.append(.setupDone, detail: ["moved": report.imported.joined(separator: ","), "kept": (s.keepPlaintext ?? []).joined(separator: ","),
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
    if inSandbox { return "watcher left alone: ZSP_HOME is set (sandbox)" }
    if !on {
        _ = launchctl(["bootout", "gui/\(getuid())/\(watchLabel)"])
        return "watcher stopped"
    }
    guard selfPath().contains(".app/Contents/Helpers/") else { return "watcher not loaded: run from the app bundle" }
    try loadWatcher(bin: selfPath())
    return "watcher running"
}

/// Everything that has to be true for aws-cli-zsp to protect you, checked without a prompt.
func doctorChecks(network: Bool = true) -> [Check] {
    var probes = DoctorProbes(binary: selfPath(), watcherLoaded: { agentLoaded(watchLabel) }, menuAtLogin: { agentLoaded(menuLabel) },
                              someoneAtMac: someoneAtMac, pins: inSandbox ? nil : KeychainStore())
    probes.network = network && !opts.flags.contains("--offline")
    return Doctor(vault: makeVault(), probes: probes).run()
}

func cmdDoctor() {
    let checks = doctorChecks()
    let failed = checks.filter { !$0.ok }
    if !failed.isEmpty { Log.warning("doctor", "failed: \(failed.map(\.name).joined(separator: ", "))") }
    done(checks, checks.map { "\($0.symbol) \($0.name): \($0.detail)" }.joined(separator: "\n")
         + "\n\(failed.isEmpty ? "all checks pass" : "\(failed.count) check(s) failed")")
}

/// A redacted report for support: checks, settings, profiles, the support log and the audit
/// trail, with no secret in it.
func cmdDiagnostics() throws {
    let url = opts.values["--output"].map { URL(fileURLWithPath: ($0 as NSString).expandingTildeInPath) } ?? SupportReport.defaultURL()
    try SupportReport(version: version, checks: doctorChecks(), vault: makeVault()).write(to: url)
    done(["file": url.path], "wrote \(url.path): secrets removed, safe to attach to a support request")
}

/// A real AWS call with the profile's credentials: Touch ID if there is no session.
func cmdTest() throws {
    let profile = requireProfile()
    let vault = makeVault()
    let hadSession = vault.list().first { $0.profile == profile }?.sessionActive() ?? false
    let c = try vault.credentials(for: profile, requester: Requester.describe(pid: getpid()), asker: "a test from the AWS CLI: ZSP app")
    let identity = try AWSQueryService().getCallerIdentity(c)
    try vault.audit.append(.profileTested, profile: profile, detail: ["arn": identity.arn])
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
    try vault.audit.append(.watcherTested, ok: moved || !s.watching, detail: ["moved": moved ? "yes" : "no", "seconds": String(format: "%.1f", seconds)])
    struct R: Encodable { let moved: Bool; let seconds: Double; let autoMove: Bool }
    let text = moved ? "the watcher moved a test key out of ~/.aws/credentials in \(String(format: "%.1f", seconds)) s (removed again)"
        : s.watching ? "the watcher did NOT move the test key within 20 s: run aws-cli-zsp install" : "automatic move is off, so the test key stayed (removed again)"
    done(R(moved: moved, seconds: seconds, autoMove: s.watching), text)
    if !moved && s.watching { exit(1) }
}
