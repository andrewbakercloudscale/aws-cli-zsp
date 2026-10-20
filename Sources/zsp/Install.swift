import Foundation
import ZSPCore

// MARK: Install

let watchLabel = "consulting.cloudscale.zsp.watch"
let menuLabel = "consulting.cloudscale.zsp.menu"
let agentsDir = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/LaunchAgents")

func agentLoaded(_ label: String) -> Bool { launchctl(["print", "gui/\(getuid())/\(label)"]) == 0 }

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
    try makeVault().audit.append(.installed, detail: ["binary": bin, "rewired": rewired.joined(separator: ",")])
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
    _ = try? makeVault().audit.append(.uninstalled, detail: ["restored": restored.joined(separator: ",")])
    done(restored, restored.isEmpty
        ? "agents removed; keys stay in the vault and profiles still use aws-cli-zsp (remove the app last, or run with --restore-plaintext)"
        : "agents removed; wrote \(restored.joined(separator: ", ")) back to \(paths.credentialsFile.path)")
}
