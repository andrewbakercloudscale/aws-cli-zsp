import Foundation
import ZSPCore

// The watcher runs every few seconds and the AWS CLI calls credential-process for every
// command: those log at debug level, everything else says which command ran (never its
// values: profiles yes, codes and keys no).
let quiet = opts.command == "credential-process" || (opts.command == "import" && opts.flags.contains("--auto"))
Log.configure(paths, process: opts.flags.contains("--auto") ? "watcher" : "cli")
let summary = ([opts.command] + opts.values.keys.sorted().map { $0 == "--profile" ? "--profile \(opts.profile ?? "")" : $0 } + opts.flags.sorted()).joined(separator: " ")
if quiet { Log.debug("cli", summary) } else if !opts.command.isEmpty { Log.info("cli", summary) }


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
    case "diagnostics", "support": try cmdDiagnostics()
    case "test": try cmdTest()
    case "selftest-watcher": try cmdSelfTestWatcher()
    case "remote": try cmdRemote()
    case "approve": try cmdApprove()
    case "pin": try cmdPin()
    case "access": try cmdAccess()
    case "uninstall": try cmdUninstall()
    case "version", "--version": print(version)
    case "", "help", "--help", "-h": print(usage)
    default: fail("unknown command \(opts.command)\n\n\(usage)", code: 2)
    }
}
exit(0)
