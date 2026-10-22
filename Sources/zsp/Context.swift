import CoreGraphics
import Darwin
import Foundation
import ZSPCore

/// The real path of this binary: what credential_process lines and launch agents point at.
func selfPath() -> String {
    var buf = [CChar](repeating: 0, count: 4096)
    let path = proc_pidpath(getpid(), &buf, UInt32(buf.count)) > 0 ? String(cString: buf) : CommandLine.arguments[0]
    return URL(fileURLWithPath: path).resolvingSymlinksInPath().path
}

let paths = Paths.standard()

/// ZSP_HOME points the app at another folder (a demo or a test): the login Keychain, the
/// real watcher and the real login item are left alone.
let inSandbox = ProcessInfo.processInfo.environment["ZSP_HOME"] != nil

/// An IAM MFA device name: letters, digits and +=,.@-_ only, at most 64 characters.
func deviceName(_ raw: String) -> String {
    String(raw.map { $0.isLetter || $0.isNumber || "+=,.@-_".contains($0) ? $0 : "-" }.prefix(64))
}

func makeVault() -> Vault {
    // Sealed to the Secure Enclave under ZSP_HOME, so a sandbox (another ZSP_HOME) is separate.
    let store = EnclaveStore(dir: paths.supportDir.appendingPathComponent("vault"))
    let presence = DeviceOwnerPresence(enclaveGated: true)
    store.context = { presence.context }
    let vault = Vault(paths: paths, store: store, auth: presence, aws: AWSQueryService(), commandPath: selfPath())
    vault.someoneAtMac = someoneAtMac
    // Pins live in the login Keychain, outside the vault folder. A sandbox has none.
    if !inSandbox {
        vault.pins = KeychainStore()
        store.keyPins = vault.pins
    }
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
