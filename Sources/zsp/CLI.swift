import Darwin
import Foundation
import ZSPCore

let version = "0.3.3"

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
  aws-cli-zsp mfa add-phone --profile P        a QR code for your authenticator app (Google Authenticator etc.)
  aws-cli-zsp mfa confirm-phone --profile P --serial ARN CODE1 CODE2   enable it and allow phone approval
  aws-cli-zsp remote enable --profile P [--serial ARN]   phone approval with a device already in IAM
  aws-cli-zsp approve --profile P CODE         issue a session with that code, no Touch ID
  aws-cli-zsp remote disable --profile P
  aws-cli-zsp mfa unenforce --profile P        undo: the key works without MFA again
  aws-cli-zsp mfa remove --profile P           undo all of it: this Mac's MFA device is deleted from AWS

Rotate and revoke
  aws-cli-zsp rotate --profile P [--keep-old]  new key, verified, old one deleted (or deactivated)
  aws-cli-zsp revoke-sessions --profile P      invalidate every session issued so far, in AWS
  aws-cli-zsp clear-sessions [--profile P]     drop cached sessions on this Mac
  aws-cli-zsp disable-key --profile P          deactivate the key in AWS (re-enable in the IAM console)
  aws-cli-zsp delete-key --profile P           delete the key in AWS and on this Mac
  aws-cli-zsp forget --profile P               remove the key from this Mac only

Client keys (read-only IAM users)
  aws-cli-zsp access --profile P read-only|full|auto   hide or offer rotate, revoke and MFA (auto: what IAM allows)

Account pinning (a key swapped for one to another account is refused)
  aws-cli-zsp pin show --profile P             the account and user the profile is pinned to
  aws-cli-zsp pin reset --profile P            after you changed the key to another account yourself

Setup and tests
  aws-cli-zsp setup [--move a,b] [--keep c] [--auto on|off] [--duration 1h]   first run: what moves, what stays, auto-move
  aws-cli-zsp import [--profiles a,b] [--all]   move keys now (profiles kept in plain text stay unless named or --all)
  aws-cli-zsp doctor                           check everything, with no prompt
  aws-cli-zsp test --profile P                 a real AWS call with the profile (Touch ID if no session)
  aws-cli-zsp diagnostics [--output FILE]      a redacted report for support (default: on the Desktop)
  aws-cli-zsp selftest-watcher                 write AWS's example key to ~/.aws and time the automatic move

Audit and setup
  aws-cli-zsp audit [--limit N] [--verify]     the hash-chained audit trail
  aws-cli-zsp migrate                          move keys stored by 0.1.x into the Secure Enclave vault
  aws-cli-zsp check-touch-id                   show a Touch ID prompt and nothing else
  aws-cli-zsp ui                               open the panel in a window (when the menu bar icon is hidden)
  aws-cli-zsp install                          watcher, menu bar app at login, ~/.local/bin/aws-cli-zsp, first import
  aws-cli-zsp uninstall [--restore-plaintext]  remove the agents; optionally put the keys back in the file

  --json for machine output, --yes to skip confirmations.
  Support log: ~/Library/Application Support/aws-cli-zsp/logs/aws-cli-zsp.log (ZSP_DEBUG=1 for more detail).
"""

// MARK: Arguments

struct Options {
    var command = ""
    var values: [String: String] = [:]
    var flags: Set<String> = []
    var rest: [String] = []

    static let takesValue: Set<String> = ["--profile", "--limit", "--access-key-id", "--serial", "--name", "--profiles", "--move", "--keep", "--auto", "--duration", "--output"]

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
    Log.error("cli", "\(opts.command.isEmpty ? "aws-cli-zsp" : opts.command) failed: \(message)")
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

func run(_ body: () throws -> Void) {
    do { try body() } catch { fail(error.localizedDescription) }
}

func list(_ key: String) -> [String] {
    (opts.values[key] ?? "").split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
}
