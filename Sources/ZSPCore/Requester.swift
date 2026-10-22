import Darwin
import Foundation

/// Who asked for credentials: the process that ran zsp and its parent, so the audit log says
/// "aws s3 ls ← zsh" rather than just "a session was issued".
public enum Requester {
    public static func describe(pid: pid_t = getppid()) -> String {
        var parts: [String] = []
        var current = pid
        for _ in 0..<2 {
            guard current > 1 else { break }
            parts.append("\(commandLine(current)) [\(current)]")
            guard let parent = parentPid(current) else { break }
            current = parent
        }
        return parts.isEmpty ? "unknown" : parts.joined(separator: " ← ")
    }

    /// The short form for a Touch ID dialog: "aws sts get-caller-identity, from Claude Code".
    /// The full chain, with arguments and pids, stays in the audit log.
    public static func summary(pid: pid_t = getppid()) -> String {
        let command = shortCommand(redact(arguments(pid)))
        var current = parentPid(pid)
        for _ in 0..<8 {
            guard let p = current, p > 1 else { break }
            if let origin = origin(p) { return "\(command), from \(origin)" }
            current = parentPid(p)
        }
        return command
    }

    static let shells: Set<String> = ["zsh", "bash", "sh", "fish", "dash", "login", "env", "sudo", "tmux", "screen", "node"]

    /// The program name and its leading subcommands: `aws s3 cp /a s3://b` is `aws s3 cp`.
    static func shortCommand(_ argv: [String]) -> String {
        var args = argv
        if args.count > 1, let first = args.first, (first as NSString).lastPathComponent.lowercased().hasPrefix("python") {
            args.removeFirst()
        }
        guard let first = args.first else { return "an unknown program" }
        var words = [(first as NSString).lastPathComponent]
        for a in args.dropFirst() {
            if a.hasPrefix("-") || a.contains("/") || a.contains("=") || words.count == 3 { break }
            words.append(a)
        }
        return words.joined(separator: " ")
    }

    /// What a person would recognise as the source: an app ("Terminal"), Claude Code, or the
    /// script a shell is running ("backup-s3.sh"). Plain interactive shells are skipped.
    static func origin(_ pid: pid_t) -> String? {
        if let path = executablePath(pid), let r = path.range(of: ".app/Contents/MacOS/") {
            let app = (String(path[..<r.lowerBound]) as NSString).lastPathComponent
            return app == "Electron" ? nil : app
        }
        let argv = arguments(pid)
        guard let first = argv.first else { return nil }
        let name = (first as NSString).lastPathComponent.trimmingCharacters(in: CharacterSet(charactersIn: "-"))
        if name == "claude" || argv.contains(where: { $0.hasSuffix("/claude") || $0.contains("claude-code") }) { return "Claude Code" }
        if shells.contains(name) {
            // `bash backup-s3.sh` is the script; `zsh -c …` and a login shell are not.
            if argv.count > 1, !argv[1].hasPrefix("-") { return (argv[1] as NSString).lastPathComponent }
            return nil
        }
        return name
    }

    static func commandLine(_ pid: pid_t) -> String {
        var args = redact(arguments(pid))
        // `python3 /opt/homebrew/bin/aws s3 ls` reads better as `aws s3 ls`.
        if args.count > 1, let first = args.first, (first as NSString).lastPathComponent.lowercased().hasPrefix("python") {
            args.removeFirst()
        }
        if args.isEmpty, let path = executablePath(pid) { args = [path] }
        guard !args.isEmpty else { return "pid" }
        args[0] = (args[0] as NSString).lastPathComponent
        let line = args.joined(separator: " ")
        return line.count > 120 ? String(line.prefix(117)) + "..." : line
    }

    static func executablePath(_ pid: pid_t) -> String? {
        var buf = [CChar](repeating: 0, count: 4096)
        return proc_pidpath(pid, &buf, UInt32(buf.count)) > 0 ? String(cString: buf) : nil
    }

    static func parentPid(_ pid: pid_t) -> pid_t? {
        var info = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.size)
        guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size) == size else { return nil }
        return pid_t(info.pbi_ppid)
    }

    /// argv of another process, from KERN_PROCARGS2: argc, the exec path, padding, then argv.
    static func arguments(_ pid: pid_t) -> [String] {
        var argmax: Int32 = 0
        var size = MemoryLayout<Int32>.size
        var mib: [Int32] = [CTL_KERN, KERN_ARGMAX]
        guard sysctl(&mib, 2, &argmax, &size, nil, 0) == 0, argmax > 0 else { return [] }
        var buf = [UInt8](repeating: 0, count: Int(argmax))
        size = buf.count
        mib = [CTL_KERN, KERN_PROCARGS2, pid]
        guard sysctl(&mib, 3, &buf, &size, nil, 0) == 0, size > 4 else { return [] }
        let argc = buf.withUnsafeBytes { $0.load(as: Int32.self) }
        var i = 4
        while i < size, buf[i] != 0 { i += 1 }   // exec path
        while i < size, buf[i] == 0 { i += 1 }   // padding
        var args: [String] = []
        while args.count < argc, i < size {
            let start = i
            while i < size, buf[i] != 0 { i += 1 }
            args.append(String(decoding: buf[start..<i], as: UTF8.self))
            i += 1
        }
        return args
    }

    static let keyId = try! NSRegularExpression(pattern: "\\b(AKIA|ASIA)[A-Z0-9]{16}\\b")

    /// Keeps secrets typed on a command line (`aws configure set aws_secret_access_key …`)
    /// out of the audit log.
    public static func redact(_ args: [String]) -> [String] {
        var out: [String] = []
        var hideNext = false
        for raw in args {
            let a = maskKeyIds(raw)
            let lower = a.lowercased()
            if hideNext {
                out.append("[redacted]")
                hideNext = false
            } else if lower.contains("secret") || lower.contains("token") || lower.contains("password") {
                if a.allSatisfy({ $0.isLetter || $0.isNumber || "-_.".contains($0) }) {
                    // A name (`aws_secret_access_key`, `--session-token`): the value follows it.
                    out.append(a)
                    hideNext = true
                } else if let eq = a.firstIndex(of: "="), a[..<eq].allSatisfy({ $0.isLetter || $0.isNumber || "-_.".contains($0) }) {
                    out.append(String(a[...eq]) + "[redacted]")
                } else {
                    // The secret is inside the argument itself (`{"SecretAccessKey": …}`).
                    out.append("[redacted]")
                }
            } else if a.count >= 30, a.allSatisfy({ $0.isLetter || $0.isNumber || "/+=".contains($0) }) {
                out.append("[redacted]")
            } else {
                out.append(a)
            }
        }
        return out
    }

    /// An access key id is not a secret, but the audit trail shows it masked everywhere else.
    static func maskKeyIds(_ s: String) -> String {
        var out = s
        for m in keyId.matches(in: s, range: NSRange(s.startIndex..., in: s)).reversed() {
            guard let r = Range(m.range, in: out) else { continue }
            out.replaceSubrange(r, with: maskKeyId(String(out[r])))
        }
        return out
    }
}
