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

    static func commandLine(_ pid: pid_t) -> String {
        var args = redact(arguments(pid))
        // `python3 /opt/homebrew/bin/aws s3 ls` reads better as `aws s3 ls`.
        if args.count > 1, let first = args.first, (first as NSString).lastPathComponent.hasPrefix("python") {
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

    /// Keeps secrets typed on a command line (`aws configure set aws_secret_access_key …`)
    /// out of the audit log.
    public static func redact(_ args: [String]) -> [String] {
        var out: [String] = []
        var hideNext = false
        for a in args {
            let lower = a.lowercased()
            if hideNext {
                out.append("[redacted]")
                hideNext = false
            } else if lower.contains("secret") || lower.contains("token") || lower.contains("password") {
                if let eq = a.firstIndex(of: "=") {
                    out.append(String(a[...eq]) + "[redacted]")
                } else {
                    out.append(a)
                    hideNext = true
                }
            } else if a.count >= 30, a.allSatisfy({ $0.isLetter || $0.isNumber || "/+=".contains($0) }) {
                out.append("[redacted]")
            } else {
                out.append(a)
            }
        }
        return out
    }
}
