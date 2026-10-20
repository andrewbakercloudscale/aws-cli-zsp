import Foundation
import ZSPCore

/// The app never opens the vault itself: it runs the aws-cli-zsp helper and reads its --json
/// output.
enum CLI {
    /// The CLI is a helper app inside this bundle, so macOS names it "AWS CLI: ZSP" in Touch ID
    /// and Keychain dialogs. It is the only thing that opens the vault.
    static var path: String {
        let helper = Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/aws-cli-zsp.app/Contents/MacOS/aws-cli-zsp")
        if FileManager.default.isExecutableFile(atPath: helper.path) { return helper.path }
        // swift run: the CLI is built next to the app.
        let dir = Bundle.main.executableURL?.deletingLastPathComponent() ?? URL(fileURLWithPath: CommandLine.arguments[0]).deletingLastPathComponent()
        return dir.appendingPathComponent("zsp").path
    }

    struct Result {
        var status: Int32
        var out: Data
        var err: String
    }

    /// Runs the CLI and waits. Both pipes are read at once: reading stdout to the end first
    /// would hang for good once the CLI filled the stderr pipe (64 KB) and blocked on it.
    static func exec(_ path: String, _ args: [String]) -> Result {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: path)
        p.arguments = args
        let out = Pipe(), err = Pipe()
        p.standardOutput = out
        p.standardError = err
        p.standardInput = FileHandle.nullDevice
        do { try p.run() } catch {
            Log.error("menu", "cannot run \(path): \(error.localizedDescription)")
            return Result(status: 127, out: Data(), err: "cannot run aws-cli-zsp: \(error.localizedDescription)")
        }
        final class Box: @unchecked Sendable { var data = Data() }
        let stderr = Box()
        let group = DispatchGroup()
        group.enter()
        DispatchQueue.global().async {
            stderr.data = err.fileHandleForReading.readDataToEndOfFile()
            group.leave()
        }
        let data = out.fileHandleForReading.readDataToEndOfFile()
        group.wait()
        p.waitUntilExit()
        let r = Result(status: p.terminationStatus, out: data, err: String(decoding: stderr.data, as: UTF8.self))
        // The CLI logs its own failures; this is for a crash or a CLI that did not answer in JSON.
        if r.status != 0 && r.out.isEmpty { Log.warning("menu", "\(args.first ?? "aws-cli-zsp") exited \(r.status): \(r.err.prefix(300))") }
        return r
    }

    struct Envelope<T: Decodable>: Decodable {
        let ok: Bool
        let result: T?
        let error: String?
    }

    struct Ignored: Decodable {}

    static func decode<T: Decodable>(_ type: T.Type, _ data: Data) -> T? {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .iso8601
        do { return try d.decode(type, from: data) } catch {
            if !data.isEmpty { Log.warning("menu", "unreadable answer from aws-cli-zsp (\(type)): \(error)") }
            return nil
        }
    }
}
