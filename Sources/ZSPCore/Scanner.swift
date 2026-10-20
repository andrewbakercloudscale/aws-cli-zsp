import Foundation

/// A plaintext key found in an AWS file.
public struct Finding: Codable, Equatable, Sendable {
    public var file: String
    public var profile: String
    public var accessKeyId: String
    /// Both the key id and the secret are there. An incomplete pair is mid-write
    /// (`aws configure set` writes one line at a time) and is picked up on the next pass.
    public var complete: Bool
}

/// The key lines of one section of an AWS file.
struct PlaintextKey {
    var id: String
    var secret: String
    var token: String

    var isEmpty: Bool { id.isEmpty && secret.isEmpty && token.isEmpty }
    var complete: Bool { !id.isEmpty && !secret.isEmpty }
}

extension INIDocument {
    /// Each profile in this file that has any key line, by profile name.
    func plaintextKeys(isConfig: Bool) -> [(section: String, profile: String, key: PlaintextKey)] {
        sectionNames.compactMap { section in
            guard let profile = isConfig ? AWSFiles.profileName(configSection: section) : section else { return nil }
            let key = PlaintextKey(id: value("aws_access_key_id", in: section) ?? "",
                                   secret: value("aws_secret_access_key", in: section) ?? "",
                                   token: value("aws_session_token", in: section) ?? value("aws_security_token", in: section) ?? "")
            return key.isEmpty ? nil : (section, profile, key)
        }
    }
}

/// Reads the AWS files for plaintext keys. Needs no Keychain access, so the menu bar app
/// runs it itself.
public enum Scanner {
    public static func scan(_ paths: Paths) -> [Finding] {
        [(paths.configFile, true), (paths.credentialsFile, false)].flatMap { url, isConfig -> [Finding] in
            guard let text = try? String(contentsOf: url, encoding: .utf8) else { return [] }
            return INIDocument(text).plaintextKeys(isConfig: isConfig).map {
                Finding(file: url.path, profile: $0.profile, accessKeyId: $0.key.id, complete: $0.key.complete)
            }
        }
    }
}
