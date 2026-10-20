import Foundation

/// This Mac only: removing keys, rewiring ~/.aws/config, and the way back to plain text.
extension Vault {
    /// Removes the key from this Mac only. AWS still has it.
    public func forget(_ profile: String) throws {
        let master = try unlock(profile, reason: "remove the AWS key for profile “\(profile)” from this Mac")
        try audit.append(.keyForgotten, profile: profile, detail: ["keyId": maskKeyId(master.accessKeyId)])
        try removeLocal(profile)
    }

    /// Everything this Mac holds for the profile: the key, its session and remote copy, its
    /// metadata, its account pin and its credential_process line.
    func removeLocal(_ profile: String) throws {
        try store.delete(.master, profile)
        try store.delete(.session, profile)
        try store.delete(.remote, profile)
        try meta.update(profile) { $0 = nil }
        try editConfig { config in
            let section = AWSFiles.configSection(for: profile)
            guard let cp = config.value("credential_process", in: section), isOurs(cp) else { return }
            config.remove(keys: ["credential_process"], in: section)
            config.removeHeaderIfEmpty(section)
        }
        dropPin(profile)
    }

    /// Points every profile in the vault at this binary, and refreshes the hint at the top of
    /// the credentials file. For when the binary moves (a rename, a new install location).
    public func rewire() throws -> [String] {
        let profiles = Set(try store.accounts(.master)).union(meta.all().keys).sorted()
        try editConfig { wire(profiles, in: &$0) }
        let creds = paths.text(paths.credentialsFile)
        if creds.contains("`zsp add") {
            try writeAtomically(creds.replacingOccurrences(of: "`zsp add", with: "`aws-cli-zsp add")
                .replacingOccurrences(of: "`zsp list`", with: "`aws-cli-zsp list`"), to: paths.credentialsFile)
        }
        Log.info("install", "pointed \(profiles.count) profile(s) at \(commandPath)")
        return profiles
    }

    /// The watcher self-test's profile: a documented AWS example key, never a real one.
    public static let selfTestProfile = "aws-cli-zsp-selftest"
    public static let selfTestKeyId = "[APIKEY-2]"

    /// Removes the self-test profile without Touch ID: its key is AWS's published example.
    public func removeSelfTest() throws {
        guard let m = meta.all()[Self.selfTestProfile], m.accessKeyId == Self.selfTestKeyId else { return }
        try removeLocal(Self.selfTestProfile)
    }

    /// Writes every key back into the credentials file and drops zsp's wiring: the way out
    /// before uninstalling. The watcher must be stopped first or it moves them straight back.
    public func restorePlaintext() throws -> [String] {
        let profiles = try store.accounts(.master)
        guard !profiles.isEmpty else { return [] }
        try auth.confirm("write \(profiles.count) AWS key(s) back to \(paths.credentialsFile.lastPathComponent) in plain text")
        var creds = INIDocument(paths.text(paths.credentialsFile))
        for profile in profiles {
            guard let data = try store.read(.master, profile) else { continue }
            let key = try decodeKey(data, profile)
            creds.set("aws_access_key_id", key.accessKeyId, in: profile)
            creds.set("aws_secret_access_key", key.secretAccessKey, in: profile)
            if let token = key.sessionToken { creds.set("aws_session_token", token, in: profile) }
        }
        try writeAtomically(creds.text, to: paths.credentialsFile)
        for profile in profiles {
            try audit.append(.keyRestored, profile: profile)
            try removeLocal(profile)
        }
        Log.info("install", "wrote \(profiles.count) key(s) back to the credentials file")
        return profiles
    }
}
