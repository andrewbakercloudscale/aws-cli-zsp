import Foundation

extension Vault {
    /// Moves every complete key pair out of both AWS files into the vault and points the
    /// profile at zsp. The vault write is read back before a line is removed from a file, so a
    /// failure leaves the key where it was, never nowhere.
    /// `only` limits the move to those profiles; `skip` leaves those where they are.
    public func importPlaintext(origin: String, only: Set<String>? = nil, skip: Set<String> = []) throws -> ImportReport {
        try paths.ensureSupportDir()
        return try withFileLock(paths.lock("import")) {
            var report = ImportReport()
            let credsText = paths.text(paths.credentialsFile)
            let configText = paths.text(paths.configFile)
            var creds = INIDocument(credsText)
            var config = INIDocument(configText)

            // Config first: when both files hold a key, the credentials file wins in the AWS
            // CLI, so it must win here too.
            let wanted: (String) -> Bool = { p in !skip.contains(p) && (only?.contains(p) ?? true) }
            let fromConfig = try extract(&config, isConfig: true, file: paths.configFile, origin: origin, wanted: wanted, report: &report)
            let fromCreds = try extract(&creds, isConfig: false, file: paths.credentialsFile, origin: origin, wanted: wanted, report: &report)
            wire(fromConfig + fromCreds, in: &config)
            if config.text != configText {
                try writeAtomically(config.text, to: paths.configFile)
            }
            if creds.text != credsText {
                if !creds.text.contains(AWSFiles.managedMarker) {
                    creds.prepend(comments: [
                        "\(AWSFiles.managedMarker): access keys written here are moved into the Secure Enclave vault within seconds.",
                        "# Add keys with `aws-cli-zsp add --profile NAME` (or keep using `aws configure`); see `aws-cli-zsp list`.",
                    ])
                }
                try writeAtomically(creds.text, to: paths.credentialsFile)
            }
            if !report.imported.isEmpty { Log.info("import", "moved \(report.imported.joined(separator: ", ")) (by \(origin))") }
            return report
        }
    }

    func extract(_ doc: inout INIDocument, isConfig: Bool, file: URL, origin: String, wanted: (String) -> Bool,
                 report: inout ImportReport) throws -> [String] {
        var moved: [String] = []
        for (section, profile, key) in doc.plaintextKeys(isConfig: isConfig) where wanted(profile) {
            guard key.complete else {
                report.incomplete.append(Finding(file: file.path, profile: profile, accessKeyId: key.id, complete: false))
                continue
            }
            let master = MasterKey(accessKeyId: key.id, secretAccessKey: key.secret, sessionToken: key.token.isEmpty ? nil : key.token,
                                   importedAt: now(), source: file.lastPathComponent)
            let replaced = try adopt(master, profile: profile, event: .keyImported, origin: origin)
            doc.remove(keys: AWSFiles.secretKeys, in: section)
            if !isConfig { doc.removeHeaderIfEmpty(section) }
            moved.append(profile)
            report.imported.append(profile)
            if replaced { report.replaced.append(profile) }
        }
        return moved
    }

    /// Stores a key for `profile`. Returns whether it replaced a different key.
    @discardableResult
    func adopt(_ key: MasterKey, profile: String, event: AuditEvent, origin: String) throws -> Bool {
        let previous = meta.all()[profile]
        let changed = previous.map { $0.accessKeyId != key.accessKeyId } ?? false
        // The same key again (pasted twice) keeps the sealed copy, and with it this Mac's MFA
        // seed. A different key drops the MFA set-up and the remote copy: they belonged to the old one.
        if changed || previous == nil || !hasMaster(profile) { try store.write(.master, profile, try ZSPJSON.encoder.encode(key)) }
        if changed { try store.delete(.remote, profile) }
        if changed || previous == nil { try store.delete(.session, profile) }
        try meta.update(profile) { m in
            var e = m ?? ProfileMeta(profile: profile, accessKeyId: key.accessKeyId, importedAt: key.importedAt,
                                     source: key.source, temporary: key.sessionToken != nil)
            if changed {
                e = ProfileMeta(profile: profile, accessKeyId: key.accessKeyId, importedAt: key.importedAt, source: key.source,
                                temporary: key.sessionToken != nil, previousKeyId: previous?.accessKeyId)
            }
            e.importedAt = key.importedAt
            e.source = key.source
            e.temporary = key.sessionToken != nil
            if changed || previous == nil { e.sessionExpiresAt = nil }
            m = e
        }
        var detail = ["keyId": maskKeyId(key.accessKeyId), "from": key.source, "by": origin]
        if changed, let p = previous { detail["replaced"] = maskKeyId(p.accessKeyId) }
        if key.sessionToken != nil { detail["temporary"] = "true" }
        try audit.append(event, profile: profile, detail: detail)
        return changed
    }

    /// Adds a key typed at the prompt, so it never touches a file at all.
    public func add(profile: String, accessKeyId: String, secretAccessKey: String, sessionToken: String? = nil) throws {
        try paths.ensureSupportDir()
        try withFileLock(paths.lock("import")) {
            try adopt(MasterKey(accessKeyId: accessKeyId, secretAccessKey: secretAccessKey, sessionToken: sessionToken,
                                importedAt: now(), source: "aws-cli-zsp add"),
                      profile: profile, event: .keyAdded, origin: "aws-cli-zsp add")
            try editConfig { wire([profile], in: &$0) }
        }
        Log.info("import", "added a key for \(profile)")
    }
}
