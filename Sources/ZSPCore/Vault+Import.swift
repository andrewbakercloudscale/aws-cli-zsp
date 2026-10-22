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
            let credsText = try paths.text(paths.credentialsFile)
            let configText = try paths.text(paths.configFile)
            var creds = INIDocument(credsText)
            var config = INIDocument(configText)

            // Config first: when both files hold a key, the credentials file wins in the AWS
            // CLI, so it must win here too.
            let wanted: (String) -> Bool = { p in !skip.contains(p) && (only?.contains(p) ?? true) }
            let sealedFromConfig = Dictionary(config.plaintextKeys(isConfig: true).map { ($0.profile, $0.key) }, uniquingKeysWith: { _, b in b })
            let sealedFromCreds = Dictionary(creds.plaintextKeys(isConfig: false).map { ($0.profile, $0.key) }, uniquingKeysWith: { _, b in b })
            let fromConfig = try extract(&config, isConfig: true, file: paths.configFile, origin: origin, wanted: wanted, report: &report)
            let fromCreds = try extract(&creds, isConfig: false, file: paths.credentialsFile, origin: origin, wanted: wanted, report: &report)
            // Sealing takes a moment, and `aws configure` may have written a file meanwhile: its
            // change is kept, and only the key lines just sealed are taken out of the file as it is now.
            if let latest = try changedSince(configText, paths.configFile) {
                config = INIDocument(latest)
                dropMoved(&config, isConfig: true, Set(fromConfig), sealedFromConfig)
            }
            if let latest = try changedSince(credsText, paths.credentialsFile) {
                creds = INIDocument(latest)
                dropMoved(&creds, isConfig: false, Set(fromCreds), sealedFromCreds)
            }
            let configNow = try paths.text(paths.configFile)
            let credsNow = try paths.text(paths.credentialsFile)
            wire(fromConfig + fromCreds, in: &config)
            if config.text != configNow {
                try writeAtomically(config.text, to: paths.configFile)
            }
            if creds.text != credsNow {
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

    /// The file's text now, when it is no longer `text`.
    func changedSince(_ text: String, _ url: URL) throws -> String? {
        let now = try paths.text(url)
        return now == text ? nil : now
    }

    /// Takes the key lines of `moved` out of `doc`, where they still hold the key that was sealed.
    func dropMoved(_ doc: inout INIDocument, isConfig: Bool, _ moved: Set<String>, _ sealed: [String: PlaintextKey]) {
        for (section, profile, key) in doc.plaintextKeys(isConfig: isConfig) where moved.contains(profile) && sealed[profile] == key {
            doc.remove(keys: AWSFiles.secretKeys, in: section)
            if !isConfig { doc.removeHeaderIfEmpty(section) }
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
        var previous = meta.all()[profile]
        var recovered: MasterKey?
        if previous == nil, hasMaster(profile) {
            // profiles.json lost the entry (it was damaged and started again): which key is
            // sealed, and whether it carries this Mac's MFA seed, is only known by opening it.
            let sealed = try unlock(profile, reason: "replace the AWS key stored for profile “\(profile)”")
            recovered = sealed
            previous = ProfileMeta(profile: profile, accessKeyId: sealed.accessKeyId, importedAt: sealed.importedAt,
                                   source: sealed.source, temporary: sealed.sessionToken != nil)
        }
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
            if let recovered, !changed { e.mfaSerial = recovered.mfaSerial }
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
