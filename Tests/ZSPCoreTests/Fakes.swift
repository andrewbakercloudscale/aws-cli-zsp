import Foundation
@testable import ZSPCore

/// An AWS that remembers what it was asked.
final class FakeAWS: AWSService {
    var calls: [String] = []
    var keys: [AccessKeyInfo] = []
    var identity = CallerIdentity(account: "123456789012", arn: "arn:aws:iam::123456789012:user/team/andrew", userId: "AIDAEXAMPLE")
    var sessionCount = 0
    var rejectNewKeyTimes = 0
    var policies: [(user: String, name: String, document: String)] = []
    var failSession: ZSPError?
    var mfaDevices: [String] = []
    var mfaCodes: [MFACode] = []
    var enabled: [(serial: String, code1: String, code2: String)] = []
    let mfaSeed = "JBSWY3DPEHPK3PXP"
    let phoneSeed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    /// IAM actions refused with AccessDenied, as for a client's read-only user.
    var denied: Set<String> = []
    var simulationRefused = false

    func check(_ action: String) throws {
        if denied.contains(action) { throw ZSPError.aws(code: "AccessDenied", message: "not authorized to perform: \(action)") }
    }

    func simulate(_ c: AWSCredentials, principal: String, actions: [String], resource: String,
                  context: [String: String]) throws -> [String: Bool] {
        calls.append("SimulatePrincipalPolicy \(principal)")
        try check("iam:SimulatePrincipalPolicy")
        if simulationRefused { throw ZSPError.aws(code: "AccessDenied", message: "no simulation") }
        return Dictionary(uniqueKeysWithValues: actions.map { ($0, !denied.contains($0)) })
    }

    func getSessionToken(_ c: AWSCredentials, durationSeconds: Int, mfa: MFACode?) throws -> AWSCredentials {
        calls.append("GetSessionToken \(c.accessKeyId) \(durationSeconds)\(mfa.map { " mfa=\($0.serial)" } ?? "")")
        if let mfa { mfaCodes.append(mfa) }
        if let failSession { throw failSession }
        sessionCount += 1
        return AWSCredentials(accessKeyId: "ASIASESSION\(sessionCount)", secretAccessKey: "sessionsecret\(sessionCount)",
                              sessionToken: "token\(sessionCount)", expiration: Date().addingTimeInterval(TimeInterval(durationSeconds)))
    }

    func getCallerIdentity(_ c: AWSCredentials) throws -> CallerIdentity {
        calls.append("GetCallerIdentity \(c.accessKeyId)")
        if c.accessKeyId.hasPrefix("AKIANEW"), rejectNewKeyTimes > 0 {
            rejectNewKeyTimes -= 1
            throw ZSPError.aws(code: "InvalidClientTokenId", message: "not yet")
        }
        return identity
    }

    func listAccessKeys(_ c: AWSCredentials) throws -> [AccessKeyInfo] {
        calls.append("ListAccessKeys \(c.accessKeyId)")
        try check("iam:ListAccessKeys")
        return keys
    }

    func createAccessKey(_ c: AWSCredentials) throws -> AWSCredentials {
        calls.append("CreateAccessKey \(c.accessKeyId)")
        try check("iam:CreateAccessKey")
        let k = AWSCredentials(accessKeyId: "AKIANEWKEY000000001", secretAccessKey: "newsecretnewsecretnewsecretnewsecret1234")
        keys.append(AccessKeyInfo(accessKeyId: k.accessKeyId, status: "Active", createDate: Date()))
        return k
    }

    func updateAccessKey(_ c: AWSCredentials, keyId: String, active: Bool) throws {
        calls.append("UpdateAccessKey \(c.accessKeyId) \(keyId) \(active ? "Active" : "Inactive")")
        try check("iam:UpdateAccessKey")
    }

    func deleteAccessKey(_ c: AWSCredentials, keyId: String) throws {
        calls.append("DeleteAccessKey \(c.accessKeyId) \(keyId)")
        try check("iam:DeleteAccessKey")
        keys.removeAll { $0.accessKeyId == keyId }
    }

    func getAccessKeyLastUsed(_ c: AWSCredentials, keyId: String) throws -> AccessKeyLastUsed {
        calls.append("GetAccessKeyLastUsed \(keyId)")
        return AccessKeyLastUsed(lastUsedDate: Date(timeIntervalSince1970: 1_700_000_000), serviceName: "s3", region: "af-south-1")
    }

    func putUserPolicy(_ c: AWSCredentials, userName: String, policyName: String, document: String) throws {
        calls.append("PutUserPolicy \(userName) \(policyName)")
        try check("iam:PutUserPolicy")
        policies.append((userName, policyName, document))
    }

    func listMFADevices(_ c: AWSCredentials) throws -> [String] {
        calls.append("ListMFADevices \(c.accessKeyId)")
        return mfaDevices
    }

    func createVirtualMFADevice(_ c: AWSCredentials, name: String) throws -> (serial: String, seed: String) {
        calls.append("CreateVirtualMFADevice \(name)")
        try check("iam:CreateVirtualMFADevice")
        return name.contains("phone") ? ("arn:aws:iam::123456789012:mfa/\(name)", phoneSeed) : ("arn:aws:iam::123456789012:mfa/\(name)", mfaSeed)
    }

    func enableMFADevice(_ c: AWSCredentials, userName: String, serial: String, code1: String, code2: String) throws {
        calls.append("EnableMFADevice \(userName) \(serial)")
        enabled.append((serial, code1, code2))
        mfaDevices.append(serial)
    }

    func deleteVirtualMFADevice(_ c: AWSCredentials, serial: String) throws {
        calls.append("DeleteVirtualMFADevice \(serial)")
        mfaDevices.removeAll { $0 == serial }
    }

    func deactivateMFADevice(_ c: AWSCredentials, userName: String, serial: String) throws {
        calls.append("DeactivateMFADevice \(userName) \(serial)")
    }

    func deleteUserPolicy(_ c: AWSCredentials, userName: String, policyName: String) throws {
        calls.append("DeleteUserPolicy \(userName) \(policyName)")
        policies.removeAll { $0.user == userName && $0.name == policyName }
    }
}

/// A Vault over temporary AWS files, an in-memory Keychain and a Touch ID that counts.
struct Sandbox {
    let dir: URL
    let paths: Paths
    let store = MemoryStore()
    let auth = CountingPresence()
    let aws = FakeAWS()
    let vault: Vault

    init() {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("zsp-test-\(UUID().uuidString)")
        try! FileManager.default.createDirectory(at: dir.appendingPathComponent(".aws"), withIntermediateDirectories: true)
        paths = Paths(credentialsFile: dir.appendingPathComponent(".aws/credentials"),
                      configFile: dir.appendingPathComponent(".aws/config"),
                      supportDir: dir.appendingPathComponent("support"))
        vault = Vault(paths: paths, store: store, auth: auth, aws: aws, commandPath: "/Users/me/Applications/aws-cli-zsp.app/Contents/MacOS/zsp")
        vault.pause = { _ in }
    }

    func write(credentials: String? = nil, config: String? = nil) {
        if let credentials { try! credentials.write(to: paths.credentialsFile, atomically: true, encoding: .utf8) }
        if let config { try! config.write(to: paths.configFile, atomically: true, encoding: .utf8) }
    }

    var credentials: String { (try? String(contentsOf: paths.credentialsFile, encoding: .utf8)) ?? "" }
    var config: String { (try? String(contentsOf: paths.configFile, encoding: .utf8)) ?? "" }

    func master(_ profile: String) -> MasterKey? {
        (try? store.read(.master, profile)).flatMap { $0 }.flatMap { try? ZSPJSON.decoder.decode(MasterKey.self, from: $0) }
    }

    func cleanup() { try? FileManager.default.removeItem(at: dir) }
}

let screenshotCredentials = """
[default]
aws_access_key_id = AKIADEFAULT00000001
aws_secret_access_key = defaultsecretdefaultsecretdefaultsecret1

[bedrock]
aws_access_key_id=AKIABEDROCK00000001
aws_secret_access_key=bedrocksecretbedrocksecretbedrocksecret1
region = us-east-1
[personal]
aws_access_key_id = AKIAPERSONAL0000001
aws_secret_access_key = personalsecretpersonalsecretpersonalsec1
"""
