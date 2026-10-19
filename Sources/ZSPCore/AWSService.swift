import Foundation

/// The handful of STS and IAM calls zsp makes. A protocol so tests run without AWS.
public protocol AWSService {
    func getSessionToken(_ c: AWSCredentials, durationSeconds: Int, mfa: MFACode?) throws -> AWSCredentials
    func getCallerIdentity(_ c: AWSCredentials) throws -> CallerIdentity
    func listAccessKeys(_ c: AWSCredentials) throws -> [AccessKeyInfo]
    func createAccessKey(_ c: AWSCredentials) throws -> AWSCredentials
    func updateAccessKey(_ c: AWSCredentials, keyId: String, active: Bool) throws
    func deleteAccessKey(_ c: AWSCredentials, keyId: String) throws
    func getAccessKeyLastUsed(_ c: AWSCredentials, keyId: String) throws -> AccessKeyLastUsed
    func putUserPolicy(_ c: AWSCredentials, userName: String, policyName: String, document: String) throws
    func listMFADevices(_ c: AWSCredentials) throws -> [String]
    /// A new virtual MFA device: its ARN and base32 seed.
    func createVirtualMFADevice(_ c: AWSCredentials, name: String) throws -> (serial: String, seed: String)
    func enableMFADevice(_ c: AWSCredentials, userName: String, serial: String, code1: String, code2: String) throws
    func deleteVirtualMFADevice(_ c: AWSCredentials, serial: String) throws
    func deactivateMFADevice(_ c: AWSCredentials, userName: String, serial: String) throws
    func deleteUserPolicy(_ c: AWSCredentials, userName: String, policyName: String) throws
}

public extension AWSService {
    func getSessionToken(_ c: AWSCredentials, durationSeconds: Int) throws -> AWSCredentials {
        try getSessionToken(c, durationSeconds: durationSeconds, mfa: nil)
    }
}

/// STS and IAM over the AWS Query protocol: a signed form POST, an XML answer.
public final class AWSQueryService: AWSService {
    public typealias Transport = (URLRequest) throws -> (Int, Data)

    struct Endpoint {
        let host: String
        let service: String
        let version: String
    }

    // Regional, not sts.amazonaws.com: the global endpoint issues v1 session tokens, which
    // opt-in regions such as af-south-1 reject with InvalidClientTokenId. Regional tokens
    // work in every region.
    static let sts = Endpoint(host: "sts.us-east-1.amazonaws.com", service: "sts", version: "2011-06-15")
    static let iam = Endpoint(host: "iam.amazonaws.com", service: "iam", version: "2010-05-08")

    let transport: Transport
    let now: () -> Date

    public init(transport: Transport? = nil, now: @escaping () -> Date = Date.init) {
        self.transport = transport ?? AWSQueryService.urlSession
        self.now = now
    }

    static func urlSession(_ request: URLRequest) throws -> (Int, Data) {
        final class Box: @unchecked Sendable { var result: Result<(Int, Data), Error>? }
        let box = Box()
        let done = DispatchSemaphore(value: 0)
        URLSession.shared.dataTask(with: request) { data, response, error in
            if let error {
                box.result = .failure(ZSPError.io("cannot reach \(request.url?.host ?? "AWS"): \(error.localizedDescription)"))
            } else {
                box.result = .success(((response as? HTTPURLResponse)?.statusCode ?? 0, data ?? Data()))
            }
            done.signal()
        }.resume()
        done.wait()
        return try box.result!.get()
    }

    func call(_ ep: Endpoint, _ action: String, _ params: [(String, String)], _ c: AWSCredentials) throws -> XMLDocument {
        let body = Data(SigV4.formEncode([("Action", action), ("Version", ep.version)] + params).utf8)
        let date = now()
        var headers = [
            "content-type": "application/x-www-form-urlencoded; charset=utf-8",
            "host": ep.host,
            "x-amz-date": SigV4.amzDate(date),
        ]
        if let token = c.sessionToken { headers["x-amz-security-token"] = token }
        let auth = SigV4.authorization(method: "POST", path: "/", query: [], headers: headers, payload: body,
                                       credentials: c, region: "us-east-1", service: ep.service, date: date)
        var request = URLRequest(url: URL(string: "https://\(ep.host)/")!, timeoutInterval: 20)
        request.httpMethod = "POST"
        for (k, v) in headers where k != "host" { request.setValue(v, forHTTPHeaderField: k) }
        request.setValue(auth, forHTTPHeaderField: "Authorization")
        request.httpBody = body

        let (status, data) = try transport(request)
        let doc = try? XMLDocument(data: data)
        guard status == 200, let doc else {
            let code = doc.flatMap { Self.text($0, "Code") } ?? "HTTP\(status)"
            let message = doc.flatMap { Self.text($0, "Message") } ?? String(decoding: data.prefix(300), as: UTF8.self)
            throw ZSPError.aws(code: code, message: message)
        }
        return doc
    }

    static func text(_ node: XMLNode, _ name: String) -> String? {
        (try? node.nodes(forXPath: ".//*[local-name()='\(name)']"))?.first?.stringValue
    }

    static func required(_ node: XMLNode, _ name: String) throws -> String {
        guard let v = text(node, name), !v.isEmpty else { throw ZSPError.aws(code: "BadResponse", message: "no \(name) in the answer") }
        return v
    }

    public func getSessionToken(_ c: AWSCredentials, durationSeconds: Int, mfa: MFACode?) throws -> AWSCredentials {
        var params = [("DurationSeconds", String(durationSeconds))]
        if let mfa { params += [("SerialNumber", mfa.serial), ("TokenCode", mfa.code)] }
        let doc = try call(Self.sts, "GetSessionToken", params, c)
        return AWSCredentials(accessKeyId: try Self.required(doc, "AccessKeyId"),
                              secretAccessKey: try Self.required(doc, "SecretAccessKey"),
                              sessionToken: try Self.required(doc, "SessionToken"),
                              expiration: parseISO8601(try Self.required(doc, "Expiration")))
    }

    public func getCallerIdentity(_ c: AWSCredentials) throws -> CallerIdentity {
        let doc = try call(Self.sts, "GetCallerIdentity", [], c)
        return CallerIdentity(account: try Self.required(doc, "Account"), arn: try Self.required(doc, "Arn"),
                              userId: try Self.required(doc, "UserId"))
    }

    public func listAccessKeys(_ c: AWSCredentials) throws -> [AccessKeyInfo] {
        let doc = try call(Self.iam, "ListAccessKeys", [], c)
        let members = (try? doc.nodes(forXPath: "//*[local-name()='AccessKeyMetadata']/*[local-name()='member']")) ?? []
        return members.compactMap { m in
            guard let id = Self.text(m, "AccessKeyId") else { return nil }
            return AccessKeyInfo(accessKeyId: id, status: Self.text(m, "Status") ?? "?",
                                 createDate: Self.text(m, "CreateDate").flatMap(parseISO8601))
        }
    }

    public func createAccessKey(_ c: AWSCredentials) throws -> AWSCredentials {
        let doc = try call(Self.iam, "CreateAccessKey", [], c)
        return AWSCredentials(accessKeyId: try Self.required(doc, "AccessKeyId"),
                              secretAccessKey: try Self.required(doc, "SecretAccessKey"))
    }

    public func updateAccessKey(_ c: AWSCredentials, keyId: String, active: Bool) throws {
        _ = try call(Self.iam, "UpdateAccessKey", [("AccessKeyId", keyId), ("Status", active ? "Active" : "Inactive")], c)
    }

    public func deleteAccessKey(_ c: AWSCredentials, keyId: String) throws {
        _ = try call(Self.iam, "DeleteAccessKey", [("AccessKeyId", keyId)], c)
    }

    public func getAccessKeyLastUsed(_ c: AWSCredentials, keyId: String) throws -> AccessKeyLastUsed {
        let doc = try call(Self.iam, "GetAccessKeyLastUsed", [("AccessKeyId", keyId)], c)
        func known(_ s: String?) -> String? { s == nil || s == "N/A" ? nil : s }
        return AccessKeyLastUsed(lastUsedDate: Self.text(doc, "LastUsedDate").flatMap(parseISO8601),
                                 serviceName: known(Self.text(doc, "ServiceName")), region: known(Self.text(doc, "Region")))
    }

    public func putUserPolicy(_ c: AWSCredentials, userName: String, policyName: String, document: String) throws {
        _ = try call(Self.iam, "PutUserPolicy", [("UserName", userName), ("PolicyName", policyName), ("PolicyDocument", document)], c)
    }

    public func listMFADevices(_ c: AWSCredentials) throws -> [String] {
        let doc = try call(Self.iam, "ListMFADevices", [], c)
        let members = (try? doc.nodes(forXPath: "//*[local-name()='MFADevices']/*[local-name()='member']")) ?? []
        return members.compactMap { Self.text($0, "SerialNumber") }
    }

    public func createVirtualMFADevice(_ c: AWSCredentials, name: String) throws -> (serial: String, seed: String) {
        let doc = try call(Self.iam, "CreateVirtualMFADevice", [("VirtualMFADeviceName", name)], c)
        let raw = try Self.required(doc, "Base32StringSeed")
        // A blob in the Query API, so it arrives base64-encoded: the base32 text inside it.
        let seed = Data(base64Encoded: raw).map { String(decoding: $0, as: UTF8.self) } ?? raw
        return (try Self.required(doc, "SerialNumber"), seed)
    }

    public func enableMFADevice(_ c: AWSCredentials, userName: String, serial: String, code1: String, code2: String) throws {
        _ = try call(Self.iam, "EnableMFADevice", [("UserName", userName), ("SerialNumber", serial),
                                                   ("AuthenticationCode1", code1), ("AuthenticationCode2", code2)], c)
    }

    public func deleteVirtualMFADevice(_ c: AWSCredentials, serial: String) throws {
        _ = try call(Self.iam, "DeleteVirtualMFADevice", [("SerialNumber", serial)], c)
    }

    public func deactivateMFADevice(_ c: AWSCredentials, userName: String, serial: String) throws {
        _ = try call(Self.iam, "DeactivateMFADevice", [("UserName", userName), ("SerialNumber", serial)], c)
    }

    public func deleteUserPolicy(_ c: AWSCredentials, userName: String, policyName: String) throws {
        _ = try call(Self.iam, "DeleteUserPolicy", [("UserName", userName), ("PolicyName", policyName)], c)
    }
}
