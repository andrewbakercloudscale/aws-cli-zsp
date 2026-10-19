import Foundation

/// What a key's IAM user may change about itself. A client's read-only user can still get
/// sessions (GetSessionToken needs no IAM permission), but not rotate, revoke or add MFA:
/// those buttons are hidden for it rather than failing after a Touch ID.
public enum IAMPermission: String, Codable, CaseIterable, Sendable {
    /// Rotate, deactivate and delete the access key.
    case keys
    /// Revoke sessions (an inline user policy).
    case revoke
    /// This Mac or a phone as an MFA device, and requiring MFA.
    case mfa

    /// The IAM actions it needs, simulated against the user itself.
    var userActions: [String] {
        switch self {
        case .keys: return ["iam:ListAccessKeys", "iam:CreateAccessKey", "iam:UpdateAccessKey", "iam:DeleteAccessKey"]
        case .revoke: return ["iam:PutUserPolicy"]
        case .mfa: return ["iam:EnableMFADevice", "iam:PutUserPolicy"]
        }
    }

    public var refused: String {
        switch self {
        case .keys: return "change its access keys"
        case .revoke: return "revoke its sessions"
        case .mfa: return "add MFA devices or require MFA"
        }
    }
}

/// `ProfileMeta.access`: set by hand with `aws-cli-zsp access`, otherwise learned.
public enum AccessLevel: String, Codable, CaseIterable, Sendable {
    /// Managed by the client: never offer an IAM change.
    case readOnly = "read-only"
    /// Offer everything, whatever was learned.
    case full
}

extension ProfileMeta {
    /// IAM refuses this, or the profile was marked read-only.
    public func cannot(_ p: IAMPermission) -> Bool {
        switch access {
        case .readOnly?: return true
        case .full?: return false
        case nil: return iamDenied?.contains(p) ?? false
        }
    }

    public var readOnly: Bool { IAMPermission.allCases.allSatisfy(cannot) }
}

extension Vault {
    static let deniedCodes: Set<String> = ["AccessDenied", "AccessDeniedException", "UnauthorizedOperation"]

    /// Refuses at once, before any Touch ID, what this profile is known not to be allowed.
    func requireAllowed(_ profile: String, _ p: IAMPermission) throws {
        guard let m = meta.all()[profile], m.cannot(p) else { return }
        throw ZSPError.invalid(readOnlyMessage(profile, p, marked: m.access == .readOnly))
    }

    func readOnlyMessage(_ profile: String, _ p: IAMPermission, marked: Bool) -> String {
        let why = marked ? "“\(profile)” is marked read-only (managed by the client)"
                         : "The IAM user behind “\(profile)” is not allowed to \(p.refused): it is managed by its account's owner"
        return "\(why). Sessions still work as normal. If that changed: aws-cli-zsp access --profile \(profile) full"
    }

    /// Runs an IAM change. A refusal from AWS is remembered, so the menu stops offering it.
    func guarded<T>(_ profile: String, _ p: IAMPermission, _ body: () throws -> T) throws -> T {
        try requireAllowed(profile, p)
        do {
            return try body()
        } catch let ZSPError.aws(code, message) where Self.deniedCodes.contains(code) {
            try? meta.update(profile) { m in
                var d = Set(m?.iamDenied ?? []); d.insert(p)
                m?.iamDenied = IAMPermission.allCases.filter(d.contains)
            }
            _ = try? audit.append("access.denied", profile: profile, ok: false, detail: ["for": p.rawValue, "error": message])
            throw ZSPError.invalid(readOnlyMessage(profile, p, marked: false))
        }
    }

    /// Asks IAM what the user may do (SimulatePrincipalPolicy), when it is allowed to ask.
    /// Nil when the simulation itself is refused: what was learned so far stays.
    func simulateAccess(_ c: AWSCredentials, _ identity: CallerIdentity) -> [IAMPermission]? {
        guard let user = Self.userName(fromArn: identity.arn) else { return nil }
        let actions = Array(Set(IAMPermission.allCases.flatMap(\.userActions)))
        let context = ["aws:username": user]
        guard var allowed = try? aws.simulate(c, principal: identity.arn, actions: actions, resource: identity.arn, context: context),
              let mfa = try? aws.simulate(c, principal: identity.arn, actions: ["iam:CreateVirtualMFADevice"],
                                          resource: "arn:aws:iam::\(identity.account):mfa/aws-cli-zsp-check", context: context)
        else { return nil }
        allowed.merge(mfa) { a, b in a && b }
        return IAMPermission.allCases.filter { p in
            (p.userActions + (p == .mfa ? ["iam:CreateVirtualMFADevice"] : [])).contains { allowed[$0] != true }
        }
    }

    /// Marks a profile read-only or full by hand, or (nil) goes back to what IAM says.
    public func setAccess(_ profile: String, _ level: AccessLevel?) throws {
        guard meta.all()[profile] != nil else { throw ZSPError.notFound("No profile “\(profile)” in the vault") }
        // Auto also forgets what was learned, so the next refusal (or Check in AWS) decides again.
        try meta.update(profile) { $0?.access = level; if level == nil { $0?.iamDenied = nil } }
        try audit.append("access.set", profile: profile, detail: ["access": level?.rawValue ?? "auto"])
    }
}
