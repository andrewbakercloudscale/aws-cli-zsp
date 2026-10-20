import Foundation

/// What `importPlaintext` moved.
public struct ImportReport: Codable, Equatable, Sendable {
    public var imported: [String] = []
    public var replaced: [String] = []
    public var incomplete: [Finding] = []

    public init() {}
}

public struct RotateResult: Codable, Equatable, Sendable {
    public var profile: String
    public var oldKeyId: String
    public var newKeyId: String
    public var oldKey: String
}

public struct KeyReport: Codable, Equatable, Sendable {
    public var accessKeyId: String
    public var status: String
    public var createDate: Date?
    public var lastUsed: AccessKeyLastUsed?
    public var thisProfile: Bool
}

public struct InspectReport: Codable, Equatable, Sendable {
    public var profile: String
    public var identity: CallerIdentity
    public var keys: [KeyReport]
}

/// 3600 is "1-hour", 900 is "15-minute", 5400 is "90-minute": the form a dialog reads naturally.
func durationText(_ seconds: Int) -> String {
    if seconds % 3600 == 0 { return "\(seconds / 3600)-hour" }
    return "\(seconds / 60)-minute"
}
