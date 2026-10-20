import ZSPCore

/// What a profile's menu can do. Every action but clearing the local session needs Touch ID,
/// which zsp asks for itself.
enum Action: CaseIterable {
    case inspect, clearSession, rotate, revoke, disable, delete, forget
    /// The three steps to MFA enforced by AWS and approval from your phone, in order.
    case mfaSetup, mfaEnforce, remoteEnable, remoteDisable
    /// Undoing them: enforcement alone, or everything including this Mac's MFA device.
    case mfaUnenforce, mfaRemove
    /// A client's key: hide rotate, revoke and MFA, or offer them again.
    case markReadOnly, markAuto

    /// What the ⋯ menu lists; the MFA steps have their own buttons on the row.
    static let keyMenu: [Action] = [.inspect, .clearSession, .rotate, .revoke, .disable, .delete, .forget]

    var title: String {
        switch self {
        case .inspect: return "Check last use in AWS"
        case .clearSession: return "Clear cached session"
        case .rotate: return "Rotate key…"
        case .revoke: return "Revoke all sessions…"
        case .disable: return "Deactivate key…"
        case .delete: return "Delete key…"
        case .forget: return "Remove from this Mac…"
        case .mfaSetup: return "Set up MFA…"
        case .mfaEnforce: return "Require MFA…"
        case .remoteEnable: return "Allow phone approval…"
        case .remoteDisable: return "Turn off phone approval…"
        case .mfaUnenforce: return "Stop requiring MFA…"
        case .mfaRemove: return "Remove MFA…"
        case .markReadOnly: return "Mark read-only (client's key)…"
        case .markAuto: return "Offer IAM changes again"
        }
    }

    var symbol: String {
        switch self {
        case .inspect: return "magnifyingglass"
        case .clearSession: return "clock.arrow.circlepath"
        case .rotate: return "arrow.triangle.2.circlepath"
        case .revoke: return "xmark.shield"
        case .disable: return "pause.circle"
        case .delete: return "trash"
        case .forget: return "minus.circle"
        case .mfaSetup: return "lock.iphone"
        case .mfaEnforce: return "checkmark.shield"
        case .remoteEnable: return "iphone.radiowaves.left.and.right"
        case .remoteDisable: return "iphone.slash"
        case .mfaUnenforce: return "shield.slash"
        case .mfaRemove: return "lock.open"
        case .markReadOnly: return "eye"
        case .markAuto: return "arrow.uturn.backward"
        }
    }

    /// The explanation shown before anything happens: what it does, and what it breaks.
    func explain(_ p: String) -> String? {
        switch self {
        case .inspect, .clearSession, .markAuto: return nil
        case .markReadOnly:
            return "For a key a client gave you with read-only IAM access: rotate, revoke, deactivate, delete and MFA are no longer offered for “\(p)”, so nothing fails after a Touch ID.\n\nSessions work exactly as before. Nothing changes in AWS. Undo from the same menu."
        case .rotate:
            return "Creates a new access key for the IAM user behind “\(p)”, seals it in the vault, waits until AWS accepts it, then deletes the old key.\n\nAnything else still using the old key (CI, another machine) stops working. Touch ID is asked first."
        case .revoke:
            return "Attaches a deny-all policy to the IAM user that applies to every session token issued before now, on every machine, including any minted from a leaked key.\n\nThe key itself keeps working and your next command gets a fresh session. Touch ID is asked first."
        case .disable:
            return "Marks the key Inactive in AWS. Everything using it stops at once.\n\nAWS CLI: ZSP cannot turn it back on, because the key was its only way in: re-enable it in the IAM console."
        case .delete:
            return "Deletes the key in AWS, then removes it from the vault and from ~/.aws/config.\n\nThis cannot be undone."
        case .forget:
            return "Removes the key from this Mac only. AWS still has it and it keeps working wherever else it is used.\n\nIf this was your only copy of the secret, it is gone for good."
        case .mfaSetup:
            return "Step 1 of 3. Adds this Mac as a virtual MFA device for the IAM user behind “\(p)”, and seals its secret with the key in the vault.\n\nFrom then on every session carries MFA, still with one Touch ID. Nothing else changes yet. The IAM user needs iam:CreateVirtualMFADevice and iam:EnableMFADevice on itself. Touch ID is asked first."
        case .mfaEnforce:
            return "Step 2 of 3. Attaches a policy (aws-cli-zsp-require-mfa) to the IAM user: AWS then refuses everything the key does without MFA, so a copy of the key alone is worthless.\n\nAnything that uses this key directly rather than through AWS CLI: ZSP (CI, another machine, a script with the key in it) stops working. To undo, delete that inline policy in the IAM console. Touch ID is asked first."
        case .remoteEnable:
            return "Step 3 of 3, with a phone that is already an MFA device on this IAM user (added in the IAM console). Lets a 6-digit code from it approve a session when nobody is at the Mac, for example while you drive Claude Code with Remote Control: Claude asks you for the code.\n\nA copy of the key without this Mac's MFA secret is kept for it, which AWS refuses without your phone's code. Touch ID is asked first."
        case .remoteDisable:
            return "Deletes the copy of the key kept for phone approval. Away from the Mac, AWS commands for “\(p)” then wait until you are back at it.\n\nNothing changes in AWS: MFA stays required."
        case .mfaUnenforce:
            return "Undoes step 2: removes the aws-cli-zsp-require-mfa policy, so AWS accepts the “\(p)” key without MFA again, everywhere. Phone approval is turned off with it.\n\nUse this if something that needs the key stopped working. This Mac stays an MFA device, so step 2 can be turned on again in one click. Touch ID is asked first."
        case .mfaRemove:
            return "Undoes all three steps: turns off phone approval and MFA enforcement, then deactivates and deletes this Mac's MFA device in AWS. Sessions are plain Touch ID ones again.\n\nA phone device you added stays in IAM (delete it in the IAM console if you no longer want it). Touch ID is asked first."
        }
    }

    var destructive: Bool { [.disable, .delete, .forget, .mfaEnforce, .mfaRemove].contains(self) }

    func args(_ p: String) -> [String] {
        switch self {
        case .inspect: return ["inspect", "--profile", p]
        case .clearSession: return ["clear-sessions", "--profile", p]
        case .rotate: return ["rotate", "--profile", p, "--yes"]
        case .revoke: return ["revoke-sessions", "--profile", p, "--yes"]
        case .disable: return ["disable-key", "--profile", p, "--yes"]
        case .delete: return ["delete-key", "--profile", p, "--yes"]
        case .forget: return ["forget", "--profile", p, "--yes"]
        case .mfaSetup: return ["mfa", "setup", "--profile", p]
        case .mfaEnforce: return ["mfa", "enforce", "--profile", p, "--yes"]
        case .remoteEnable: return ["remote", "enable", "--profile", p]
        case .remoteDisable: return ["remote", "disable", "--profile", p]
        case .mfaUnenforce: return ["mfa", "unenforce", "--profile", p]
        case .mfaRemove: return ["mfa", "remove", "--profile", p, "--yes"]
        case .markReadOnly: return ["access", "--profile", p, "read-only"]
        case .markAuto: return ["access", "--profile", p, "auto"]
        }
    }
}
