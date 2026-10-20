import Foundation
import ZSPCore

// MARK: MFA and approval by code

func cmdMFA() throws {
    let profile = requireProfile()
    let vault = makeVault()
    switch opts.rest.first ?? "" {
    case "setup":
        let host = (Host.current().localizedName ?? "mac").lowercased()
        let raw = opts.values["--name"] ?? "aws-cli-zsp-\(host)-\(profile)"
        let serial = try vault.setupMFA(profile, deviceName: deviceName(raw))
        done(["profile": profile, "serial": serial], """
            this Mac is now an MFA device for \(profile): \(serial)
            every session it issues carries MFA, still with one Touch ID. Next: aws-cli-zsp mfa enforce --profile \(profile)
            """)
    case "enforce":
        confirm("Make AWS refuse the \(profile) key unless MFA is present? Scripts that use this key directly, not through aws-cli-zsp, stop working.")
        try vault.enforceMFA(profile)
        done(["profile": profile], """
            AWS now refuses the \(profile) key without MFA (inline policy \(Vault.requireMFAPolicyName)); a copy of the key alone is worth nothing.
            To approve from your phone when away from the Mac: aws-cli-zsp remote enable --profile \(profile)
            """)
    case "unenforce":
        try vault.unenforceMFA(profile)
        done(["profile": profile], "AWS accepts the \(profile) key without MFA again (policy \(Vault.requireMFAPolicyName) removed); phone approval is off")
    case "remove":
        confirm("Remove this Mac's MFA device from \(profile)? MFA enforcement and phone approval are turned off first.")
        try vault.removeMFA(profile)
        done(["profile": profile], "this Mac is no longer an MFA device for \(profile); sessions are plain Touch ID ones again")
    case "add-phone":
        let stamp = String(Int(Date().timeIntervalSince1970))
        let d = try vault.addPhone(profile, deviceName: deviceName("aws-cli-zsp-phone-\(profile)-\(stamp)"))
        done(d, """
            scan this in your authenticator app (or type the secret in by hand):
              \(d.uri)
              secret: \(d.seed)
            then: aws-cli-zsp mfa confirm-phone --profile \(profile) --serial \(d.serial) CODE1 CODE2
            """)
    case "confirm-phone":
        guard let serial = opts.values["--serial"], opts.rest.count == 3 else {
            fail("usage: aws-cli-zsp mfa confirm-phone --profile \(profile) --serial ARN CODE1 CODE2 (two codes in a row)")
        }
        try vault.confirmPhone(profile, serial: serial, code1: opts.rest[1], code2: opts.rest[2])
        done(["profile": profile, "serial": serial], "your phone is an MFA device for \(profile), and its codes approve sessions when you are away: aws-cli-zsp approve --profile \(profile) CODE")
    case "cancel-phone":
        guard let serial = opts.values["--serial"] else { fail("usage: aws-cli-zsp mfa cancel-phone --profile \(profile) --serial ARN") }
        try vault.cancelPhone(profile, serial: serial)
        done(["profile": profile], "removed the unused device \(serial)")
    default:
        fail("usage: aws-cli-zsp mfa setup|enforce|unenforce|remove|add-phone|confirm-phone|cancel-phone --profile P")
    }
}

func cmdRemote() throws {
    let profile = requireProfile()
    let vault = makeVault()
    switch opts.rest.first ?? "" {
    case "enable":
        let serial = try vault.enableRemote(profile, serial: opts.values["--serial"])
        done(["profile": profile, "serial": serial], """
            away from the Mac, a code from \(serial) approves \(profile):
              aws-cli-zsp approve --profile \(profile) 123456
            Claude Code asks you for the code when it needs one.
            """)
    case "disable":
        try vault.disableRemote(profile)
        done(["profile": profile], "approval by MFA code is off for \(profile): only Touch ID at the Mac unlocks it")
    default:
        fail("usage: aws-cli-zsp remote enable|disable --profile P [--serial ARN]")
    }
}
