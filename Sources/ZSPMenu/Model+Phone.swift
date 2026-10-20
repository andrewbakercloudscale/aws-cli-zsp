import AppKit
import CoreImage
import ZSPCore

/// Approval by code and adding a phone: the steps that need a dialog of their own.
extension Model {
    /// Approval by phone code from the panel: the same as `aws-cli-zsp approve`, for when Touch
    /// ID is not an option (a broken sensor, a closed lid on a monitor without Touch ID).
    func approveWithCode(_ profile: String) {
        NSApp.activate(ignoringOtherApps: true)
        let a = NSAlert()
        a.messageText = "Approve “\(profile)” with a code"
        a.informativeText = "Type the 6-digit code from your phone's authenticator app. AWS checks it and issues a session; no Touch ID."
        let field = NSTextField(frame: NSRect(x: 0, y: 0, width: 120, height: 24))
        field.placeholderString = "123456"
        a.accessoryView = field
        a.window.initialFirstResponder = field
        a.addButton(withTitle: "Approve")
        a.addButton(withTitle: "Cancel")
        guard a.runModal() == .alertFirstButtonReturn else { return }
        let code = field.stringValue.filter(\.isNumber)
        call(["approve", "--profile", profile, code], label: "Asking AWS…", as: CLI.Ignored.self) { _ in
            "Approved: “\(profile)” has a session."
        }
    }

    /// Step 3 without the IAM console: AWS creates a device, the phone scans its QR code, and
    /// two codes from the phone enable it and turn on approval by code. Cancel deletes it again.
    func addPhone(_ profile: String) {
        guard confirm("Add your phone for “\(profile)”?",
                      "Step 3 of 3. Creates an MFA device in AWS for your phone and shows its QR code. Scan it with Google Authenticator, Microsoft Authenticator, 1Password or any authenticator app, then type two codes in a row.\n\nAfter that, when nobody is at the Mac (Claude Code over Remote Control), a code from your phone approves a session. AWS has no push approval for IAM keys: you read the code and send it. Touch ID is asked first, and again to confirm.",
                      button: "Continue", destructive: false) else { return }
        call(["mfa", "add-phone", "--profile", profile], label: "Creating the MFA device…", as: Vault.PhoneDevice.self) { [weak self] d in
            guard let d, let self else { return nil }
            DispatchQueue.main.async { self.askForPhoneCodes(profile, d) }
            return nil
        }
    }

    func askForPhoneCodes(_ profile: String, _ d: Vault.PhoneDevice, retry: String? = nil) {
        NSApp.activate(ignoringOtherApps: true)
        let (a, first, second) = Self.phoneAlert(d, retry: retry)
        guard a.runModal() == .alertFirstButtonReturn else {
            call(["mfa", "cancel-phone", "--profile", profile, "--serial", d.serial], label: "Removing the unused device…", as: CLI.Ignored.self) { _ in
                "Cancelled: the phone device was deleted from AWS again."
            }
            return
        }
        let c1 = first.stringValue.filter(\.isNumber), c2 = second.stringValue.filter(\.isNumber)
        call(["mfa", "confirm-phone", "--profile", profile, "--serial", d.serial, c1, c2], label: "Enabling your phone…", as: CLI.Ignored.self, banner: false) { [weak self] r, error in
            guard let self else { return nil }
            if r != nil {
                self.banner = Banner(text: "Your phone is set up for “\(profile)”. Away from the Mac, Claude asks you for a code from it.", isError: false)
            } else {
                DispatchQueue.main.async { self.askForPhoneCodes(profile, d, retry: "That did not work: \(error ?? "AWS refused the codes"). Try two fresh codes.") }
            }
            return nil
        }
    }

    /// The QR code and two code fields; separate so `--snapshot --qr` can draw it.
    static func phoneAlert(_ d: Vault.PhoneDevice, retry: String?) -> (NSAlert, NSTextField, NSTextField) {
        let a = NSAlert()
        a.messageText = "Scan this with your authenticator app"
        a.informativeText = (retry.map { "\($0)\n\n" } ?? "")
            + "Then type the code it shows, wait for the next one, and type that too.\n\nCan't scan? Add a key by hand with this secret:\n\(d.seed)"
        let qr = NSImageView(image: Self.qrCode(d.uri) ?? NSImage())
        qr.frame = NSRect(x: 0, y: 64, width: 220, height: 220)
        let first = NSTextField(frame: NSRect(x: 0, y: 32, width: 220, height: 24))
        first.placeholderString = "First code"
        let second = NSTextField(frame: NSRect(x: 0, y: 0, width: 220, height: 24))
        second.placeholderString = "Next code"
        let box = NSView(frame: NSRect(x: 0, y: 0, width: 220, height: 284))
        [qr, first, second].forEach(box.addSubview)
        a.accessoryView = box
        a.window.initialFirstResponder = first
        a.addButton(withTitle: "Enable")
        a.addButton(withTitle: "Cancel")
        return (a, first, second)
    }

    static func qrCode(_ text: String) -> NSImage? {
        guard let f = CIFilter(name: "CIQRCodeGenerator") else { return nil }
        f.setValue(Data(text.utf8), forKey: "inputMessage")
        f.setValue("M", forKey: "inputCorrectionLevel")
        guard let out = f.outputImage?.transformed(by: CGAffineTransform(scaleX: 8, y: 8)) else { return nil }
        let rep = NSCIImageRep(ciImage: out)
        let image = NSImage(size: rep.size)
        image.addRepresentation(rep)
        return image
    }
}
