# Handover: aws-cli-zsp

Updated 2026-10-20. Version 0.3.3 is on `main` (`dcb247a`) and has no tag. v0.3.2 is the latest release.

## State

- The work is committed and pushed, and the tree is clean.
- Tests: 65 run, 1 is skipped, and all pass.
- The installed app at `~/Applications/aws-cli-zsp.app` matches `main`, and the menu bar app is running.
- `aws-cli-zsp doctor` on the owner's Mac passes. It shows two warnings:
  - MFA is not enforced.
  - The accounts are not pinned yet. Each account pins at its next Touch ID session.

## Rules for whoever picks this up

- **Do not release on your own.** Commit and push version bumps, but create no git tag and no GitHub release unless the owner asks for one.
- **The owner's AWS accounts are read-only.** Do not run live tests of anything that writes to IAM: MFA setup, rotate, revoke, disable or delete. The FakeAWS tests in `Tests/` cover those flows.
- Do not rotate the owner's keys.
- Clients' AWS accounts must never be changed.
- Name it "AWS CLI: ZSP" in dialogs and aws-cli-zsp everywhere else.
- Commit as `andrew.j.baker.007@gmail.com`.
- Commits that touch the example-key fixtures (`Tests/`, `Sources/zsp/SetupCommands.swift`) need `ALLOW_SECRET=1`.

## Build and test

```bash
bash scripts/build-app.sh   # tests, build, sign, install, relaunch
swift test                  # tests only
ZSPMenu --snapshot out.png [--keys|--mfa|--audit|--setup|--about|--checks|--qr]
```

To work in a sandbox, point `ZSP_HOME`, `AWS_SHARED_CREDENTIALS_FILE` and `AWS_CONFIG_FILE` at a scratch folder, and delete the folder when you finish.

## Layout

- `Sources/ZSPCore` is the core:
  - The vault, split into `Vault+Import`, `+Sessions`, `+MFA`, `+Phone`, `+Keys` and `+Local`.
  - Secure Enclave storage.
  - SigV4 and the AWS calls.
  - The audit chain and the `AuditEvent` catalogue.
  - The doctor checks and their fixes.
  - The support log (`Log.swift`) and redaction.
  - The diagnostics report (`SupportReport.swift`).
- `Sources/zsp` is the CLI (`aws-cli-zsp`). Each area has its own file, and `main.swift` logs every command.
- `Sources/ZSPMenu` is the menu bar app, with one view per tab. `CLIClient.swift` runs the CLI and reads stdout and stderr at the same time, so the app does not deadlock on a full pipe.
- PLAN.md holds the threat model, the architecture, the phases (1 to 7) and the Roles Anywhere design.

## Support

- The support log is at `<support>/logs/aws-cli-zsp.log`. It rotates at 1 MB, and the same lines go to os.Logger under `consulting.cloudscale.zsp`.
- `ZSP_DEBUG=1` adds debug lines.
- `aws-cli-zsp diagnostics` writes a redacted report to the Desktop, with file mode 0600.
- Auto-move uses the launchd agent `consulting.cloudscale.zsp.watch`. It watches `~/.aws` and also re-scans every 5 minutes.

## Known gotchas

- **Swift 6.2 compiler crash:** the compiler can crash in the release optimiser (in CopyPropagation). The code was changed to avoid it. If swift-frontend crashes again, check the newest code for the same pattern.
- **Menu bar icon hidden:** when the menu bar is full, macOS hides the icon behind the notch. Open the app from Spotlight or run `aws-cli-zsp ui` to get the window.
- **Clock check:** it uses an ephemeral URLSession that skips caches. A cached Date header once showed a false 59-second clock skew.

## Open items

- SimulatePrincipalPolicy has not been tested against real AWS.
- Pins are not set on the live accounts yet. They are set at each account's next session, and nothing needs doing.
- An off-box copy of the audit log on the Pi was offered. The owner has not answered.
- Parked by the owner, so do not start these:
  - Roles Anywhere, for the owner's own accounts only.
  - Moving the audit anchor into the Keychain.
- Unanswered offer: delete the old `zsp-*` and `swift-frontend-*` crash reports in `~/Library/Logs/DiagnosticReports`. They all come from one build on 19 Oct and are harmless.
