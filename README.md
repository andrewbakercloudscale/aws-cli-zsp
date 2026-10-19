# aws-cli-zsp (AWS CLI: ZSP)

**Zero standing plaintext for AWS keys on macOS.** Your access keys are sealed by the Mac's
Secure Enclave, the chip will not unseal one without Touch ID, the AWS CLI and SDKs only ever
see a session that lasts an hour, and any key that lands in `~/.aws/credentials` (from
`aws configure`, a paste, a script) is moved out within seconds.

It is built from scratch on the ideas behind [aws-vault](https://github.com/ByteNess/aws-vault),
and adds:

| | aws-vault | aws-cli-zsp |
|---|---|---|
| No plaintext keys on disk, STS sessions to the CLI | ✅ Keychain | ✅ Secure Enclave, Touch ID enforced by the chip |
| Keys written to `~/.aws` are moved automatically | ❌ | ✅ launchd watcher plus a 5-minute sweep |
| Touch ID before a long-lived key is used | optional | always |
| Audit trail | ❌ | hash-chained, with who asked (`aws s3 ls ← zsh`) |
| Rotate a key | `aws-vault rotate` | one click, verified before the old key is deleted |
| Revoke sessions already issued (a thief's too) | ❌ | one click (an `aws:TokenIssueTime` deny policy) |
| When AWS last saw each key used | ❌ | **Check last use in AWS** |
| Menu bar UI | ❌ | ✅ |
| Works with plain `aws` and every SDK, no wrapper | `exec` or `credential_process` | `credential_process`, wired for you |

![In use](docs/images/inuse.png) ![Audit trail](docs/images/audit.png)

## Install

```bash
bash scripts/build-app.sh             # tests, build, sign, copy to ~/Applications (changes nothing in ~/.aws)
bash scripts/build-app.sh --install   # the same, then `aws-cli-zsp install`
```

`aws-cli-zsp install`:
1. links `~/.local/bin/aws-cli-zsp`
2. loads `consulting.cloudscale.zsp.watch`, which runs `aws-cli-zsp import --auto` whenever
   either AWS file changes, and every 5 minutes
3. starts the menu bar app at login
4. moves every plaintext key into the vault and adds
   `credential_process = …/aws-cli-zsp credential-process --profile NAME` to `~/.aws/config`

From then on, `aws --profile bedrock s3 ls` works as before. The first command each hour shows
"AWS CLI: ZSP is trying to issue AWS credentials for profile “bedrock” to aws s3 ls …"; the
rest reuse the cached session.

**Upgrading from 0.1.x** (which stored keys as plain Keychain items): run `aws-cli-zsp migrate`
once. macOS asks for your login password once per key, because those items were bound to the
exact build that made them. After that, updates never ask for anything but Touch ID.

## How it works

```
aws / SDK ──credential_process──▶ aws-cli-zsp ──cached session (≤1h)?──▶ yes: print it
                                        └──no──▶ Secure Enclave + Touch ID unseals the key ──▶ STS GetSessionToken
launchd WatchPaths ~/.aws/* ──▶ aws-cli-zsp import --auto ──▶ seal to the enclave's public key ──▶ scrub the file
menu bar app ──reads──▶ profiles.json, audit.jsonl ;  every action ──▶ aws-cli-zsp
```

- **Touch ID enforced by hardware.** Each key is encrypted (P-256 ECDH, HKDF-SHA256, AES-GCM,
  bound to its profile name) to a Secure Enclave key created with `.userPresence`. The enclave
  will not decrypt until you approve, whichever program asks, and the sealed files are useless
  on any other Mac. Moving a key in needs only the public key, so it never prompts. Sessions
  and the audit anchor use a second enclave key that needs no prompt.
- **Named dialogs.** The command is a helper app inside the bundle, so every prompt says
  "AWS CLI: ZSP".
- **Why not Keychain items.** macOS binds an item made by a binary with no Apple Team ID to that
  build's exact code hash. 0.1.0 used them, and every update showed a login-password dialog,
  with no Touch ID, for the app's own keys.
- **Sessions, not keys.** The CLI gets `GetSessionToken` credentials from the regional STS
  endpoint, which are valid in opt-in regions such as af-south-1. A leaked session expires on
  its own and cannot call IAM to mint a new key.
- **Fail closed.** A key leaves a file only after its sealed copy has been written and read
  back. If the audit entry can't be written, no credentials are issued.
- **Audit chain.** `~/Library/Application Support/aws-cli-zsp/audit.jsonl`: every entry hashes
  the one before it, and the newest hash is sealed separately, so editing, deleting or
  truncating the file fails `aws-cli-zsp audit --verify`.

## Commands

```
aws-cli-zsp list                              keys in the vault, sessions, last use and by whom
aws-cli-zsp scan                              plaintext keys left in ~/.aws (exit 1 if any)
aws-cli-zsp add --profile P                   type a key in, secret hidden; it never touches a file
aws-cli-zsp inspect --profile P               ARN, and when AWS last saw each key used
aws-cli-zsp rotate --profile P [--keep-old]   new key, verified, then the old one deleted (or deactivated)
aws-cli-zsp revoke-sessions --profile P       deny every session issued before now
aws-cli-zsp clear-sessions [--profile P]      drop cached sessions here (the next command needs Touch ID)
aws-cli-zsp duration --profile P 8h           session length, 15m to 12h (default 1h)
aws-cli-zsp exec --profile P -- terraform plan
aws-cli-zsp disable-key | delete-key | forget --profile P
aws-cli-zsp audit [--verify] [--limit N]
aws-cli-zsp migrate                           move 0.1.x Keychain items into the vault
aws-cli-zsp check-touch-id                    show the Touch ID prompt, unlock nothing
aws-cli-zsp uninstall [--restore-plaintext]
```

`--json` on any command prints a machine-readable result, which is what the menu bar app uses.

## Limits

- Malware running as you can run aws-cli-zsp too. It gets a cached session without a prompt
  until that session expires, the same trade-off aws-vault makes; `clear-sessions` or a
  shorter `duration` narrows the window. It cannot get the long-lived key without your finger.
- The enclave's public key is not secret, so a program running as you could seal a key of its
  own in place of yours, and could rewrite the audit log and its anchor together. **Inspect**
  shows the ARN a profile really belongs to.
- Rotate, revoke and disable call IAM with the profile's own key, so the IAM user needs
  `iam:ListAccessKeys`, `iam:CreateAccessKey`, `iam:DeleteAccessKey`, `iam:UpdateAccessKey`,
  `iam:GetAccessKeyLastUsed` and `iam:PutUserPolicy` on itself.
- MFA (`mfa_serial`) is not supported yet; see PLAN.md.

## Development

```bash
swift test                               # 31 tests, including the real Secure Enclave (no-prompt tier)
ZSP_NETWORK_TESTS=1 swift test           # adds a real STS call with a fake key (expects InvalidClientTokenId)
```

To try it without touching your real setup, point it at a sandbox with
`AWS_SHARED_CREDENTIALS_FILE`, `AWS_CONFIG_FILE` and `ZSP_HOME`.
`ZSPMenu --snapshot out.png [--audit]` renders the panel to a file.
