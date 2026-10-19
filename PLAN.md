# aws-cli-zsp plan

Zero Standing Permissions (ZSP) for AWS credentials on macOS: no key ever sits readable in `~/.aws`,
and nothing can use AWS access until you approve it with Touch ID.
It is built from scratch on aws-vault's ideas (Keychain storage, short-lived STS sessions)
and adds four things aws-vault lacks: plaintext keys are moved automatically, Touch ID guards
every use of a key, the audit trail is hash-chained, and rotate and revoke happen in one click.

## Threat model

| Threat | Today (plaintext file) | With zsp |
|---|---|---|
| Anything running as you reads `~/.aws/credentials` (`cat`, malware, a compromised npm package, an AI agent, a screenshot) | Gets every long-lived key | The file holds no secrets. Keys are sealed by the Secure Enclave and only open after Touch ID |
| A process asks zsp for credentials | n/a | It gets a session of at most 1h (configurable, 15m–12h). Minting a session needs Touch ID. Session credentials cannot call IAM without MFA. With `mfa enforce`, sessions carry MFA, so the policy also requires MFA from the last 5 minutes for minting keys, MFA devices or policies: a leaked hour-long session cannot make itself permanent |
| A key leaks anyway | Valid until someone notices | **Inspect** shows when AWS last saw each key used. **Revoke sessions** denies every token issued before now. **Rotate** swaps the key in seconds |
| Someone edits the audit log to hide use | n/a | Each entry hashes the one before it, and the newest hash is sealed in the vault. An edit, a deletion or a truncation fails `zsp audit --verify`, unless it is done by malware running as you (below) |
| `aws configure` writes a new key in plaintext | Stays there forever | The launchd WatchPaths agent moves it within about 2s, and a 5-minute sweep catches anything the watcher missed |

Out of scope, stated honestly:
- Malware that can run zsp itself can use a cached session until it expires, the same
  trade-off aws-vault makes. `clear-sessions`, or a shorter `duration`, narrows that window.
- Malware running as you can seal a key for *its own* AWS account under your profile's
  name: sealing needs only the enclave's public key. Caught since 0.3.1 by account pinning:
  the first session records the account and IAM ARN in the login Keychain (an item only
  zsp can change without a prompt; a hash in the vault folder would just be recomputed),
  and every new session is checked against it. The pin also holds the issued session's key
  id, so a planted session is not served. `pin reset` (Touch ID) re-pins.
- Malware running as you can rewrite `credential_process` in `~/.aws/config` to its own
  program, bypassing zsp. `doctor` reports unwired profiles.
- Malware running as you can rewrite the audit log and re-seal its anchor, because the
  anchor uses the no-prompt enclave key. The trail is a record, not evidence against an
  attacker on the Mac. Planned: an off-box copy (CloudWatch, or S3 with Object Lock).
- Both are closed properly only by Developer ID signing with a keychain access group, so
  the enclave keys are usable by this app alone.
- Root, or someone who has your login password, can unlock the Keychain.

## Architecture

```
~/.aws/config  credential_process = …/aws-cli-zsp.app/Contents/MacOS/zsp credential-process --profile X
                  │
aws CLI / SDKs ───┘──▶ zsp ──▶ Keychain (session cache) ──hit──▶ JSON creds
                          └──miss──▶ Touch ID ──▶ Keychain (master key) ──▶ STS GetSessionToken
launchd (WatchPaths ~/.aws/*) ──▶ zsp import --auto ──▶ Keychain + scrub the files
Menu bar app (ZSPMenu) ── reads metadata and the audit log; every action shells out to zsp
```

- **Secure Enclave vault** (0.2.0): keys are sealed to an enclave key that demands Touch ID; the command is a helper app named "AWS CLI: ZSP" in dialogs.
  single code signature. It is signed with the local stable identity ("Claude Burst Local
  Signing"), so rebuilds keep that trust.
- **ZSPCore** (library, unit tested): INI editing that preserves comments, the Keychain,
  Touch ID, SigV4 (verified against AWS's published test vector), the STS and IAM Query
  API, the vault logic, the audit chain, and identifying who made each request.
- **Fail closed.** A key is removed from a file only after its Keychain copy has been read
  back. If the audit log can't be written, no credentials are issued.

## Phases

1. ✅ **Core plus tests**: 29 tests covering import and scrub, idempotency, key
   replacement, half-written pairs, a failing Keychain, session caching, Touch ID count,
   rotate (including propagation retries and the two-key limit), revoke policy, delete,
   forget and restore, inspect, audit tamper cases, and the real Keychain.
2. ✅ **CLI** (`zsp`): every command in `zsp help`, with `--json` for the app.
3. ✅ **Menu bar app**: an "In use" tab (profiles, key, session expiry, last use and by
   whom), an "Audit" tab (trail and chain status), per-profile actions (Rotate, Revoke
   sessions, Inspect, Clear session, Disable, Delete, Forget) with a confirmation that
   explains each one, a red shield when plaintext is found, and a notification when a key
   is moved.
4. ✅ **Bundle and sign**: `scripts/build-app.sh` runs the tests, builds, assembles
   `aws-cli-zsp.app` (ZSPMenu + zsp), signs it and installs it to `~/Applications`.
5. ✅ **Sandbox end-to-end**: point `AWS_SHARED_CREDENTIALS_FILE`, `AWS_CONFIG_FILE` and
   `ZSP_HOME` at a temp directory with fake keys. Run import, scan, list, audit and a real
   `aws` call through credential_process (AWS should return InvalidClientTokenId, which
   proves signing and the transport work end to end). The real `~/.aws` is not touched.
6. ✅ **README and repo**: commit locally.

## Needs your go-ahead (not done automatically)

- **Live migration** (`zsp install`): it rewrites your real `~/.aws` files. Other running
  sessions and deploy scripts (`backup-s3.sh` uses `default`) will get a Touch ID prompt
  the first time each profile is used, and then once an hour.
- **Rotating the three exposed keys**: one click each in the menu once installed. That is
  an outward change in your AWS accounts.
- **GitHub**: `gh repo create andrewbakercloudscale/aws-cli-zsp --private --source . --push`.

## Next: no long-lived keys (IAM Roles Anywhere, CA on the Pi)

Status: design, not started. **Scope: our own AWS accounts only.**

**Constraint (decided):** we cannot ask clients to change their AWS accounts, and some give
us read-only IAM users. So for client accounts the long-lived key is theirs to issue and
cannot be removed, only guarded. That is what key mode already does, and it stays the mode
for every client profile:
- The key is sealed by the Mac's Secure Enclave and every new session needs Touch ID.
  The Pi has no secure enclave, so moving client keys there (a broker) would make them
  extractable by anyone who takes the Pi: weaker, not stronger, for client keys.
- GetSessionToken needs no IAM permission, so sessions work for read-only users.
- Anything that writes to IAM needs permissions a read-only user lacks: rotate,
  disable/delete key, revoke sessions, `mfa setup`/`enforce`/`add-phone`. For those
  profiles zsp should detect AccessDenied and show "read-only: managed by the client"
  rather than offer the buttons.
- What the Pi can still add for client profiles without holding secrets: an off-box
  copy of the audit trail.

### Goal

No IAM access key exists anywhere: not on the Mac, not on the Pi, not in AWS. A session
comes from IAM Roles Anywhere, which accepts an X.509 certificate for a Secure Enclave key
on this Mac. Touch ID still approves every new session, as today.

### Pieces

| Piece | Where | What it does |
|---|---|---|
| Root CA | Offline (created once, kept off the Pi, e.g. encrypted on a USB stick) | The trust anchor in AWS. Only used to sign the Pi's intermediate |
| Intermediate CA | Pi, in its own container, reachable only through the Cloudflare tunnel; not the WordPress container | Signs short-lived device certificates. Revocable without touching the root |
| Device key | Mac, Secure Enclave, P-256, Touch ID required | Signs Roles Anywhere `CreateSession`. Never leaves the chip |
| Remote key | Mac, Secure Enclave, P-256, no Touch ID | For approval while away (below). Useless without a fresh certificate |
| Hub account | One AWS account of ours | The only account with Roles Anywhere set up |
| Account roles | Each of our own accounts | One role per profile, trusting the hub role |

### Changes in AWS accounts

- **Hub account (ours):** a trust anchor (the root CA certificate), a Roles Anywhere
  profile, and one role per use, trusted by `rolesanywhere.amazonaws.com` with conditions
  on the certificate subject. Free with our own CA (AWS Private CA would be ~$400/month).
- **Other accounts of ours:** a cross-account role trusting the hub role.
- **Client accounts:** none. They stay on key mode (above).

### Flows

- **Enrol the Mac (once):** zsp creates the device key, sends a CSR signed by it to the Pi,
  you approve with a passkey tap (Face ID on your phone) against the Pi, the Pi returns a
  certificate valid 7 days. Renewal: the same, with Touch ID instead of the passkey while
  the old certificate is still valid.
- **A command at the Mac:** credential_process → Touch ID → the device key signs
  `CreateSession` (SigV4 X.509, `AWS4-X509-ECDSA-SHA256`) → a 1-hour hub session →
  `AssumeRole` into the account's role → cached session. The Pi is not involved, so the Pi
  being down does not stop work until the certificate expires.
- **Approval while away (Claude Code Remote Control):** zsp asks the Pi; you get a
  passkey prompt on your phone; on approval the Pi signs a **15-minute** certificate for
  the remote key, with a distinct OU, accepted only by a Roles Anywhere profile limited to
  1-hour sessions. This replaces typing a 6-digit TOTP code. The remote key works without
  Touch ID, so the window is that 15-minute certificate, and only after your tap.

### Revocation and break-glass

- One Mac: stop renewing its certificate (7 days at most), or import a CRL into the hub.
- The Pi compromised: delete or disable the trust anchor in the hub account. Every
  certificate stops working at once; the other accounts need no change. Re-issue the
  intermediate from the offline root.
- Break-glass: console sign-in with MFA in the hub account, kept outside zsp.

### What it fixes, what it does not

| Gap | After |
|---|---|
| A long-lived key to steal, copy or leak | ✅ none exists |
| Key swap in the vault | ✅ nothing to swap; the certificate and role are checked by AWS |
| Audit rewritten on the Mac | ✅ CloudTrail in the hub logs every `CreateSession` with the certificate serial; the Pi logs every certificate it signs |
| Key rotation | ✅ gone: certificates expire by themselves |
| Malware running as you using a cached session | ⚠️ unchanged (inherent: anything you can do without a prompt, it can). Shorter sessions narrow it |
| `~/.aws/config` rewired to another program | ⚠️ unchanged; `doctor` reports it |
| The Pi compromised | ⚠️ attacker can mint certificates until the trust anchor is disabled; no keys to rotate afterwards |

### Work

1. Swift: Roles Anywhere `CreateSession` signing with a Secure Enclave key (AWS's
   `aws_signing_helper` cannot use enclave keys). Tests against AWS's published examples.
2. Pi service: intermediate CA, CSR endpoint, passkey (WebAuthn) approval, issuance log.
   Its own container; no inbound ports beyond the tunnel.
3. zsp: per-profile mode (`key` as today, or `roles-anywhere`), enrol, renew, and the
   remote flow. Key mode stays as the fallback during migration.
4. A CloudFormation template for our other accounts (the cross-account role), and a
   setup command for the hub.
5. Migrate one profile (`bedrock`), then the rest; delete the IAM user keys last.

### Open decisions

- Which account is the hub.
- Where the offline root CA key lives.
- Certificate lifetimes (7 days device, 15 minutes remote are proposals).
- Whether it is worth it: it only helps our own accounts. If most profiles are client
  keys, the read-only handling and off-box audit above matter more.

## Later

- Done in 0.3.0: this Mac as a virtual MFA device, `mfa enforce`, and approval by a phone
  code (`remote enable`, `approve`) for Claude Code Remote Control. Still to do: profiles
  with `mfa_serial` + `role_arn` (AssumeRole with MFA).
- Roles: `source_profile` already works through credential_process; native AssumeRole
  caching could come later.
- IAM Identity Center (SSO) profiles: an alternative to Roles Anywhere where accounts sit in one AWS Organization.
- Off-box audit: ship each entry to CloudWatch Logs or S3 with Object Lock.
- Developer ID signing and notarisation, for sharing beyond this Mac, and so the enclave
  keys can be restricted to this app (a keychain access group).
