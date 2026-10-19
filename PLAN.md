# aws-cli-zsp plan

Zero Standing Permissions (ZSP) for AWS credentials on macOS: no key ever sits readable in `~/.aws`,
and nothing can use AWS access until you approve it with Touch ID.
It is built from scratch on aws-vault's ideas (Keychain storage, short-lived STS sessions)
and adds four things aws-vault lacks: plaintext keys are moved automatically, Touch ID guards
every use of a key, the audit trail is hash-chained, and rotate and revoke happen in one click.

## Threat model

| Threat | Today (plaintext file) | With zsp |
|---|---|---|
| Anything running as you reads `~/.aws/credentials` (`cat`, malware, a compromised npm package, an AI agent, a screenshot) | Gets every long-lived key | The file holds no secrets. Keys are in the login Keychain, and only the zsp binary can read them without a macOS prompt |
| A process asks zsp for credentials | n/a | It gets a session of at most 1h (configurable, 15m–12h). Minting a session needs Touch ID. Session credentials cannot call IAM without MFA. With `mfa enforce`, sessions carry MFA, so the policy also requires MFA from the last 5 minutes for minting keys, MFA devices or policies: a leaked hour-long session cannot make itself permanent |
| A key leaks anyway | Valid until someone notices | **Inspect** shows when AWS last saw each key used. **Revoke sessions** denies every token issued before now. **Rotate** swaps the key in seconds |
| Someone edits the audit log to hide use | n/a | Each entry hashes the one before it, and the newest hash is anchored in the Keychain. An edit, a deletion or a truncation fails `zsp audit --verify` |
| `aws configure` writes a new key in plaintext | Stays there forever | The launchd WatchPaths agent moves it within about 2s, and a 5-minute sweep catches anything the watcher missed |

Out of scope, stated honestly:
- Malware that can run zsp itself can use a cached session until it expires, the same
  trade-off aws-vault makes. `clear-sessions`, or a shorter `duration`, narrows that window.
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

## Later

- Done in 0.3.0: this Mac as a virtual MFA device, `mfa enforce`, and approval by a phone
  code (`remote enable`, `approve`) for Claude Code Remote Control. Still to do: profiles
  with `mfa_serial` + `role_arn` (AssumeRole with MFA).
- Roles: `source_profile` already works through credential_process; native AssumeRole
  caching could come later.
- IAM Identity Center (SSO) profiles, to remove long-lived keys entirely.
- Developer ID signing and notarisation, for sharing beyond this Mac.
