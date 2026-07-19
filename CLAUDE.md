# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

This repo (`cc-presence-gate`) ships **two** macOS Claude Code plugins that require a physical
**presence** proof before a high-risk tool call proceeds. A `PreToolUse` hook renders the exact
effect of a gated call and demands a hardware signature; the agent can *trigger* the prompt but
cannot satisfy it (no finger → no touch → no signature). Two presence technologies, one shared
broker engine:

- **`cc-fido`** — a FIDO/security-key touch (signs via `ssh-keygen` + the FIDO provider).
- **`cc-touch-id`** — a Touch ID / Secure Enclave biometric (signs a P-256 SE key gated by
  `.biometryCurrentSet`).

See `README.md` for the pitch and `docs/design.md` for the threat model and honest scope of the
guarantee. **`docs/design.md` describes the *original* synchronous in-hook ceremony; the code
actually ships the v2 privileged-broker architecture** (design.md flags this under the ceremony-lock
discussion). When they conflict, the code and the SDD reports (`.superpowers/sdd/task-*-report.md`)
are ground truth, not design.md's gate-flow section.

## Build & test

```bash
swift build                       # debug build → .build/debug/{cc-fido,cc-touch-id}
swift build -c release            # release build (the plain daemon/CLI binaries the installer deploys)
swift test                        # the [SW] unit suite (pure logic; no sudo/hardware)
swift test --filter CCGateCoreTests.PolicyTests           # a single test class
swift test --filter CCGateCoreTests.PolicyTests/testFoo   # a single test method
```

Test targets: `CCGateCoreTests` (the shared engine — the bulk), `CCFidoBackendTests`,
`CCTouchIDBackendTests`. `swift test` covers only the **[SW]** (software-only) portion. The
**[USER-RUN]** end-to-end verification lives in `scripts/userrun/` and needs `sudo` + a real
touch; those are authored in-repo but **must be run by the human, un-sandboxed, with output pasted
back** — Claude cannot execute them (no touch, no interactive sudo). **Do not claim an end-to-end
path works until a USER-RUN script has confirmed it on hardware.**

## Architecture — one engine, two presence backends

The security machinery is written **once**, profile-agnostic, in `CCGateCore`; each backend plugs in
its presence technology through a set of seam protocols and supplies a concrete `GateProfile`.

- **`CCGateCore`** — the whole broker/hook/policy/audit/custody/WYSIWYS engine, unit-testable. It
  knows nothing about FIDO vs Touch ID.
  - `Profile/GateProfile.swift` — a struct that parameterizes *everything* install-specific:
    `serviceAccount`, `namespace`, `sock`, `keydir`, `runDir`, `codeDir`, `policy`, `binaryName`,
    `launchdLabel`, `plist`, … The two products differ only by their `GateProfile` values.
  - `Signing/` — the seam protocols the backends implement: `Signer`, `Verifier`, `Enroller`,
    `CeremonyCanceller`, and `GateCeremony`. `Platform.swift` abstracts OS operations.
- **`CCFidoBackend`** — FIDO implementations (`FidoSigner`/`FidoVerifier`/`FidoEnroller`/
  `FidoCeremony`/`BlinkTest`) + `fidoProfile` (service account **`_ccfido`**, `/opt/cc-fido-gate`,
  socket `/var/ccfido-run/gate.sock`).
- **`CCTouchIDBackend`** — Secure Enclave / Touch ID implementations (`SecureEnclave.swift` =
  `seCreateKey`/`seSign`/`seVerify`; `TouchIdVerifier`/`TouchIdEnroller`/`TouchIdCeremony`) +
  `touchIdProfile` (service account **`_cctouchid`**, `/opt/cc-touch-id-gate`, socket
  `/var/cctouchid-run/gate.sock`, namespace `cc-touch-id-gate/v1`).
- **`cc-fido` / `cc-touch-id`** — thin CLI dispatchers (`Sources/*/main.swift`); each wires its
  profile + backend into a `GateContext` and routes a subcommand to a `CCGateCore` function.

### Runtime topology

A long-lived **broker daemon** runs as a dedicated hidden service account (`_ccfido` /
`_cctouchid`), started by a LaunchDaemon. It listens on a per-product Unix domain socket (mode 0666
— **auth is by *touch*, not caller identity**). The broker **exclusively holds the signing key** and
serializes signing. Clients (the hook) connect, receive a challenge, run the presence ceremony
client-side, and send back a signature; the broker verifies off-session with only the public key.

### The gate flow

1. Claude Code fires the managed `PreToolUse` hook → `<binary> hook` (`hookMain`, `HookLogic.swift`).
2. `Policy.decide` (`Policy.swift`) returns `.pass` / `.gate` / `.denyNudge` from `policy.json`.
   - **Write/Edit**: `sensitive_globs` win over `allow_tier`; unmatched writes default to **gate**.
   - **Bash**: `bash_advisory` regexes are **advisory only** — a match gates, but this list is not a
     security guarantee (arbitrary shell gating is undecidable).
   - **MCP** (`mcp__server__tool`): **default-gate**; only explicit `(server, tool)` pairs in
     `mcp_allow` pass. Not a verb-denylist.
   - **`.denyNudge`**: locked path → exit 2 with a "use `<binary> write`" message.
3. On `.gate`, the client (`Client.swift`) opens the socket and runs one of two broker ops:
   - **`approve`** — best-effort verdict, **no write** (Bash/MCP/Edit gating). Broker builds a
     `SignedDocument` over `{tool,input,cwd}`, challenges, verifies the touch, audits, returns ok/deny.
   - **`execute-write`** — the broker itself performs the privileged, `uchg`-protected write to an
     enrolled target after verifying the touch (`<binary> write <path>` with content on stdin).
4. `confirmAndSign` shows an `osascript` dialog **and arms the key concurrently** ("touch from the
   get-go") — touch / Enter / Approve all approve; Cancel / give-up (60s) / walk-away deny.
5. Verified → hook emits the `allow` JSON on clean exit 0. Denied/error → exit 2 (fail-closed).

### Trust model (how the agent can't cheat)

- **Control files** (`allowed_signers`, `custody.json`, `audit.log`, `policy.json`, the socket, the
  lock) are root- or service-account-owned and `execute-write`-denied unconditionally
  (`controlDenylist` + `isControlPath`). Enrolled write targets are service-account-owned + `chflags
  uchg` (immutable); only the broker can flip `uchg` and write. **Service-account ownership — not the
  `uchg` flag — is the real write barrier.**
- **Custody registry** (`custody.json`): the broker writes *only* to paths in this registry
  (`isEnrolledTarget`) and never to control paths. `CustodyRegistry.add` normalizes via `Broker.normPath`.
- **Path canonicalization**: `Broker.normPath` folds the macOS `/private` firmlink (`/var` ==
  `/private/var`) *without* `realpath`. Symlink-redirect defense is the post-open `F_GETPATH` re-check
  in `uchgWrite` (open `O_NOFOLLOW`, fstat regular + `nlink==1` + owner service-account, re-derive the
  real path, re-run control/enrolled checks, *then* `ftruncate`+write) — **not** the string normalization.
- **Env scrubbing**: `scrubEnv` (one allowlist, `HOME/USER/LANG/__CF_USER_TEXT_ENCODING` + a fixed
  `PATH`) is the single source of truth; every child spawn (sign/verify/dialog/`sudo`) uses
  `scrubbedEnv()`. This drops `DYLD_*`, `SSH_SK_*`, `BASH_ENV`, etc.
- **WYSIWYS**: `humanRendering` (`Canonical.swift`) escapes confusables / zero-width / bidi to a
  `<U+XXXX>` token so `execution_input → human_rendering` is injective (you can't render a benign
  string while signing a malicious one). Large writes fall back to digest mode (path + sha256 + size).
- **Audit** (`Audit.swift`): append-only, hash-chained (`seq` + `prev_hash`), `flock`-serialized.
  Best-effort/tamper-resistant, **not** cryptographically authenticated against a same-uid forger.
- **Peer cred** (`peerUID`) is recorded for forensics; it is *not* the auth boundary (the touch is).
- **cc-fido only — two `ssh-keygen` binaries** (`FidoProfile`): Homebrew OpenSSH for **signing** (has
  the FIDO provider), stock `/usr/bin/ssh-keygen` for **verifying**. cc-touch-id signs/verifies
  in-process via `SecKey` APIs, no subprocess.

### Key files (all shared logic lives in `Sources/CCGateCore/`)

| File | Role |
|---|---|
| `Broker.swift` | Daemon: socket serve loop, `handleExecuteWrite`/`handleApprove`, `uchgWrite`, path auth (`normPath`/`isControlPath`/`isEnrolledTarget`). |
| `Client.swift` | Client side: `confirmAndSign` (concurrent dialog+arm), `runWrite`, `runApprove`. |
| `HookLogic.swift` | `hookMain`, `decideAndEmit` (verdict → exit code + allow/deny JSON), `scrubEnv`. |
| `Policy.swift` | `policy.json` parse (fail-closed regex validation) + `decide`. |
| `Canonical.swift` | `SignedDocument`, `canonicalBytes`, `humanRendering`, confusable escaping. |
| `Crypto.swift` | ssh-keygen `sign`/`verify` spawns, `SignCanceller`, `scrubbedEnv`. |
| `Custody.swift` | `CustodyRegistry`, `checkAncestors` (agent-writable-ancestor warning). |
| `Profile/GateProfile.swift` | The install-fixed parameters struct both products instantiate. |
| `Signing/{Signer,Verifier,Enroller,CeremonyCanceller}.swift` | The seams each backend implements. |
| `CLIHelpers.swift`, `Install.swift`, `Enroll.swift`, `Status.swift`, `Wire.swift`, `Platform.swift`, `GateContext.swift` | Rendering/privileged-run helpers, install/enroll/status logic, wire protocol, OS + context plumbing. |

## Install / enroll / teardown

Each product has its own plugin + guided install skill: `/cc-fido:install`
(`plugins/cc-fido/skills/install/SKILL.md`) and `/cc-touch-id:install`
(`plugins/cc-touch-id/skills/install/SKILL.md`). They drive the privileged subcommands
(`install`/`enroll`/`activate`/`uninstall`) one at a time, prompting for sudo/touch as needed.
Enrollment ordering is **lock-first, then register** (fails safe: over-protected, never
registered-but-writable) with `rollbackFileLock` restoring the *captured* original uid+mode on
registry-add failure.

Privileged **acceptance verification** is scripted under `scripts/userrun/` (needs `sudo` + a touch),
e.g. `touchid_accept.sh` (custody/gated-write/audit suite), `touchid_notarize_accept.sh` (the
distribution-build acceptance), `touchid_cancel.sh`, and the FIDO `task7_accept.sh`.

### Internal (`_`-prefixed) subcommands

`main.swift` dispatches internal subcommands invoked *by the scripts*, not by hand (e.g.
`_render-plist`, `_render-managed`, `_verify-audit`, `_registry-add`, `_validate-policy`,
`_presence-test`/`_blink-test`). `_verify-audit` and `_registry-add` run via `sudo -u <service
account>` so they can touch the 0600 service-account-owned files.

## cc-touch-id: two binaries, not one (critical)

Unlike cc-fido, cc-touch-id ships **two** binaries and using the wrong one for a signing op crashes
or hangs instead of prompting:

- **Plain daemon/CLI** at `$CODE_DIR/cc-touch-id` (`swift build -c release`, ad-hoc signed) —
  **verify-only**; used by the LaunchDaemon, `enroll-file`/`enroll-dir`, `_verify-audit`,
  `_validate-policy`, control-path canaries. Never touches the Secure Enclave.
- **Entitled/provisioned `.app`** at `$CODE_DIR/cc-touch-id.app/Contents/MacOS/cc-touch-id` —
  **required for anything that SIGNS** (`write`, `enroll`, the hook). A bare CLI binary is
  amfid-killed the instant it touches the SE key. See `packaging/` and `task0-se/`.

### Packaging the entitled `.app`

The SE key needs the `keychain-access-groups`/`application-identifier` access group, which macOS
requires an embedded **provisioning profile** to authorize (a bare Developer ID signature fails:
amfid SIGKILL, or `SecKeyCreateRandomKey -34018`). Two build scripts in `packaging/`:

- **`build-signed.sh`** — author-machine build (Xcode automatic signing, Development profile).
  Launches + creates the SE key **on the signing Mac only**; carries `get-task-allow`; **not**
  notarized. The no-Developer-ID fallback.
- **`build-distribution.sh`** — the notarized, Gatekeeper-clean distribution build: `xcodebuild
  archive` → `-exportArchive method: developer-id` (`ExportOptions.plist`) →
  `notarytool submit --wait` → `stapler staple`. The Developer ID profile grants
  `application-identifier` (the SE access group) **without** `get-task-allow` (TID-5 intact). See
  the RESOLVED entry in `docs/FOLLOWUPS.md` and
  `docs/superpowers/specs/2026-07-19-cc-touch-id-notarized-distribution-design.md`.

### Distribution: three install paths (who obtains the `.app`)

The entitled `.app` reaches a user's `/opt` one of three ways; the install skill (Step 0) branches on
whether they have a Developer ID identity:

- **Self-build** — a user with their own Apple Developer account runs `build-distribution.sh`
  (retargeting `DEVELOPMENT_TEAM`/bundle id if their team ≠ `HH3SJBAS42`) or `build-signed.sh`, then
  installs their own binary (`EXPECTED_TEAM=<their-team>`). Highest trust: they compiled + signed it.
- **Download the maintainer's prebuilt** — `install/fetch-app.sh` fetches the release pinned in
  `plugins/cc-touch-id/install/release.json` and verifies **SHA-256 pin + notarization + team + no
  get-task-allow + stapled** before handing the path to `install.sh`. Fails closed if unpublished.
- **Maintainer publish** — `packaging/publish-release.sh` (after `build-distribution.sh`) uploads the
  stapled `.app` as a GitHub release asset and writes the pin into `release.json` (commit by hand).

`install.sh` itself hard-fails on an invalid signature or a team ≠ `EXPECTED_TEAM` (default
`HH3SJBAS42`, `=any` to skip) before copying into `/opt` — protecting all three paths.

## Conventions & gotchas

- **Fail-closed everywhere**: unreadable payload, missing policy, bad regex, service-account lookup
  failure, unknown tool → deny (exit 2). Preserve this when editing decision paths.
- **The service account must exist** for most runtime behavior; several code paths fail closed if
  `getpwnam("_ccfido")` / `getpwnam("_cctouchid")` returns nil.
- **Namespaces/handles are install-fixed**: cc-fido's placeholder `cc-fido-gate@example.test` and
  `~/.ccfido/gate_sk`, cc-touch-id's `cc-touch-id-gate/v1`. Treat them as wired for the current
  single-user setup. (The `ns` domain-separator field exists on `SignedDocument` but is **not** wired
  into the broker challenge — a documented deferred item.)
- **`docs/FOLLOWUPS.md`** tracks known non-blocking residuals (partial-enroll rollback, symlink-enroll
  inconsistency, same-path write race, unlocked custody RMW, etc.). Check it before "fixing" something
  that may already be a documented, accepted residual.
- **SDD provenance**: built spec-driven. `.superpowers/sdd/` holds per-task briefs, reports, and
  review diffs; `docs/superpowers/{plans,specs,spikes}/` hold the plans/designs/feasibility probes;
  `task0*/` are Task-0 platform-fact probes the design depends on.
