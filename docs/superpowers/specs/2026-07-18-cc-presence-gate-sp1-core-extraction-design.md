# cc-presence-gate — SP1: Core extraction + monorepo restructure (FIDO only)

**Date:** 2026-07-18
**Status:** Design approved; pending spec review → implementation plan.
**Author:** Sean Perkins (with Claude)

## Context

`cc-fido-gate` (this repo) gates high-risk Claude Code tool calls behind a physical FIDO
security-key touch. A parallel branch (`worktree-touch-id-gate`, package `cc-touch-id-gate`)
forked the same enforcement engine and swapped the crypto primitive for the macOS Secure
Enclave + Touch ID. The fork's own README states it plainly: *"the enforcement architecture —
hook, WYSIWYS canonical-document binding, broker/daemon custody, socket transport — is shared;
only the crypto primitive and enrollment differ."*

Two problems today:

1. **Drift.** The Touch ID fork branched *before* the guided-install layer landed on `main`
   (`Install` / `Enroll` / `Status` / `Platform` subcommands + the `/cc-fido:install` skill).
   The two cores are diverging and the shared ~90% is maintained twice.
2. **Distribution.** A Task-0 finding (`task0-se/REPORT.md`) proves the Touch ID variant must
   ship as a **provisioned, notarized `.app`** — an entitled Secure-Enclave binary is SIGKILL'd
   under a development cert without an embedded provisioning profile, and bare SwiftPM CLIs
   cannot embed one. FIDO ships as a plain CLI. Their install stories are genuinely different.

### Decisions already settled (out of scope to re-litigate here)

- **One monorepo**, not three repos. The shared engine is extracted into a library target;
  two thin products depend on it. Promotion to a standalone core repo later is a mechanical
  lift once the module boundary exists.
- **Distribution via a Claude Code plugin *marketplace*.** The repo carries
  `.claude-plugin/marketplace.json` listing two plugins (`cc-fido-gate`, `cc-touch-id-gate`);
  users `/plugin install` whichever they want. Shared `Sources/` is build-time only and never
  ships into `~/.claude`.
- **Umbrella name: `cc-presence-gate`** — names the real property (hardware-backed proof of
  human presence) that unifies both methods.
- **Touch ID distribution: public, notarized `.app`** (Apple Developer Program + Developer-ID +
  notarization). This is SP3's concern, noted here only because it justifies the module split.
- **Decomposition into ordered sub-projects**, each with its own spec → plan → build cycle:
  - **SP1 (this spec)** — Core extraction + `cc-presence-gate` restructure, FIDO only.
  - **SP2** — Touch ID backend on the extracted core + guided-install port.
  - **SP3** — Touch ID notarization + distribution pipeline.

## SP1 goal and non-goals

**Goal:** Extract the method-agnostic engine into a `CCGateCore` library behind three seams
(`Signer`/`Verifier`, `Enroller`, `GateProfile`), restructure this repo into the
`cc-presence-gate` monorepo + marketplace layout, and keep the **FIDO product working with
zero behavior change**. SP1 is a pure refactor + repackage; the existing [SW] test suite is the
safety net.

**Non-goals (deferred):**

- No Touch ID / Secure Enclave code (SP2).
- No notarization or `.app` packaging (SP3).
- No new gate behavior, policy semantics, or threat-model changes.
- No functional change to the `cc-fido` CLI surface or the `/cc-fido:install` skill.

**Success is defined by absence of change**, not new capability: FIDO builds, its [SW] suite
passes unchanged, and the on-hardware e2e still gates.

## Architecture

### Module topology (one `Package.swift`, `name: "cc-presence-gate"`)

```
Sources/
  CCGateCore/      # library — method-agnostic engine
    Audit · Broker · Canonical · Custody · HookLogic · Policy · Wire · CLIHelpers
    Client (de-FIDO'd) · Install · Enroll (orchestration) · Status · Platform
    Signing/  Signer.swift · Verifier.swift · Enroller.swift   (protocols)
    Profile/  GateProfile.swift
  CCFidoBackend/   # library (deps: CCGateCore) — FIDO conformances
    FidoSigner.swift · FidoVerifier.swift   (ex-Crypto.swift)
    FidoEnroller.swift                       (sk-keygen + blink-test + allowed_signers)
    FidoProfile.swift                        (fidoProfile: GateProfile)
  cc-fido/         # executable (deps: CCGateCore + CCFidoBackend)
    main.swift     # constructs fidoProfile + FIDO backend, injects into core, dispatches
Tests/
  CCGateCoreTests/     # Policy, Canonical, Wysiwys, Broker (allowlist/logic), Audit,
                       #   Custody, Wire, Hook, CLIHelper — method-agnostic
  CCFidoBackendTests/  # blink-test, enroll-plan, FIDO crypto-adjacent bits
```

**Litmus test for a clean extraction:** `CCGateCore` contains **zero** literal references to
`ssh-keygen`, `_ccfido`, `/var/ccfido`, `cc-fido-gate@example.test`, or `com.cc-fido-gate.*`.
Everything method- or identity-specific arrives via `GateProfile` or a protocol.

**Why a separate `CCFidoBackend` library** (vs folding conformances into the `cc-fido`
executable): SP2's `CCTouchIDBackend` becomes a symmetric peer, and the core's protocol
boundary is exercised by a real second consumer instead of only the executable. Keeps the seam
honest.

### The three seams

**`struct GateProfile`** — replaces the `Paths` constant bag. Injected at composition time.

Fields (supplying *roots + identity*; core still composes *structure* like
`<keydir>/allowed_signers`):

| Field | FIDO value (today's `Paths`) |
|---|---|
| `principal` (service account) | `_ccfido` |
| `namespace` | `cc-fido-gate@example.test` |
| `signPrincipal` | `gate-principal` |
| `keydir` / `runDir` / `sock` | `/var/ccfido` · `/var/ccfido-run` · `/var/ccfido-run/gate.sock` |
| `codeDir` / `policy` | `/opt/cc-fido-gate` · `/opt/cc-fido-gate/policy.json` |
| `launchdLabel` / `plist` | `com.cc-fido-gate.brokerd` · `/Library/LaunchDaemons/…plist` |
| `managedSettings` / `claudeCodeDir` | `/Library/Application Support/ClaudeCode/…` |
| `keyHandle` | `~/.ccfido/gate_sk` |
| `signKeygen` / `verifyKeygen` | Homebrew ssh-keygen · `/usr/bin/ssh-keygen` |

Control-file paths (`allowedSigners`, `audit`, `custody`, `ceremonyLock`) and the
`controlDenylist` are **derived** by core from the profile roots, so the deny logic stays in
one place. Each method gets **distinct** roots + account so a machine with both plugins
installed (but only one active) never stomps the other's state.

**`protocol Signer`** (client-side): `sign(challenge: Data, canceller: SignCanceller?) throws -> Data`.
`FidoSigner` wraps today's free `sign(...)` (spawns Homebrew ssh-keygen `-Y sign`). `SignCanceller`
stays in core (transport-agnostic cancellation).

**`protocol Verifier`** (broker-side): `verify(challenge: Data, signature: Data) -> Bool`.
`FidoVerifier` wraps today's free `verify(...)` (spawns stock ssh-keygen `-Y verify` against
`allowed_signers`).

**`protocol Enroller`**: FIDO impl = `sk` keygen + `allowed_signers` append + negative blink-test
(`planEnrollFile`/`planEnrollDir` orchestration stays in core; the key-material + blink steps
move to `FidoEnroller`).

**Composition:** `Broker` takes `(Verifier, GateProfile)`; `Client` takes `(Signer, GateProfile)`;
`main.swift` builds the FIDO `Signer`/`Verifier`/`Enroller` + `fidoProfile` and injects them.
The `sign`/`verify` functions already accept `namespace`/paths/`keygen` as parameters, so the
protocol wrap is thin.

### Marketplace packaging (folds into SP1)

```
.claude-plugin/marketplace.json     # lists cc-fido-gate now; cc-touch-id-gate added in SP2
plugins/cc-fido-gate/
  .claude-plugin/plugin.json
  skills/cc-fido-install/SKILL.md    # moved from .claude/skills/, function unchanged
  install/policy.json.template
  README.md                          # FIDO-specific
docs/   scripts/   task0*/           # shared / historical — stay at root
```

- GitHub repo renamed `cc-fido-gate` → `cc-presence-gate` (GitHub preserves the redirect; the
  Touch ID fork's README link is updated in SP2).
- **Mutual-exclusion guard:** both gates ultimately write a `PreToolUse` entry into the single
  system-wide managed-settings file, so two *active* gates would double-prompt / fight. SP1
  *designs* the hook-point — install/activate consults a "foreign gate present?" check — but it
  is only *enforceable* in SP2 when a second gate exists. SP1 ships the check as a no-op-safe
  stub that already refuses if it detects a non-matching gate label, so SP2 only supplies the
  second label.

## Migration strategy

Ordered so the build/test stays green at each step (details belong to the plan, not this spec):

1. Rename `Sources/CCFidoCore` → `Sources/CCGateCore`; `Package.swift` `name` →
   `cc-presence-gate`; add empty `CCFidoBackend` target + `cc-fido` executable target.
2. Introduce `GateProfile` + the three protocols in `CCGateCore`; add `fidoProfile` +
   `FidoSigner`/`FidoVerifier`/`FidoEnroller` in `CCFidoBackend` wrapping the existing free
   functions.
3. Thread `GateProfile` through `Broker`/`Client`/`Install`/`Status`/`Enroll`, replacing
   `Paths.*` reads. **Delete `Paths` outright** (see Risks) so the compiler enumerates every
   remaining call site rather than letting a stray hardcoded constant survive.
4. Move `Crypto.swift`'s FIDO specifics into `CCFidoBackend`; leave transport-agnostic helpers
   (`SignCanceller`, `scrubbedEnv`/`scrubEnv`) in core.
5. Split `CCFidoCoreTests` → `CCGateCoreTests` + `CCFidoBackendTests`.
6. Restructure into `plugins/cc-fido-gate/` + `.claude-plugin/marketplace.json`.

## Testing

- **[SW] (Claude-runnable):** full existing unit suite must pass with **no assertion changes**
  beyond mechanical target/import splits. The suite passing unchanged *is* the proof that the
  refactor preserved behavior. New tests: `GateProfile` composition (derived control paths,
  denylist) and that `CCGateCore` builds without any FIDO backend linked.
- **[USER-RUN] (human, on hardware, un-sandboxed):** re-run the FIDO enroll + gate e2e
  (`scripts/userrun/…` / `cc-fido enroll` → gated tool call → touch). [SW] cannot cover the
  daemon/socket/touch path, so this is the load-bearing acceptance for SP1. Do not claim SP1
  complete until a USER-RUN confirms the gate still fires and denies correctly.

## Risks

- **`Paths` is referenced widely** (`Broker`, `Client`, `Install`, `Status`, `main`). Threading
  the profile is the bulk of the diff; a missed `Paths.*` that stays hardcoded silently breaks
  SP2's second profile. Mitigation: delete `Paths` outright so the compiler enumerates every
  call site.
- **Control-denylist derivation** must stay byte-for-byte equivalent to today's
  `Paths.controlDenylist` for FIDO, or the write-authorization barrier weakens. Covered by a
  `CCGateCoreTests` equivalence assertion against the known FIDO paths.
- **Behavior drift hiding in "mechanical" moves.** Mitigation: no logic edits during extraction;
  the green [SW] suite + USER-RUN e2e gate the claim of "no change."

## Done criteria

- `swift build` and `swift test` green.
- `CCGateCore` free of FIDO / `_ccfido` / ssh-keygen / `cc-fido-gate@…` / `com.cc-fido-gate.*`
  literals (grep-verified).
- FIDO gate e2e re-confirmed on hardware via USER-RUN.
- `cc-fido-gate` installs from the marketplace layout with its skill + hook unchanged in
  function.
- SP2 and SP3 remain cleanly startable: the `GateProfile` + protocol seams admit a Touch ID
  backend without touching `CCGateCore`.
