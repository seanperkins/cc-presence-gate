# cc-presence-gate — SP1: Core extraction + monorepo restructure (FIDO only)

**Date:** 2026-07-18 (rev 2 — incorporates 5-model review)
**Status:** Design under review → implementation plan.
**Author:** Sean Perkins (with Claude)

## Context

`cc-fido-gate` (this repo) gates high-risk Claude Code tool calls behind a physical FIDO
security-key touch. A parallel branch (`worktree-touch-id-gate`, package `cc-touch-id-gate`)
forked the same enforcement engine and swapped the crypto primitive for the macOS Secure
Enclave + Touch ID. The fork's own README states it plainly: *"the enforcement architecture —
hook, WYSIWYS canonical-document binding, broker/daemon custody, socket transport — is shared;
only the crypto primitive and enrollment differ."*

The Touch ID fork branched *before* the guided-install layer landed on `main` (`Install` /
`Enroll` / `Status` / `Platform` subcommands + the install skill). The two cores are diverging
and the shared ~90% is maintained twice. SP1 stops that drift by extracting the shared engine.

### Decisions already settled (out of scope to re-litigate here)

- **One monorepo**, not three repos. The shared engine becomes a library target; two thin
  products depend on it. Promotion to a standalone core repo later is a mechanical lift once
  the module boundary exists.
- **Distribution via a Claude Code plugin *marketplace*** (`.claude-plugin/marketplace.json`
  listing two plugins). **How the compiled binary reaches an installed user is an open design
  question resolved in this spec (§Marketplace), not assumed.**
- **Umbrella name: `cc-presence-gate`** — the property (hardware-backed proof of human presence)
  that unifies both methods.
- **Touch ID distribution: public, notarized `.app`** (Apple Developer Program). SP3's concern.
- **Ordered sub-projects**, each with its own spec → plan → build cycle:
  - **SP1 (this spec)** — Core extraction + `cc-presence-gate` restructure, FIDO only.
  - **SP2** — Touch ID backend on the extracted core + guided-install port + **mutual-exclusion
    & ownership-aware managed-settings** (see §Deferred-to-SP2, moved here after review).
  - **SP3** — Touch ID notarization + distribution pipeline.

## SP1 goal and non-goals

**Goal:** Extract the method-agnostic engine into a `CCGateCore` library behind four seams
(`Signer`/`Verifier`, `Enroller`, `CeremonyCanceller`, `GateProfile`), restructure this repo
into the `cc-presence-gate` monorepo + marketplace layout, and keep FIDO's **runtime gate
behavior** unchanged. SP1 is a refactor + repackage; the [SW] suite plus a USER-RUN e2e are the
safety net.

**Non-goals (deferred):**

- No Touch ID / Secure Enclave code (SP2).
- No notarization or `.app` packaging (SP3).
- No new gate *runtime* behavior, policy semantics, or threat-model changes.
- **No mutual-exclusion / ownership-aware managed-settings logic (moved to SP2 — see review
  finding below; it cannot be built or tested honestly with only one gate present).**

**What SP1 DOES change (was wrongly listed as a non-goal in rev 1):** the install **skill**
changes — its invocation name is renamed for plugin namespacing and it gains a binary-bootstrap
step (§Marketplace). "Function unchanged" was false and is dropped.

**Success:** FIDO's runtime gate behavior is preserved (green [SW] suite + USER-RUN e2e), the
grep gate confirms `CCGateCore` carries no FIDO identity, and SP2's Touch ID backend is
startable **without editing `CCGateCore`**.

## Architecture

### Module topology (one `Package.swift`, `name: "cc-presence-gate"`)

```
Sources/
  CCGateCore/      # library — method-agnostic engine
    Audit · Broker · Canonical · Custody · HookLogic · Policy · Wire · CLIHelpers
    Client (de-FIDO'd) · Install · Enroll (orchestration) · Status · Platform
    Signing/  Signer.swift · Verifier.swift · Enroller.swift · CeremonyCanceller.swift  (protocols)
    Profile/  GateProfile.swift
  CCFidoBackend/   # library (deps: CCGateCore) — FIDO conformances
    FidoSigner.swift · FidoVerifier.swift   (ex-Crypto.swift; owns keygen paths + SignCanceller)
    FidoEnroller.swift                       (sk-keygen + blink-test + allowed_signers + isEnrolled/cleanup)
    FidoProfile.swift                        (fidoProfile: GateProfile)
  cc-fido/         # executable (deps: CCGateCore + CCFidoBackend)
    main.swift     # builds a GateContext (profile + FIDO signer/verifier/enroller), injects, dispatches
Tests/
  CCGateCoreTests/     # method-agnostic: Policy, Canonical, Wysiwys, Broker logic (synthetic profile),
                       #   Audit, Custody, Wire, Hook, CLIHelper, derivation-mechanism, cancellation-seam
  CCFidoBackendTests/  # FIDO exact-equivalence: isControlPath outcomes, ported sign→verify roundtrip,
                       #   blink-test, enroll-plan
```

**Why a separate `CCFidoBackend` library** (vs folding into the executable): SP2's
`CCTouchIDBackend` becomes a symmetric peer, and — decisively — the **FIDO exact-equivalence
regression guard** (below) must assert against real FIDO identity, which the litmus forbids in
`CCGateCore`/`CCGateCoreTests`. It has to live in a backend test target, so the backend library
must exist.

### The four seams

**`struct GateProfile`** — replaces `Paths`. Injected at composition time. Carries the
daemon/filesystem topology **and product/display/binary identity that both methods genuinely
share the *shape* of** — but **not** crypto-primitive details (per Architect review: keygen
paths and key-handle are CLI/file-backed FIDO-isms the SE backend won't have).

Fields and their true source today (the rev-1 table wrongly attributed some to `Paths`):

| Field | Value today | Source today |
|---|---|---|
| `serviceAccount` | `_ccfido` | **bare literals, not `Paths`** (`Broker.swift:54`, `Install.swift:14`, `Custody.swift:5,9`, `main.swift`, …) |
| `accountRealName` | `cc-fido broker` | literal `Platform.swift:71` |
| `namespace` *(signing-domain separator — see note)* | `cc-fido-gate@example.test` | `Paths.namespace` |
| `keydir` / `runDir` / `sock` | `/var/ccfido` · `/var/ccfido-run` · `…/gate.sock` | `Paths` |
| `daemonLogErr` | `/var/ccfido/brokerd.err` | literal in `renderPlist` (`CLIHelpers.swift:14`) |
| `codeDir` / `policy` | `/opt/cc-fido-gate` · `…/policy.json` | `Paths.code`/`Paths.policy` |
| `binaryName` | `cc-fido` | literals (`renderManagedSettings` hookCmd, nudge, status exe check) |
| `displayName` | `cc-fido-gate` | literal dialog title (`Client.swift:14`) |
| `launchdLabel` / `plist` | `com.cc-fido-gate.brokerd` · `…plist` | `Paths` + `renderPlist` literal |
| `daemonMatchPattern` | `cc-fido daemon` | literal `pkill -f` (`Platform.swift:101`) |
| `managedSettings` / `claudeCodeDir` | `/Library/Application Support/ClaudeCode/…` | `Paths` |

**Moved OUT of the profile into `CCFidoBackend`** (Architect + Fable; `signPrincipal` added
per Opus-r2 Minor-3): `signKeygen`, `verifyKeygen`, `keyHandle`, **`signPrincipal`
(`gate-principal`)**. All four are ssh-keygen/allowed-signers/file artifacts with no Secure
Enclave analog, so `main.swift` passes them directly into the `FidoSigner` / `FidoVerifier` /
`FidoEnroller` constructors. `keyHandle` must be composed with `NSHomeDirectory()`/login-home —
**never** a literal `~` (`Process` does not expand `~`; `Executor` review).

**Why `namespace` stays in `GateProfile` but `signPrincipal` does not** (resolving Opus-r2's
"move both or justify both"): `signPrincipal` is purely the SSH `allowed_signers` `-I` identity —
an ssh concept with no SE meaning → backend. `namespace` is the **signing-domain separator** and
is a genuine shared-shape field: **both** operations consume it — `sign()` takes `namespace`
(`Crypto.swift:26` → `-n` at `:33`) **and** `verify()` takes it (`Crypto.swift:59` → `-n` at
`:79`) — so it is not a one-sided ssh artifact the way `signPrincipal` is; any backend needs a
distinct signing domain. It stays generic; only its *value* differs per product.
`FidoSigner`/`FidoVerifier` receive `namespace` from the profile and `signPrincipal` from their
constructor. *(Precision, per Pentester-r3/Opus-r3: on **this** repo `namespace` is only the
ssh-keygen `-n` sig-namespace — it is **not** bound into `canonicalBytes`/`SignedDocument` today.
The Touch ID fork's `ns`-in-the-canonical-document field is a **forward-looking** reason to keep a
generic signing domain, not a current-repo fact; the load-bearing rationale above stands on
`Crypto.swift:26/59` alone.)*

Control-file paths (`allowedSigners`, `audit`, `custody`, `ceremonyLock`) and the
`controlDenylist` are **derived** by core from the profile roots. **`normPath`'s firmlink set
(`/var`,`/etc`,`/tmp`) is a fixed macOS platform constant and is NOT profile-derived** — folding
it into `GateProfile` would break the `/private/var == /var` denylist-bypass defense (Pentester).

**`protocol Signer`** (client-side):
```
protocol Signer {
    func makeCanceller() -> CeremonyCanceller                          // NEW — the construction seam
    func sign(challenge: Data, canceller: CeremonyCanceller) throws -> Data   // non-optional (see below)
}
```
`FidoSigner` spawns Homebrew ssh-keygen and owns the `Process`-terminating canceller impl. The
`canceller` parameter is **non-optional** *(codex + Fable-r3)*: today's free `sign(..., canceller:
SignCanceller? = nil)` (`Crypto.swift:28`) is optional only so non-ceremony callers could sign
without one, but in the new world `confirmAndSign` **always** mints one via `makeCanceller()`, and
the nil-canceller hang is precisely the regression this seam exists to kill. Making it non-optional
lets the type system forbid the regression instead of leaning on a test; any cancel-less internal
backend caller passes a fresh throwaway canceller.

**`protocol Verifier`** (broker-side): `verify(challenge: Data, signature: Data) -> Bool`.
`FidoVerifier` spawns stock ssh-keygen against `allowed_signers`, using the profile-derived
`namespace` and its constructor-supplied `signPrincipal`.

**`protocol CeremonyCanceller { func cancel() }`** *(new — Fable Major-2)* — the abstract
cancellation handle the `confirmAndSign` dialog race needs. FIDO supplies a `Process`-terminating
impl (today's `SignCanceller`, moved to the backend); SE will supply an `LAContext`-invalidating
one. `SignCanceller` is **not** transport-agnostic (it holds a `Process`), so it does not stay in
core — only the abstract protocol does.

**The construction seam (`makeCanceller`)** *(new — codex + Fable-r2 Major-1)*: today core's
`confirmAndSign` mints the concrete canceller inline (`let canceller = SignCanceller()`,
`Client.swift:21`) and the dialog thread + 90s backstop call `.cancel()` on it
(`Client.swift:44,49-50`). Once `SignCanceller` moves to the backend, core cannot instantiate it,
and `GateContext` otherwise supplies no factory. Without this seam the two "obvious" implementer
workarounds both regress silently: passing `nil` turns Cancel/give-up/backstop into no-ops on the
armed key (the sign thread blocks in `waitUntilExit`, `Crypto.swift:44`, and the uncapped
`group.wait()` at `Client.swift:50` hangs until Claude Code's own hook timeout — a runtime-behavior
change), while keeping `SignCanceller` in core defeats the fix **and matches none of the ten
grep-gate tokens**, so every SP1 done-criterion would still pass. So the factory is mandatory and
lives in the spec: `confirmAndSign` calls `signer.makeCanceller()` **once per ceremony**, passes
it to `sign`, and the dialog/backstop call `.cancel()` on it. Covered by a new core [SW] test —
see Testing.

**`protocol Enroller`** — enroll actions **plus** `isEnrolled(home:) -> Bool` and
`removeKeyMaterial(home:)` *(new — Fable Major-3)*. FIDO's `isEnrolled` is the
`~/.ccfido/gate_sk` file check (today inline in `Status.swift:59`); SE's will be a keychain
query. `gatherStatus` and `uninstall` call these seams instead of the hardcoded file ops, or
Touch ID's `rollup` never reaches `enrolled` and the skill wedges.

**Composition:** `main.swift` builds a `GateContext` (`GateProfile` + `Signer` + `Verifier` +
`Enroller`) and passes it into the entry points. Precisely (Fable-r2 Minor-3): `hookMain`,
`runWrite`, `runApprove` are **free functions** that take the context as a parameter; `Broker` is
a `class` whose `init` already accepts injected params (`Broker.swift:9`), so the context threads
into `Broker.init` and `serve()` reads it — *not* a free function. rev-1's "Broker/Client take
(X, profile)" implied an object graph that doesn't exist; this is the accurate shape.
**Invariant (Pentester Minor-4):** the
`Verifier`/`GateProfile` are composed at process start from compiled-in backend code — **never**
deserialized from the Unix-socket payload. Auth is the touch, not the caller.

### Marketplace packaging & binary delivery *(rev-1's undischargeable half — now specified)*

Plugin skills are namespaced `/<plugin-name>:<skill-folder>`. To preserve the documented
`/cc-fido:install` surface, the **plugin is named `cc-fido`** with skill folder `install`:

```
.claude-plugin/marketplace.json     # lists plugin "cc-fido"; "cc-touch-id" added in SP2
plugins/cc-fido/
  .claude-plugin/plugin.json         # name: cc-fido
  skills/install/SKILL.md            # → /cc-fido:install  (renamed from cc-fido-install)
  install/policy.json  install/POLICY.md   # the real template names (rev 1 misnamed these)
  README.md
docs/  scripts/  task0*/  Sources/  Package.swift  # repo root — shared/build-time
```

**Binary delivery (the Critical both Codex and Fable raised).** `cc-fido install` copies the
*currently-running* binary into `/opt` (`Install.swift:32-43`) — so a compiled `cc-fido` must
already exist on the user's machine. SP1 resolves this explicitly:

- The `install` skill gains a **Step 0 bootstrap**: a **preflight** (probe Xcode Command Line
  Tools for `swift`; probe Homebrew OpenSSH — note the prefix differs by arch: ARM
  `/opt/homebrew/opt/openssh`, Intel `/usr/local/opt/openssh`, vs `Paths.swift:16`'s hardcoded ARM
  path, which is itself a portability item to thread through the FIDO backend), then locate the
  repo root via `${CLAUDE_PLUGIN_ROOT}` (the plugin dir ships inside the cloned repo tree) and run
  `swift build -c release`, yielding `.build/release/cc-fido`; the guided steps then invoke that
  binary. **Acceptance [USER-RUN]** (Fable-r2 Minor-4 — it needs enroll → a physical key + sudo +
  touch, so it is not [SW]): on a clean machine where `command -v cc-fido` initially fails, a
  marketplace install + skill run reaches `status: active`.
- The rev-1 claim *"`Sources/` never ships into `~/.claude`"* is **dropped** — whether the
  marketplace clones the whole repo or only the plugin dir is UNVERIFIED and is a **plan-phase
  spike** (`references/plugin-marketplaces` + a local `claude plugin validate .` + a clean-machine
  install). The bootstrap step is written against whichever layout the spike confirms.

### Deferred to SP2: mutual-exclusion & ownership-aware managed-settings *(review-driven descope)*

Rev 1 put a mutual-exclusion "stub" in SP1. All five reviewers flagged this; it is **removed
from SP1** because:

- There is **no "installed but only one active" state**: `install` already writes the managed
  hook (`Install.swift:16`), so installing a second product immediately replaces it (Executor
  Crit-3).
- Uninstall **wholesale-deletes** managed-settings (`Platform.swift:114`) and install
  **wholesale-overwrites** it (`Platform.swift:109-112`) — after SP2, uninstalling inactive FIDO
  could delete the active Touch ID hook, and either op could destroy **non-gate enterprise MDM**
  managed-settings (Fable Minor-6).
- The `pkill -f "cc-fido daemon"` pattern (`Platform.swift:101`) would **cross-kill the FIDO
  daemon** from the Touch ID product unless made profile-specific (Fable Major-4). SP1 makes it
  `daemonMatchPattern` in the profile so SP2 inherits per-product isolation, but the exclusion
  *policy* is SP2's.
- A refuse-branch with only one gate present is **dead and untestable** in SP1 (Opus Minor-3,
  Pentester Minor-6).

**SP2 owns:** ownership-aware install/activate/deactivate/uninstall with an **atomic
lock/check/write** on managed-settings, content-matched uninstall (delete only what this gate
rendered), preservation of unrelated MDM config, and the tests that exercise all of it.

## Migration strategy

Ordered so build/test stays green at each step (details belong to the plan):

1. Rename `Sources/CCFidoCore` → `Sources/CCGateCore` **and**, in the **same** commit, update
   `Package.swift`, the `import` in `main.swift`, **and all 15 `@testable import CCFidoCore` test
   files + the testTarget dependency (`Package.swift:9`)** — otherwise `swift test` is red at this
   step (Fable-r2 Minor-2). The test *content* split is still step 6; this is just the import
   rename. The `cc-fido` executable target already exists — it is not re-added (Executor High-7).
   Add the empty `CCFidoBackend` target.
2. Introduce `GateProfile` + the four protocols in `CCGateCore`; add `fidoProfile` +
   `FidoSigner`/`FidoVerifier`/`FidoEnroller` (+ the moved `SignCanceller`, keygen paths,
   `keyHandle`, `isEnrolled`/`removeKeyMaterial`) in `CCFidoBackend`.
3. Thread `GateContext` through `hookMain`/`runWrite`/`runApprove`/`Broker.serve` **and
   `Platform`/`MacOSPlatform`** (added to the list — it holds `pkill`, account real-name, and
   `Paths.*` reads). Replace `Paths.*` reads; **delete `Paths`** so the compiler enumerates
   `Paths.*` *references* — but see the grep gate below for the literal surface the compiler
   does **not** catch.
4. Sweep the **bare identity literals** the compiler misses. This work-list is **non-exhaustive —
   the grep gate (below) is authoritative**; route every hit through the profile. Known sites
   (`_ccfido` = 18 lines / 21 occurrences across Install ×6, Broker ×6, Custody ×2, Status ×2,
   Enroll ×1, CLIHelpers ×1 — Opus-r2 Minor-1): the **functional** `_ccfido` argv/bindings
   (`getpwnam("_ccfido")` `Broker.swift:54`; `chown _ccfido` `Custody.swift:5,9`; `Install.swift:14`;
   `Status.swift:50`) → **value-substitute** to `profile.serviceAccount`; `.ccfido`/`gate_sk`
   (`Enroll.swift`, `Install.swift:104-105`, `Status.swift:59`), `gate-principal` (`Enroll.swift:34`),
   dialog title `cc-fido-gate` (`Client.swift:14`), nudge/stderr `cc-fido` (`HookLogic.swift:3`),
   `renderPlist`/`renderManagedSettings` templates (`CLIHelpers.swift:9-14`), `pkill` pattern +
   `RealName` (`Platform.swift:71,101`). **Genericize comments *and* user-facing/error strings**
   (Opus-r2 Minor-2, Fable-r2 Minor-3): `Broker.swift:49,50,230` are comments; `:55`/`:73` are
   thrown error strings; `Client.swift:71,80,87,88` are stderr prefixes — all must lose the FIDO
   token so the grep gate needn't exclude comments (`main.swift` usage text is exempt — it lives in
   the executable, not core).
5. Move `Crypto.swift` FIDO specifics into `CCFidoBackend`; keep `scrubEnv`/`scrubbedEnv` in core
   as the single env-allowlist for every child spawn (hard invariant — Opus/Pentester).
6. Split `CCFidoCoreTests` → `CCGateCoreTests` + `CCFidoBackendTests` (see §Testing).
7. Restructure into `plugins/cc-fido/` + `.claude-plugin/marketplace.json`; move the skill to
   `plugins/cc-fido/skills/install/` and **delete the old `.claude/skills/cc-fido-install/`
   directory** so there aren't two competing install skills for anyone working in the repo
   (Fable-r2 Minor-5); add the Step-0 bootstrap; fix doc references (`install/policy.json`, and
   CLAUDE.md's dead `task7_install/enroll/teardown` pointers — only `task7_accept.sh` survives).
   Note the repo-developer flow (add the local marketplace, or run from `.build/release`) so
   developers who lose the project skill still have a path.

## Testing

Rev 1's *"no assertion changes beyond mechanical import splits"* is **false** and is replaced:
threading a profile turns static `isControlPath`/`normPath` into instance/param signatures, a
call-site change (Opus/Pentester/Fable). New wording: **"no assertion *logic / expected-value*
changes; call-site signature updates permitted."**

- **[SW] `CCGateCoreTests` (mechanism, synthetic profile — no FIDO strings):**
  - Derivation: a **dummy** `GateProfile` (dummy roots) → assert the control-denylist and
    `isControlPath` **outcomes** are derived correctly from arbitrary roots.
  - Two synthetic profiles in one process → assert **no cross-profile** paths/accounts/labels/
    sockets/match-patterns leak (proves method-independence).
  - **Cancellation seam** *(new — MAJOR A; test boundary corrected per codex + Fable-r3 + Opus-r3)*:
    test the seam **below** `confirmAndSign`, with **no `osascript` in the loop**. A fake `Signer`
    whose `sign(challenge:canceller:)` blocks until the passed canceller's `.cancel()` fires; assert
    (i) `makeCanceller()` returns a fresh handle, (ii) that same handle is threaded into `sign`, and
    (iii) `.cancel()` aborts the blocked `sign` **promptly**. This pins the method-agnostic
    cancellation contract the seam guarantees and closes the nil/no-op regression the grep gate can't
    see. **Why not test `confirmAndSign` directly:** it unconditionally spawns a real `osascript`
    dialog with no injection point (`Client.swift:11-19`), and an external `.cancel()` unblocks only
    the sign thread while `group.wait` still waits on the dialog thread — so a `confirmAndSign`-level
    assertion hangs 60s on a GUI Mac (violating "[SW] = pure logic") and passes *vacuously* headless
    because the dialog's own auto-cancel (`Client.swift:44`) resolves it, not the injected cancel.
    Extracting a full injectable dialog-runner/ceremony-coordinator seam would let SP1 also drive the
    production dialog→deny→cancel race in [SW], but that is **out of SP1's minimal scope** (it changes
    `confirmAndSign`'s structure beyond the profile/backend extraction) and is noted as an optional
    SP2 hardening. **The [SW] seam test proves only the abstract contract — it cannot catch a
    production mis-wiring** (minting two cancellers, or not calling `.cancel()` from the dialog-deny
    path). That production cancel→sign wiring is covered instead by a **new explicit USER-RUN
    cancellation case** (codex-verify) — see the USER-RUN bullet below.
  - `swift build --target CCGateCore` builds with **no backend linked**.
- **[SW] `CCFidoBackendTests` (exact-equivalence regression guard — the real barrier):**
  - `isControlPath` **outcomes** for the real `fidoProfile`: **true** for `sock`, a path under
    `keydir`, a path under `code`, `policy`, and their `/private/var/…` firmlinked forms;
    **false** for an enrolled-style target — matching today's `BrokerAllowlistTests`. Assert
    **behavior, not array equality** (the socket is control only via the explicit entry; `code`
    is prefix-denied but not in the array; `runDir` is not prefix-denied — Pentester Major-2).
    Anchor the expected values on **hardcoded literal strings** (`"/var/ccfido/allowed_signers"`,
    …), not profile-derived expressions (Fable Minor-7 — a self-comparison proves nothing).
  - **Port + tighten** the existing `CryptoTests.swift:6-43` roundtrip into `CCFidoBackendTests`
    as a `FidoSigner`/`FidoVerifier` sign→verify test *(corrected — Opus-r2 Major-1)*. The rev-2
    claim "the current suite never drives the verify-principal seam" was **false**: `CryptoTests`
    already does a headless software-ed25519 roundtrip driving principal/namespace/allowed_signers.
    The **real** risk is that the `principal→serviceAccount`/`signPrincipal` rename rewires
    `FidoVerifier` to the wrong profile field while `enroll` still writes literal `gate-principal`
    (`Enroll.swift:34`), denying every touch. To catch that, the test must be **one-sided-anchored**:
    build `allowed_signers` with the **hardcoded** `"gate-principal"` (mirroring enroll) while
    driving `FidoVerifier` from `profile`/constructor `signPrincipal` — if both sides came from the
    same field it would be a self-comparison and prove nothing (Fable Minor-7's discipline, applied
    here). Uses an injected `/usr/bin/ssh-keygen` + a generated software key + a temp test topology
    (not the real `/var/ccfido` paths), so it stays [SW], not USER-RUN (codex Moderate-2).
- **Grep gate (done-criterion, explicit — not the compiler):** `CCGateCore` free of
  `_ccfido`, `.ccfido`, `gate_sk`, `gate-principal`, `cc-fido`, `ccfido`, `/var/ccfido`,
  `cc-fido-gate@`, `com.cc-fido-gate`, `brokerd` (comments included, since step 4 rewrites them).
- **Call-site-update suites (not free — Opus-r2 test-coverage note):** `installOrchestration` /
  `uninstall` / `gatherStatus` are exercised via `MockPlatform` in `InstallTests`, `PlatformTests`,
  `StatusTests`, and internally call `renderPlist()`/`renderManagedSettings(...)`. Profile-threading
  changes those signatures, so these three suites take call-site updates (covered by the relaxed
  "call-site signature updates permitted" clause) — named here so "green [SW] suite" isn't assumed
  free.
- **[USER-RUN] (human, on hardware, un-sandboxed):**
  - re-run the FIDO enroll + gate e2e (`scripts/userrun/task7_accept.sh` → touch). [SW] cannot
    cover the daemon/socket/touch path; do not claim SP1 complete until USER-RUN confirms the gate
    fires and denies correctly on APPROVE+TOUCH.
  - **new cancellation case (codex-verify):** arm a real ceremony and **click Cancel** (and,
    separately, let it hit the 60s give-up) while signing is blocked; assert the command **exits
    promptly, denies, and performs no write — with no touch**. `task7_accept.sh` covers only
    APPROVE+TOUCH and a pre-ceremony control-path denial, so it does **not** exercise the
    dialog-deny→`cancel()`→sign-unblock wiring; this new case is the coverage the [SW] seam test
    cannot provide, and is **required for SP1 acceptance**.

## Risks

- **Literal identity surface exceeds `Paths.*` references.** Deleting `Paths` is necessary but
  **not sufficient**; the grep gate + step-4 work-list is the real net (Opus/Fable).
- **verify-principal miswire** — the `principal`→`serviceAccount`/`signPrincipal` rename could
  rewire `FidoVerifier` to the wrong field while `enroll` still writes literal `gate-principal`,
  denying every touch. (The old `CryptoTests` roundtrip *does* exercise sign→verify, but only with
  a hardcoded principal — it does not test the profile field the rename touches.) The guard is the
  **one-sided-anchored** ported roundtrip in `CCFidoBackendTests` (Opus-r2 Major-1).
- **`normPath` firmlink set** must stay a non-derived platform constant, or the denylist-bypass
  defense regresses (Pentester Major-3).
- **Marketplace binary bootstrap** depends on unverified marketplace-clone mechanics — gated by
  a plan-phase spike before the skill's Step 0 is written.

## Done criteria

- `swift build` (+ `--target CCGateCore` alone) and `swift test` green.
- Grep gate passes (token list above; comments included).
- `CCFidoBackendTests` exact-equivalence guard + the one-sided-anchored ported roundtrip pass;
  `CCGateCoreTests` cancellation-seam test passes.
- FIDO gate e2e re-confirmed on hardware via USER-RUN — **both** the APPROVE+TOUCH path **and** the
  new Cancel/give-up cancellation case (exits promptly, denies, no write, no touch).
- `/cc-fido:install` invocation resolves; a clean-machine marketplace install reaches
  `status: active` via the Step-0 bootstrap **[USER-RUN]**.
- SP2's Touch ID backend is startable **without editing `CCGateCore`**: the four seams
  (`Signer` incl. `makeCanceller()` / `Verifier` / `Enroller` / `CeremonyCanceller`) + `GateProfile`
  admit an SE backend, and `isEnrolled`/`removeKeyMaterial`/`daemonMatchPattern`/`displayName`/
  `binaryName` cover the method-specific surfaces the review found.
