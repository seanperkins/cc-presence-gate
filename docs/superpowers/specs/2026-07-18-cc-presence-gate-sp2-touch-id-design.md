# cc-presence-gate SP2 (A+B) — Touch ID / Secure Enclave backend + install port

**Status:** Design approved (brainstorming). Supersedes nothing; extends SP1.
**Source sprint:** the SP1 core-extraction spec
(`2026-07-18-cc-presence-gate-sp1-core-extraction-design.md`) named SP2 as "Touch ID backend on
the extracted core + guided-install port + mutual-exclusion & ownership-aware managed-settings."
This spec covers **Pillars A + B only**; Pillar C (mutual-exclusion) is a later cycle (§Non-goals).
**Feasibility:** de-risked by `docs/superpowers/spikes/2026-07-18-secure-enclave-touch-id-feasibility.md`
(all eight checks green on M2 hardware with ad-hoc signing; USER-RUN biometric sign + cancel confirmed).

## Context & goal

Ship a second presence method — **Touch ID / Secure Enclave** — as a product (`cc-touch-id`)
fully parallel to `cc-fido`, reusing the SP1 `CCGateCore` engine **without editing it** beyond
adding one new client-side seam. The gate's broker topology, policy engine, custody/audit, and
fail-closed semantics are unchanged; only the presence method (how a signature is produced and
verified) differs.

This proves the SP1 done-criterion in practice: *"SP2's Touch ID backend is startable without
editing `CCGateCore`."* The one deliberate exception is a fifth seam (`GateCeremony`, §2), a
planned additive extension — not a rewrite of the existing four.

### Why the broker topology already admits Touch ID

Signing is **client-side**; verification is **broker-side**. In `Client.swift` the ceremony runs
in the user's hook process (the console GUI session) and the broker only issues the challenge and
calls `verifier.verify` on the returned signature. Touch ID needs exactly this split: biometric
evaluation is bound to the console GUI session (where the client runs), while ECDSA verification
needs only the public key (so the `_cctouchid` service-account daemon verifies off-session). The
spike proved a real Touch ID signature made in-session verifies from a separate, public-bytes-only
process.

## Non-goals (deferred)

- **Pillar C — mutual-exclusion & ownership-aware managed-settings.** No atomic lock/check/write on
  managed-settings, no content-matched uninstall, no MDM preservation, no "two gates coexisting"
  policy. Until Pillar C lands, installing `cc-touch-id` **replaces** the active managed hook
  (the SP1-review-accepted "second install replaces the first" behavior). This spec's install skill
  states that plainly; it does not add coexistence logic (a refuse-branch with one gate present is
  dead/untestable — the SP1 review's reasoning still holds).
- **No `cc-fido` behavior change.** SP1's FIDO gate keeps its exact runtime behavior. The only FIDO
  edit is the mechanical move of `confirmAndSign` into `FidoCeremony` (§2), value-for-value.
- **No shared-`runCLI` extraction.** The `cc-touch-id` dispatcher duplicates the (mostly
  ctx-threaded) `cc-fido` dispatch rather than hoisting it into core (§5). Noted as future cleanup.
- **No Developer ID / notarization work.** Ad-hoc signing is sufficient (spike). If a persistent-key
  entitlement need surfaces (§4 residual), it is scoped by the first plan task, not here.

## Architecture

One SwiftPM package, adding one backend target and one executable target:

- **`CCGateCore`** — unchanged engine, **plus** the new `GateCeremony` protocol and a `ceremony`
  field on `GateContext`. The free `confirmAndSign` **leaves** core (moves to `CCFidoBackend`).
- **`CCFidoBackend`** — unchanged, **plus** `FidoCeremony` (the moved `confirmAndSign`).
- **`CCTouchIDBackend`** *(new)* — `TouchIdCeremony`, `TouchIdVerifier`, `TouchIdEnroller`,
  `touchIdProfile`, `makeTouchIdContext`, `boundedReason`.
- **`cc-fido`** — unchanged except constructing its context with the (now ceremony-bearing) factory.
- **`cc-touch-id`** *(new executable)* — thin dispatcher mirroring `cc-fido/main.swift`.

### Topology & naming (all install-fixed, parallel to FIDO)

| Concern | FIDO (SP1) | Touch ID (SP2) |
|---|---|---|
| Backend target | `CCFidoBackend` | `CCTouchIDBackend` |
| Executable / `binaryName` | `cc-fido` | `cc-touch-id` |
| Service account | `_ccfido` | `_cctouchid` |
| Profile / factory | `fidoProfile` / `makeFidoContext` | `touchIdProfile` / `makeTouchIdContext` |
| `keydir` | `/var/ccfido` | `/var/cctouchid` |
| `runDir` / `sock` | `/var/ccfido-run` / `…/gate.sock` | `/var/cctouchid-run` / `…/gate.sock` |
| `codeDir` / `policy` | `/opt/cc-fido-gate` | `/opt/cc-touch-id` |
| `launchdLabel` / `plist` | `com.cc-fido-gate.brokerd` | `com.cc-touch-id.brokerd` |
| `daemonMatchPattern` | `cc-fido daemon` | `cc-touch-id daemon` |
| `displayName` | `cc-fido-gate` | `cc-touch-id` |
| `namespace` | `cc-fido-gate@example.test` | `cc-touch-id@example.test` (placeholder) |
| Plugin dir | `plugins/cc-fido/` | `plugins/cc-touch-id/` |

The control-denylist is **derived** from these roots exactly as SP1's `GateProfile` already does;
no new denylist logic. `_cctouchid` ownership + `uchg` is the write barrier, identical to `_ccfido`.

### 1. The `GateCeremony` seam (new, additive)

```swift
// CCGateCore/Signing/GateCeremony.swift
public protocol GateCeremony {
    /// Client-side presence + signature production. Returns the signature on approval, nil on deny.
    func confirmAndSign(rendering: String, challenge: Data, displayName: String) -> Data?
}
```

- **`GateContext`'s `signer` field is replaced by `ceremony`** → `{profile, ceremony, verifier,
  enroller}`. The `Signer`/`CeremonyCanceller` **protocols are unchanged** and still exist — they
  just move from a `GateContext` field to an internal detail of `FidoCeremony` (which constructs and
  drives its own `FidoSigner`). `makeFidoContext` and any [SW] test that builds a `GateContext` take
  a call-site update (mechanical, no expected-value change — the SP1 "call-site signature updates
  permitted" clause applies).
- `Client.swift`'s `runWrite`/`runApprove` call `ctx.ceremony.confirmAndSign(rendering:challenge:displayName:)`
  in place of the free `confirmAndSign(_:challenge:signer:displayName:)`.
- **SP1's four seams (`Signer`/`Verifier`/`Enroller`/`CeremonyCanceller`) keep their contracts**, so
  SP1's `CancellationSeamTests` (which drives `Signer` directly) holds verbatim.

**`FidoCeremony` (CCFidoBackend):** the current `confirmAndSign` body moved **verbatim** (osascript
dialog + concurrent `FidoSigner` arm + dialog/backstop `cancel()` wiring), wrapped as:
```swift
public struct FidoCeremony: GateCeremony {
    let signer: Signer
    public init(signer: Signer) { self.signer = signer }
    public func confirmAndSign(rendering: String, challenge: Data, displayName: String) -> Data? { /* moved */ }
}
```

**`TouchIdCeremony` (CCTouchIDBackend):** no osascript.
```swift
public final class TouchIdCeremony: GateCeremony {
    // owns the enrolled SE key handle (keychain lookup by tag) + boundedReason
    public func confirmAndSign(rendering: String, challenge: Data, displayName: String) -> Data? {
        let ctx = LAContext()
        ctx.localizedReason = boundedReason(rendering, displayName: displayName)
        // SE key bound to ctx via kSecUseAuthenticationContext at lookup/creation so cancel() works
        // SecKeyCreateSignature(privSE, .ecdsaSignatureMessageX962SHA256, challenge) -> Data
        // on error (incl. LAError -9 user-cancel / give-up) -> nil (deny, fail-closed)
    }
}
```
Its `CeremonyCanceller` invalidates the `LAContext` (`cancel()` → `ctx.invalidate()`; proven to
abort an in-flight prompt with `LAError -9`). The 90s client-side backstop from the FIDO ceremony
is preserved so an armed-but-never-touched sheet cannot hang the client.

### 2. Secure Enclave crypto

- **Key:** P-256, `kSecAttrTokenIDSecureEnclave`, access control
  `[.privateKeyUsage, .biometryCurrentSet]`, `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`.
- **Sign** (client): `SecKeyCreateSignature(priv, .ecdsaSignatureMessageX962SHA256, challenge)` — the
  Touch ID sheet is the presence ceremony.
- **Verify** (broker): `TouchIdVerifier` loads its allowed-signers file — **base64 raw P-256 public
  keys (65-byte `04‖X‖Y`), one per line** — reconstructs each with `SecKeyCreateWithData`
  (`kSecAttrKeyClassPublic`), and `SecKeyVerifySignature`s the challenge. Returns true iff any
  enrolled key verifies. **No `ssh-keygen`; the FIDO two-binary split does not apply.**
- **`boundedReason(_:displayName:)`:** produces the sheet text. Caps the rendering to a fixed length
  and appends a `sha256` fingerprint of the **full** rendering plus a size, e.g.
  `cc-touch-id: write ~/.zshrc — sha256 3f9a…d21 (412 B)`. The signed challenge still binds the full
  canonical bytes (`Canonical.swift` unchanged); the reason is advisory display. **WYSIWYS is
  deliberately softened here** (accepted trade for a single native prompt) — documented in the
  product README/design notes as a difference from the FIDO gate's full-rendering dialog.
  `humanRendering`'s confusable/bidi escaping still applies to whatever text lands in the reason.

`TouchIdVerifier` init: `(allowedSigners: String)` (path to the base64-pubkey file). It reads the
profile-derived `allowedSigners` path; no principal/namespace/keydir args (those were FIDO-shaped).

### 3. Enrollment — makes `runEnroll` method-agnostic (absorbs the SP1 residual)

SP1 deferred de-FIDO-ing `Enroll.swift`'s `runEnroll` (it still embeds blink-test + `ssh-keygen` +
`allowed_signers` append). SP2 must make the **orchestration** method-agnostic so a Touch ID
enroller slots in; the FIDO-specific argv stays in `FidoEnroller`/FIDO wiring.

- **`runEnroll` orchestration** (core): create key(s) via `enroller.enrollPlan`/backend hook →
  register public material (privileged) → run a **positive-control self-test** → report. The FIDO
  positive control (`fidoNegativeBlinkTest`) becomes a backend-provided closure so Touch ID supplies
  its own (below). No FIDO literals remain in the orchestration.
- **`TouchIdEnroller`:**
  - *user-session step:* create a **persistent** biometric SE key (stable keychain tag), export the
    65-byte pubkey.
  - *privileged step:* register the pubkey (base64) into `/var/cctouchid/allowed_signers` (owned by
    `_cctouchid`, via the same `sudo -u` + `_registry`-style path SP1 uses for service-account-owned
    files).
  - `isEnrolled(home:)` = keychain key present **and** pubkey registered.
  - `removeKeyMaterial(home:)` = delete the keychain key (by tag) + its registered pubkey line.
- **Positive control** (replaces the negative blink-test): a **sign→verify self-test** at enroll
  time — the user touches once (they are enrolling anyway); the enroller signs a nonce and the
  method's own `TouchIdVerifier` must accept it before activation is allowed. This proves the whole
  client-sign → daemon-verify path end-to-end before the gate goes live.

**Residual to confirm (spike-flagged) → first plan task.** The spike used a **transient**
(`kSecAttrIsPermanent: false`) key. A real enroll needs a **persistent** SE key, which may
reintroduce a keychain-access-group / signing-entitlement requirement not exercised by ad-hoc
transient keys. **Plan Task 1 is a narrow persistence probe** (create a persistent biometric SE key
from an ad-hoc-signed CLI, look it up in a second process, sign) that either confirms ad-hoc is
still sufficient or scopes the minimal entitlement/keychain-group. Everything downstream is written
against that finding.

### 4. CLI / dispatcher

`cc-touch-id/main.swift` mirrors `cc-fido/main.swift`, constructing `makeTouchIdContext(home:)`.
Subcommands `daemon`/`hook`/`write`/`install`/`activate`/`uninstall`/`status` already take
`ctx`/`profile` and are reused unchanged in shape. Differences:
- `enroll` calls the method-agnostic `runEnroll` with the Touch ID enroller + positive-control
  closure (no blink-test, no keygen/handle/namespace args).
- FIDO-only internals (`_blink-test`, the FIDO `_render-*` specifics) are dropped or replaced with
  the Touch ID equivalents where an install step needs them (`_render-plist`/`_render-managed` use
  `touchIdProfile`).
- Usage/error strings carry `cc-touch-id` (executable-local literals; exempt from the core grep gate
  exactly as `cc-fido`'s are).

**Decision:** accept the modest dispatch duplication for the MVP rather than extract a shared
`runGateCLI` into core — hoisting it would force threading `binaryName` through every usage/error
string and widen the grep-gate surface. Extraction is a candidate follow-up, not required here.

### 5. Install port (Pillar B)

- `plugins/cc-touch-id/`: `.claude-plugin/plugin.json`, `skills/install/SKILL.md`,
  `install/policy.json` + `install/POLICY.md`, mirroring `plugins/cc-fido/`.
- `.claude-plugin/marketplace.json` gains the `cc-touch-id` plugin entry (SP1 reserved the name).
- **Install skill Step 0 (preflight + bootstrap):** verify `swift` (xcode-select); verify **Touch ID
  hardware present and a fingerprint enrolled** (`bioutil`); `swift build -c release` from the repo
  root located via `${CLAUDE_PLUGIN_ROOT}` per the SP1 marketplace-clone spike. **Ad-hoc linker
  signature is sufficient — no Developer ID** (spike). Then drive `install` → `enroll` (touch) →
  `activate`, prompting for sudo/touch one step at a time (same shape as `/cc-fido:install`).
- The skill explicitly notes: `cc-touch-id` and `cc-fido` **do not coexist** yet (Pillar C);
  installing one replaces the other's managed hook.

## Migration strategy (build/test stays green each step; details belong to the plan)

1. **Persistence probe (spike-2)** — confirm persistent biometric SE key + off-session verify from
   an ad-hoc CLI; record the entitlement/keychain-group finding. Gates the enroller design.
2. Add `GateCeremony` to `CCGateCore`; thread `ceremony` through `GateContext`; move `confirmAndSign`
   into `FidoCeremony` (`CCFidoBackend`) verbatim; repoint `runWrite`/`runApprove`. Green with FIDO
   unchanged.
3. Add `CCTouchIDBackend` target: `TouchIdVerifier` + `boundedReason` first (both [SW]-testable
   without hardware), then `TouchIdCeremony`, `TouchIdEnroller`, `touchIdProfile`,
   `makeTouchIdContext`.
4. Make `runEnroll` orchestration method-agnostic (positive control as a backend closure); keep FIDO
   enroll behavior identical.
5. Add the `cc-touch-id` executable target + dispatcher.
6. Marketplace restructure: `plugins/cc-touch-id/` + marketplace entry + install skill (Step-0
   bootstrap, Touch ID preflight).
7. USER-RUN acceptance scripts.

## Testing

- **[SW] `CCTouchIDBackendTests` (no hardware, no touch):**
  - `TouchIdVerifier` roundtrip using an **in-test software P-256 key** (created *without*
    `kSecAttrTokenIDSecureEnclave` → no biometric, signs headlessly) → `TouchIdVerifier` accepts;
    wrong-key and tampered-challenge negatives rejected. This is the exact analog of SP1's headless
    software-ed25519 roundtrip; it drives the real parse+verify path without the Secure Enclave.
  - allowed-signers file parsing: multiple keys, blank/garbage lines ignored (fail-closed), empty
    file → verify false.
  - `boundedReason`: length cap enforced, `sha256`+size suffix present, confusable/bidi escaping
    preserved, digest-mode rendering fits.
  - `TouchIdEnroller`: `enrollPlan` shape (persistent-key create + privileged register present),
    `isEnrolled` false on a clean home, `removeKeyMaterial` targets the right tag/line.
- **[SW] `CCGateCoreTests`:**
  - `GateCeremony` seam: a fake ceremony wired into `GateContext`; `runWrite`/`runApprove` call it.
  - Grep gate: `CCGateCore` still free of FIDO identity (moving `confirmAndSign` *out* only helps);
    Touch ID literals live only in `CCTouchIDBackend`/the executable.
  - `swift build --target CCGateCore` builds with **no backend linked**.
- **[USER-RUN] (human, on hardware):**
  - `cc-touch-id` enroll → the enroll-time positive-control self-test passes (one touch).
  - Gated write: the Touch ID sheet fires, a touch approves, the broker verifies, the write lands.
  - **Cancel case:** sheet fires, operator does **not** touch (and separately lets it give up) →
    command exits promptly, denies, **no write**, no residual.
  - Clean-machine marketplace install reaches `status: active` via Step-0 bootstrap.

## Risks

- **Persistent-key entitlement** (§3 residual) — the one unproven crypto assumption; retired by plan
  Task 1 before anything depends on it. If ad-hoc proves insufficient, the fallback (store only the
  public key broker-side; a keychain-access-group on the persistent private key) is bounded and
  known, not open-ended.
- **Softened WYSIWYS** — the sheet shows a bounded reason + hash, not the full rendering. Accepted;
  the challenge still binds the full canonical bytes, and the difference is documented so the Touch
  ID gate's guarantee is not overstated relative to the FIDO gate.
- **No coexistence** — with Pillar C deferred, installing `cc-touch-id` silently replaces `cc-fido`'s
  managed hook. Acceptable for A+B; the skill warns the operator. Pillar C removes the footgun.
- **Dispatch duplication** — two `main.swift` files drift over time. Mitigated by both being thin
  ctx-threaded dispatchers; flagged for a later shared-`runCLI` extraction.

## Done criteria

- `swift build` (+ `--target CCGateCore` alone) and `swift test` green; SP1 FIDO tests unchanged.
- Grep gate passes; `GateCeremony` seam test passes; `TouchIdVerifier` software-key roundtrip +
  allowed-signers + `boundedReason` tests pass.
- `CCGateCore` edited **only** to add `GateCeremony` + the `ceremony` field — no FIDO/Touch-ID
  identity added to core.
- **[USER-RUN]** on hardware: `cc-touch-id` enroll positive-control passes; a real Touch ID touch
  approves a gated write and the daemon verifies it; the Cancel/give-up case denies with no write.
- `/cc-touch-id:install` resolves; a clean-machine marketplace install reaches `status: active`.
- Persistent-key persistence/entitlement question answered (plan Task 1) and reflected in the
  enroller.
