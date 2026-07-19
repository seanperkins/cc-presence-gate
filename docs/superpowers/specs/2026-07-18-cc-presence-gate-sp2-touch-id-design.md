# cc-presence-gate SP2 (A+B) — Touch ID / Secure Enclave backend + install port

**Status:** Design approved (brainstorming). **Rev 2** — rebased onto the on-device-validated Touch ID
fork after it was discovered mid-execution (user direction: "rebase onto the fork's solved work").
Rev 1's "ad-hoc signing sufficient, no Developer ID" premise is **retracted** — it held only for a
*transient* SE key; real enrollment needs a persistent keychain-resident key, which requires an
entitled + provisioned build (proven below).

**Source sprint:** SP1 core-extraction (`2026-07-18-cc-presence-gate-sp1-core-extraction-design.md`).
This spec covers **Pillars A + B only**; Pillar C (mutual-exclusion) is a later cycle (§Non-goals).

**Validated basis (reuse, don't re-derive):** branch `worktree-touch-id-gate` — a rebranded fork that
already implemented and **on-device-validated** the Secure Enclave path:
- `Sources/CCTouchIDCore/SecureEnclave.swift` — `seSign` (Touch ID), `seVerify` (CryptoKit P-256),
  `seCreateKey`, `seFetchKey`, `seExportPublicKey`, `seDeleteKey`, `TouchIDCanceller`
  (`LAContext.invalidate`), `touchIDAuthenticationAllowableReuseDuration = 0` (no reuse). Port this
  file into `CCTouchIDBackend` nearly verbatim.
- `task0-se/REPORT.md` — TID-1..6 green/expected-green. Persistent SE key needs a
  `keychain-access-groups` entitlement (`-34018` without) **and** an embedded provisioning profile
  (entitled binary without one → SIGKILL rc=137). Solved by a provisioned macOS `.app`.
- `packaging/` — `xcodegen` `project.yml` + `CCTouchID.entitlements` (team **HH3SJBAS42**, bundle
  **com.mobilitylabs.cctouchid.app**, `keychain-access-groups = $(AppIdentifierPrefix)com.mobilitylabs.cctouchid.app`,
  hardened runtime).

## Context & goal

Ship **Touch ID / Secure Enclave** as a product (`cc-touch-id`) parallel to `cc-fido`, reusing the
SP1 `CCGateCore` engine — adding one client-side seam (`GateCeremony`) and one signed-document field
(`ns`), and lifting the fork's validated SE crypto + provisioned-build packaging into a new
`CCTouchIDBackend`. Broker topology, policy, custody/audit, and fail-closed semantics are unchanged;
only the presence method differs (how a signature is produced and verified).

### Why the broker topology already admits Touch ID (fork-confirmed)

Signing is **client-side** (the hook process, in the console GUI session); verification is
**broker-side**. The fork's TID-2 proved a session-0 daemon running as `_cctouchid` **cannot** produce
a signature — the SE key lives in the *user's* entitled keychain group, invisible even to root — while
the daemon verifies with only the public key (`seVerify`, pure CryptoKit, no SE/biometric). This is a
*stronger* isolation than SP1's design assumed.

### Distribution target (user decision, rev 2)

**Distributable** (not author-machine-only): the entitled `.app` is signed with **Developer ID
Application** + **notarized** (`notarytool` submit + staple), and production signing **drops
`get-task-allow`** so the hardened-runtime anti-attach property (TID-5) holds. **Prerequisite:** a
Developer ID Application certificate for team HH3SJBAS42 — the fork's REPORT records that none exists
on this machine yet (only Apple Development identities; the account is live — iOS profiles present).
Obtaining/validating that cert + a notarization credential is the plan's gating Task 1.

## Non-goals (deferred)

- **Pillar C — mutual-exclusion & ownership-aware managed-settings.** Installing `cc-touch-id`
  **replaces** the active managed hook (SP1-review-accepted "second install replaces the first"). The
  install skill states this; no coexistence logic is added.
- **No `cc-fido` runtime behavior change.** The only FIDO edits are mechanical: `confirmAndSign` moves
  into `FidoCeremony` (value-for-value), and the new `ns` field is **left nil** for FIDO so its signed
  `canonicalBytes` are byte-identical to today (FIDO keeps its `ssh-keygen -n` external namespace).
- **No shared-`runCLI` extraction** — `cc-touch-id`'s dispatcher mirrors `cc-fido`'s (noted future cleanup).

## Architecture

One SwiftPM package + a `packaging/` Xcode/xcodegen build for the entitled `.app`.

- **`CCGateCore`** — unchanged engine **plus**: the `GateCeremony` protocol; a `ceremony` field on
  `GateContext` (replacing `signer`); and an **optional `ns` field** on `SignedDocument`, folded into
  `canonicalBytes` only when non-nil. No FIDO/Touch-ID identity literals (grep gate still applies).
- **`CCFidoBackend`** — unchanged **plus** `FidoCeremony` (the moved `confirmAndSign`).
- **`CCTouchIDBackend`** *(new)* — the ported `SecureEnclave.swift`; `TouchIdSigner`/`TouchIdCeremony`,
  `TouchIdVerifier`, `TouchIdEnroller`; `touchIdProfile`, `makeTouchIdContext`; the constants
  `touchIdKeyTag = "com.mobilitylabs.cctouchid.gate"` and `touchIdAppBinary` (the in-bundle path).
- **`cc-fido`** — unchanged except constructing its ceremony-bearing context.
- **`cc-touch-id`** *(new executable)* — thin dispatcher; the plain build is the **daemon** binary; the
  entitled `.app`'s in-bundle copy is the **hook/enroll/client** binary.

### Topology & naming (from the fork's `Paths`, expressed as a `GateProfile`)

| Concern | Value |
|---|---|
| Backend target / executable | `CCTouchIDBackend` / `cc-touch-id` |
| Service account | `_cctouchid` |
| `keydir` / `runDir` / `sock` | `/var/cctouchid` / `/var/cctouchid-run` / `/var/cctouchid-run/gate.sock` |
| enrolled-pubkey (custody) | `/var/cctouchid/allowed_signers` (SP1-derived path) — **hex-encoded X9.63** pubkey |
| `codeDir` / `policy` | `/opt/cc-touch-id-gate` / `/opt/cc-touch-id-gate/policy.json` |
| daemon binary | `/opt/cc-touch-id-gate/cc-touch-id` (plain, ad-hoc-signed; verify-only) |
| entitled app binary (`touchIdAppBinary`) | `/opt/cc-touch-id-gate/cc-touch-id.app/Contents/MacOS/cc-touch-id` |
| `launchdLabel` / `plist` | `com.cc-touch-id-gate.brokerd` / `/Library/LaunchDaemons/com.cc-touch-id-gate.brokerd.plist` |
| `daemonMatchPattern` / `displayName` | `cc-touch-id daemon` / `cc-touch-id` |
| `namespace` (also the `ns` value) | `cc-touch-id-gate/v1` |
| SE key tag (`touchIdKeyTag`) | `com.mobilitylabs.cctouchid.gate` |
| Plugin dir | `plugins/cc-touch-id/` |

The control-denylist derives from these roots via SP1's `GateProfile` (no new denylist logic). No new
`GateProfile` fields: `keyTag`/`appBinary` are `CCTouchIDBackend` constants (the managed-hook command
is caller-supplied to `renderManagedSettings(hookCmd:)`, so `cc-touch-id/main.swift` passes
`touchIdAppBinary + " hook"`); `ns` reuses `profile.namespace`.

### 1. `GateCeremony` seam (unchanged from rev 1)

```swift
public protocol GateCeremony { func confirmAndSign(rendering: String, challenge: Data, displayName: String) -> Data? }
```
`GateContext.signer` → `ceremony`. `FidoCeremony` (CCFidoBackend) = the moved `confirmAndSign`
verbatim. `TouchIdCeremony` (CCTouchIDBackend) = mint `LAContext` + `TouchIDCanceller`, reason =
`rendering` (the fork's `touchIDReason` is identity; large writes already fall back to digest mode in
the shared `humanRendering`), call `seSign(message: challenge, tag: touchIdKeyTag, reason:, canceller:)`.
SP1's four seams keep their contracts. **Consent-UX convention preserved from the fork:** the reason is
a lowercase verb-phrase tail (macOS prepends "cc-touch-id wants to …" and appends the Touch ID line),
no added instruction line, path-first.

### 2. `ns` domain-separator (new, additive, FIDO-preserving)

SE signs raw P-256 over `canonicalBytes` — there is no external namespace like `ssh-keygen -n`, so a
domain separator must be **inside** the signed bytes. Add `public let ns: String?` to `SignedDocument`
(the fork's field, made **optional**), serialized into `canonicalBytes` **only when non-nil**.
`buildSignedDocument(..., ns: String? = nil)`. Touch ID passes `ns: profile.namespace`
(`"cc-touch-id-gate/v1"`); FIDO passes nil → its `canonicalBytes` are unchanged (honors "no FIDO
behavior change"). Value chosen per profile so a FIDO signature can never validate under the Touch ID
gate and vice-versa.

### 3. Secure-Enclave crypto (ported from the fork, on-device-validated)

Port `SecureEnclave.swift` into `CCTouchIDBackend` nearly verbatim (swap `Paths.keyTag` →
`touchIdKeyTag`):
- **`TouchIdVerifier`** (broker, off-session): reads the hex-encoded X9.63 pubkey from
  `profile.allowedSigners`, `hexDecode`s it, calls `seVerify(message: challenge, signatureDER:
  signature, publicKeyX963: pub)` (CryptoKit `P256.Signing`). Fail-closed on unreadable/garbage.
- **`TouchIdSigner`/`TouchIdCeremony`** (client): `seSign` with the biometry-gated key
  (`.biometryCurrentSet`, `reuseDuration = 0` → every sign re-prompts). `CeremonyCanceller` =
  `TouchIDCanceller` (`LAContext.invalidate`; aborts an in-flight prompt — validated).
- Signature wire format: base64 of the DER ECDSA-P256-SHA256 signature (unchanged `Client.swift`
  `phase:"signature"` protocol).

### 4. Enrollment — method-agnostic `runEnroll` (absorbs the SP1 residual)

Same as rev 1's approach: `runEnroll` becomes a thin driver over an expanded `Enroller`
(`enroll(home:keys:profile:)` + `positiveControl(home:profile:)` + `isEnrolled`/`removeKeyMaterial`);
`Enroll.swift` becomes FIDO-free and the SP1 grep-gate carve-out is retired.
- **`TouchIdEnroller`:** `enroll` = `seDeleteKey` (idempotent) → `seCreateKey(tag: touchIdKeyTag)` (needs
  the entitled binary) → `seExportPublicKey` → register `hexEncode(pub)` into `profile.allowedSigners`
  (one privileged escalation), chown `_cctouchid` + chmod 600. `positiveControl` = `seSign` a random
  nonce (one touch) → `TouchIdVerifier` accepts. `isEnrolled` = `seKeyExists`; `removeKeyMaterial` =
  `seDeleteKey`.

### 5. CLI / dispatcher

`cc-touch-id/main.swift` mirrors `cc-fido/main.swift` (fork's `main.swift` is the same shape): reuses
`ctx`/`profile`-threaded core entry points; `enroll` → `runEnroll(enroller: TouchIdEnroller())`;
`_presence-test` (fork's) → sign+verify self-test; **drops** FIDO `_blink-test`; `_render-managed`
passes `hookCmd = touchIdAppBinary + " hook"` (entitled binary for the client-side hook), while the
daemon `plist` (`_render-plist`) targets the plain daemon binary. Dispatch duplication accepted (MVP).

### 6. Install / packaging (Pillar B) — distributable

- **Provisioned build:** `packaging/` (ported from the fork) — `xcodegen generate` → `xcodebuild
  -scheme cc-touch-id -allowProvisioningUpdates build` produces the entitled `.app`. Then **Developer
  ID re-sign + notarize + staple**, and **strip `get-task-allow`** (fork's TID-5 script). Plain daemon
  binary is `swift build -c release` + ad-hoc codesign.
- **Install** (ported from fork's `task7_install.sh`): create `_cctouchid`; make dirs; copy the plain
  daemon binary to `codeDir/cc-touch-id` and the notarized `.app` to `codeDir/cc-touch-id.app`; copy
  policy; chown/chmod; render+install plist + managed-settings (hook → app binary); **stop if no key
  enrolled** (breaks the install↔enroll circularity — re-run after enroll); `launchctl bootstrap` +
  `kickstart`; canary control-path write must be denied.
- `plugins/cc-touch-id/`: `plugin.json`, `skills/install/SKILL.md`, `install/policy.json` + `POLICY.md`;
  `.claude-plugin/marketplace.json` gains the entry. Skill **Step 0**: preflight (`swift`; Touch ID
  hardware + enrolled fingerprint via `bioutil`; **Developer ID cert + notarization credential
  present**), then the provisioned+notarized build, then install/enroll/activate. States the
  no-coexistence caveat.

## Migration strategy (build/test green each step; details in the plan)

1. **Distribution-signing gate** — obtain/confirm a Developer ID Application cert for HH3SJBAS42 +
   notarization credential; build the entitled `.app`, Developer-ID-sign, notarize, staple, strip
   `get-task-allow`; confirm it **persists an SE key and signs** on-device (no `-34018`, no SIGKILL).
   Gates the enroller/ceremony. (Reuses the fork's packaging + REPORT; the new variable is Developer ID
   + notarization vs the fork's Apple-Development build.)
2. `GateCeremony` seam + move `confirmAndSign` into `FidoCeremony` + `GateContext.ceremony`.
3. `ns` optional field in `CCGateCore/Canonical.swift` (FIDO nil; Touch ID = namespace).
4. `CCTouchIDBackend` target: port `SecureEnclave.swift`; `TouchIdVerifier` (+ [SW] software-key
   roundtrip, ported from the fork's `SecureEnclaveTests`); then `TouchIdSigner`/`TouchIdCeremony`.
5. Method-agnostic `runEnroll`; `TouchIdEnroller`.
6. `touchIdProfile` + `makeTouchIdContext`; `cc-touch-id` executable + dispatcher.
7. Marketplace + plugin + install skill (provisioned+notarized build, Touch ID + Developer ID preflight).
8. USER-RUN acceptance (device enroll/approve/cancel; notarized clean-machine install → active).

## Testing

- **[SW] `CCTouchIDBackendTests`:** port the fork's `SecureEnclaveTests` (4 software-key `seVerify`
  cases — valid/ tampered/ wrong-key/ garbage; no hardware); `TouchIdVerifier` reads a hex-X9.63 file
  and verifies; enroller register-shape (hex pubkey line, no `gate-principal`) via injected privileged
  runner; `isEnrolled` false on clean keychain.
- **[SW] `CCGateCoreTests`:** `GateCeremony` seam wired into `GateContext`; **`ns`**: a doc with
  `ns:nil` produces byte-identical `canonicalBytes` to today (FIDO invariant) and a doc with `ns` set
  includes it and differs; grep gate still green; `swift build --target CCGateCore` links no backend.
- **[USER-RUN] (device, un-sandboxed):** provisioned+notarized build; `cc-touch-id` enroll (create SE
  key + positive-control touch); gated write approved by a real touch and daemon-verified; cancel/
  give-up denies with no write; notarized clean-machine install reaches `status: active`; TID-2
  re-confirm (daemon can't sign) if desired.

## Risks

- **Developer ID + notarization is the new gate** (Task 1). No Developer ID cert on the machine yet;
  requires paid-program access for HH3SJBAS42 (account is live). Notarization needs an App Store Connect
  API key / app-specific password. If unavailable, fall back to the fork's **Apple-Development**
  dev-signed path (author-machine scope) — a known-good downgrade, not a redesign.
- **Entitled build under Developer ID is partially unvalidated** — the fork validated Apple-Development
  provisioning; `keychain-access-groups` under Developer ID (team-prefixed) is expected to work without
  a profile but is confirmed only at Task 1.
- **`ns` optionality must truly preserve FIDO bytes** — guarded by the byte-identical `canonicalBytes`
  test (FIDO invariant) above.
- **`.app`-vs-plain split** — the hook must invoke the entitled app binary (SE sign) while the daemon
  runs the plain binary (verify only). Wrong wiring → enroll/sign fails `-34018`/not-found. Covered by
  the install task + USER-RUN.

## Done criteria

- `swift build` (+ `--target CCGateCore` alone) and `swift test` green; SP1 FIDO tests unchanged
  (incl. the `ns:nil` byte-identity invariant).
- `GateCeremony` seam test + ported `seVerify` software-key roundtrip + `TouchIdVerifier` hex-X9.63
  test pass; grep gate green; `CCGateCore` gained only `GateCeremony` + optional `ns`.
- Task 1 distribution-signing gate answered: an entitled, Developer-ID-signed, **notarized** `.app`
  persists + signs an SE key on-device (or the documented dev-signed fallback is recorded).
- **[USER-RUN]:** `cc-touch-id` enroll positive-control passes; a real Touch ID approves a gated write
  and the daemon verifies it; Cancel/give-up denies with no write; notarized clean-machine install
  reaches `status: active` via `/cc-touch-id:install`.
