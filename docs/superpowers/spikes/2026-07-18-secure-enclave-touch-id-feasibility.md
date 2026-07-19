# Spike: Secure Enclave / Touch ID backend feasibility (SP2)

**Date:** 2026-07-18
**Question:** Can a Touch ID / Secure Enclave backend satisfy the SP1 seams
(`Signer`/`Verifier`/`Enroller`/`CeremonyCanceller`) inside the existing broker topology —
specifically, can the **client** produce a biometric signature the **broker daemon** (a
non-console service account) can verify off-session, and does it work without a Developer ID?

**Verdict: YES.** All checks pass on the target hardware with only ad-hoc code signing. No
`CCGateCore` change is implied; the Touch ID backend is a pure `CCTouchIDBackend` addition.

## Why the topology admits it

Signing is **client-side**, verification is **broker-side** (`Client.swift:22-36` runs
`signer.sign` in the user's hook process; the broker only issues the challenge and calls
`verifier.verify`). Touch ID needs exactly this split: biometric evaluation is bound to the
console GUI session (where the hook runs), while ECDSA verification needs only the public key
(so the `_ccfido`-style service-account daemon can do it off-session).

## Platform

- Hardware: MacBook Air `Mac14,2`, Apple **M2**, Secure Enclave present, Touch ID (power button).
- Toolchain: Apple Swift 6.3.3, target `arm64-apple-macosx26.0`.
- **Code-signing identities available: none** (`security find-identity -v -p codesigning` → 0).
  This is the important constraint the spike had to clear.

## Findings

Probe source: a throwaway `sepx.swift` (P-256 SE key; `SecKeyCreateSignature`
`.ecdsaSignatureMessageX962SHA256`; verify by reconstructing the pubkey from raw bytes only).

| # | Check | Method | Result |
|---|---|---|---|
| 1 | Developer ID required? | inspect `swiftc` output binary | **No.** `swiftc` auto-applies an ad-hoc *linker-signed* signature (`codesign -dvvv` → `flags=0x20002(adhoc,linker-signed)`, `Signature=adhoc`). The SE accepts it. |
| 2 | SE key creation, non-biometric ACL (`[.privateKeyUsage]`) | `SecKeyCreateRandomKey` w/ `kSecAttrTokenIDSecureEnclave` | ✅ |
| 3 | SE key creation, biometric ACL (`[.privateKeyUsage, .biometryCurrentSet]`) | creation only (no prompt) | ✅ 65-byte P-256 pubkey exported |
| 4 | In-process signing (non-bio) | `SecKeyCreateSignature` | ✅ ~71-byte ECDSA sig |
| 5 | **Off-session verify, public-bytes-only** (daemon path) | separate process: `SecKeyCreateWithData(pubRaw)` + `SecKeyVerifySignature` — no SE, no keychain, no biometric | ✅ |
| 6 | Negative control | flip one challenge byte | ✅ rejected |
| 7 | **Biometric sign roundtrip** [USER-RUN] | `gen-sign --bio` (real touch) → off-session `verify` | ✅ `pub=65B sig=70B bio=true` → `signature valid` |
| 8 | **Cancel seam** [USER-RUN] | bind `LAContext` at key creation via `kSecUseAuthenticationContext`, `.invalidate()` mid-prompt | ✅ aborts with `LAError Code=-9 "Invalidated by client."` |

## Seam mapping (proven)

| SP1 seam | Touch ID implementation |
|---|---|
| `Signer.sign(challenge:canceller:)` | `SecKeyCreateSignature(sePriv, .ecdsaSignatureMessageX962SHA256, challenge)` — biometric-gated key; the Touch ID sheet **is** the presence ceremony. Runs client-side. |
| `Signer.makeCanceller()` / `CeremonyCanceller.cancel()` | fresh `LAContext` per ceremony; `cancel()` → `LAContext.invalidate()`. |
| `Verifier.verify(challenge:signature:)` | `SecKeyVerifySignature` on the pubkey reconstructed from stored raw bytes. Runs broker-side, off-session. |
| `Enroller` | `SecKeyCreateRandomKey` (biometric SE key) in the user session; export 65-byte pubkey; register it in the broker's allowed-signers-equivalent (privileged step). `isEnrolled` = pubkey present for user; `removeKeyMaterial` = delete enrolled pubkey + any keychain persistent ref. |

## Open design questions the spike surfaced (for the spec, not blockers)

1. **WYSIWYS vs the Touch ID sheet.** The Touch ID system sheet shows only a short
   `localizedReason`, not the full signed rendering. Decision needed: keep the existing
   `osascript` WYSIWYS dialog (full injective rendering) with Touch ID as the presence check, or
   fold the rendering into `localizedReason` (size-limited, less trustworthy). The `confirmAndSign`
   structure already runs dialog + arm concurrently, so keeping both is the low-risk path.
2. **Key persistence.** The probe used a **transient** key (`kSecAttrIsPermanent: false`). A real
   enroll needs a persistent SE key. Options: persistent keychain item with a keychain-access-group,
   or store only the public key broker-side and re-derive. Persistent SE keys may reintroduce a
   signing-entitlement/keychain-group requirement not exercised here — **the enroll persistence path
   is the one residual to confirm during implementation** (a narrow follow-up probe, not a redesign).
3. **`Enroller.enrollPlan` shape.** FIDO's `enrollPlan` returns `[[String]]` privileged argv. SE
   key creation is an in-process API call in the *user* session, not a privileged subprocess — only
   the pubkey *registration* is privileged. The seam either gains an in-process enroll variant or the
   plan emits a `cc-touch-id _se-enroll` self-subcommand step. Spec decides.

## Artifacts

Throwaway probe kept in the session scratchpad (`sepx.swift`), not committed to the repo.
