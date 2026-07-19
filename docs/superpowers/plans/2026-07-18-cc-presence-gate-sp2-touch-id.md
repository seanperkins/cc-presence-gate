# cc-presence-gate SP2 (A+B) — Touch ID / Secure Enclave backend + install port

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **REV 2 — rebased onto the on-device-validated fork `worktree-touch-id-gate`.** The SE crypto,
> packaging, and consent UX already exist and are validated there; this plan **ports** them into the
> SP1 seam architecture rather than re-authoring. Rev 1's "ad-hoc signing" premise is retracted.

**Goal:** Ship `cc-touch-id` (Touch ID / Secure Enclave gate) as a product parallel to `cc-fido` on the shared `CCGateCore`, reusing the fork's validated SE code + provisioned-build packaging.

**Architecture:** Add a `GateCeremony` client seam and an optional `ns` signed-doc field to `CCGateCore`; add `CCTouchIDBackend` (ported `SecureEnclave.swift` + the four seam conformances); ship the entitled binary as a Developer-ID-signed, notarized `.app`, with a plain daemon binary for verify.

**Tech Stack:** Swift 5.9, SwiftPM, macOS 13+, XCTest, Security.framework, LocalAuthentication, CryptoKit, xcodegen + xcodebuild (provisioned `.app`), `notarytool`, `codesign`.

**Source spec:** `docs/superpowers/specs/2026-07-18-cc-presence-gate-sp2-touch-id-design.md` (rev 2).
**Validated basis:** `worktree-touch-id-gate` — `Sources/CCTouchIDCore/SecureEnclave.swift`, `task0-se/REPORT.md`, `packaging/`.

## Global Constraints

- **Swift tools 5.9, macOS 13+** — do not change the `Package.swift` floor.
- **No `cc-fido` runtime behavior change.** The only FIDO edits: `confirmAndSign` moves into `FidoCeremony` **verbatim**; the new `ns` field is **left nil for FIDO** so FIDO's `canonicalBytes` are byte-identical to today. A test pins that byte-identity.
- **`CCGateCore` gains only `GateCeremony` + optional `ns`.** No FIDO/Touch-ID identity literal enters core — the `GrepGateTests` token list still applies (`_ccfido`, `.ccfido`, `gate_sk`, `gate-principal`, `cc-fido`, `ccfido`, `/var/ccfido`, `cc-fido-gate@`, `com.cc-fido-gate`, `brokerd`), and Touch ID literals (`_cctouchid`, `cc-touch-id`, `cctouchid`, `com.cc-touch-id`, `mobilitylabs`) must not appear in `Sources/CCGateCore/` either.
- **After Task 6, `Enroll.swift` is FIDO-free** — the `GrepGateTests` `Enroll.swift` exclusion is REMOVED.
- **Reuse the fork's validated code.** Port `SecureEnclave.swift` and `SecureEnclaveTests.swift` nearly verbatim (only `Paths.keyTag` → `touchIdKeyTag`). Do not re-derive SE APIs.
- **Signing (distributable):** the entitled `.app` is **Developer ID Application**-signed, **notarized** (`notarytool` + staple), and **strips `get-task-allow`** (TID-5). Team **HH3SJBAS42**, bundle **com.mobilitylabs.cctouchid.app**, `keychain-access-groups = $(AppIdentifierPrefix)com.mobilitylabs.cctouchid.app`, SE key tag **com.mobilitylabs.cctouchid.gate**, hardened runtime. If a Developer ID cert/notarization credential is unavailable, fall back to the fork's Apple-Development dev-signed build and record it.
- **Fail-closed everywhere** — unreadable pubkey, garbage hex, verify error, SE lookup failure, cancelled/timed-out sheet → deny.
- **SE constants:** P-256 (`kSecAttrKeyTypeECSECPrimeRandom`), `.ecdsaSignatureMessageX962SHA256`, `.biometryCurrentSet`, `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, `touchIDAuthenticationAllowableReuseDuration = 0`.
- **Custody format:** enrolled pubkey = **hex-encoded X9.63** (`0x04‖X‖Y`, 65 bytes) at `profile.allowedSigners`, single line. Signature wire = base64 of DER ECDSA-P256-SHA256.
- **Topology:** daemon runs the **plain** binary `/opt/cc-touch-id-gate/cc-touch-id` (verify-only); hook/enroll/client run the **entitled** `.app` binary `touchIdAppBinary = /opt/cc-touch-id-gate/cc-touch-id.app/Contents/MacOS/cc-touch-id`.

---

### Task 1: Distribution-signing gate (Developer ID + notarization) — investigation, gates Tasks 5-7

**Why first:** persistent SE keys need an entitled + provisioned build; the fork proved this with an *Apple-Development* build. The user chose a **distributable** target, so the new variable is Developer ID + notarization. This task confirms an entitled, Developer-ID-signed, **notarized** `.app` persists + signs an SE key on-device before the enroller/ceremony depend on it. **Investigation — the written finding is the deliverable.**

**Files:**
- Create: `docs/superpowers/spikes/2026-07-18-distribution-signing-gate.md`
- Copy in: the fork's `packaging/` (`project.yml`, `CCTouchID.entitlements`) as the starting recipe.

- [ ] **Step 1: Inventory signing assets**

```bash
security find-identity -v -p codesigning        # is there a "Developer ID Application: … (HH3SJBAS42)"?
xcrun notarytool --help >/dev/null 2>&1 && echo "notarytool present"
ls ~/Library/MobileDevice/Provisioning\ Profiles/ 2>/dev/null | head   # any macOS profile?
```
Record what exists. If **no Developer ID Application cert**, note the blocker and the two paths: (a) create one for HH3SJBAS42 at developer.apple.com / Xcode (needs paid-program access), or (b) fall back to the Apple-Development dev-signed build the fork already validated. Do not fabricate a cert.

- [ ] **Step 2: Build the entitled `.app`**

Port the fork's packaging (from `worktree-touch-id-gate/packaging/`), then:
```bash
cd packaging && xcodegen generate
xcodebuild -project CCTouchIDGate.xcodeproj -scheme cc-touch-id -configuration Release \
  -allowProvisioningUpdates -destination 'platform=macOS' build
```
Locate the built `.app` under DerivedData.

- [ ] **Step 3: Developer-ID re-sign + notarize + staple + strip get-task-allow [USER-RUN — needs credential]**

If a Developer ID cert exists:
```bash
codesign --force --options runtime --timestamp \
  --entitlements packaging/CCTouchID.entitlements \
  --sign "Developer ID Application: … (HH3SJBAS42)" <APP>       # no get-task-allow in this entitlements set
xcrun notarytool submit <APP-zip> --keychain-profile <profile> --wait
xcrun stapler staple <APP>
codesign -d --entitlements - <APP> | grep -i get-task-allow    # expect: ABSENT
```

- [ ] **Step 4: On-device SE persistence + sign smoke [USER-RUN — needs a touch]**

Run the notarized app's `enroll` then `_presence-test` (create → sign → verify). Expect: SE key persists (no `-34018`), no SIGKILL, `_presence-test` prints a valid round-trip after one touch.

- [ ] **Step 5: Record the finding + decide**

Write to the spike doc, with evidence: does the **notarized Developer-ID** entitled build persist + sign an SE key? Is `get-task-allow` absent? Record the exact `notarytool` credential mechanism used. Choose: **(A) Developer-ID/notarized path confirmed** (Tasks 10/11 use it), or **(B) fall back to Apple-Development dev-signed** (record the scope limitation). Everything downstream is written against this.

- [ ] **Step 6: Commit**

```bash
git add docs/superpowers/spikes/2026-07-18-distribution-signing-gate.md packaging/
git commit -m "docs(spike)+packaging: distribution-signing gate (Developer ID + notarization) finding"
```

---

### Task 2: `GateCeremony` seam; move `confirmAndSign` into `FidoCeremony`; `GateContext.ceremony`

**Files:**
- Create: `Sources/CCGateCore/Signing/GateCeremony.swift`
- Modify: `Sources/CCGateCore/GateContext.swift` (`signer` → `ceremony`)
- Modify: `Sources/CCGateCore/Client.swift` (delete free `confirmAndSign`; call `ctx.ceremony.confirmAndSign`)
- Create: `Sources/CCFidoBackend/FidoCeremony.swift`
- Modify: `Sources/CCFidoBackend/FidoProfile.swift` (`makeFidoContext` passes `ceremony:`)
- Create: `Tests/CCGateCoreTests/GateCeremonySeamTests.swift`

**Interfaces:**
- Produces: `protocol GateCeremony { func confirmAndSign(rendering: String, challenge: Data, displayName: String) -> Data? }`; `GateContext(profile:ceremony:verifier:enroller:)`; `struct FidoCeremony: GateCeremony` init `(signer: Signer)`.

- [ ] **Step 1: Write the failing seam test**

`Tests/CCGateCoreTests/GateCeremonySeamTests.swift`:
```swift
import XCTest
@testable import CCGateCore

final class GateCeremonySeamTests: XCTestCase {
    struct FakeCeremony: GateCeremony {
        let out: Data?
        func confirmAndSign(rendering: String, challenge: Data, displayName: String) -> Data? { out }
    }
    func testGateContextHoldsACeremony() {
        let ctx = GateContext(profile: dummyProfile(), ceremony: FakeCeremony(out: Data([1,2,3])),
                              verifier: AlwaysVerifier(ok: true), enroller: NoopEnroller())
        XCTAssertEqual(ctx.ceremony.confirmAndSign(rendering: "r", challenge: Data(), displayName: "d"), Data([1,2,3]))
    }
    func testCeremonyDenyIsNil() {
        let c: GateCeremony = FakeCeremony(out: nil)
        XCTAssertNil(c.confirmAndSign(rendering: "r", challenge: Data(), displayName: "d"))
    }
}
struct AlwaysVerifier: Verifier { let ok: Bool; func verify(challenge: Data, signature: Data) -> Bool { ok } }
struct NoopEnroller: Enroller {   // pre-Task-6 Enroller shape; switch to enroll/positiveControl in Task 6
    func enrollPlan(home: String, index: Int) -> [[String]] { [] }
    func isEnrolled(home: String) -> Bool { false }
    func removeKeyMaterial(home: String) {}
}
```
> `dummyProfile()` = the helper in `Tests/CCGateCoreTests/TestProfile.swift` (use its actual name).

- [ ] **Step 2: Run — verify it fails to compile**

Run: `swift test --filter CCGateCoreTests.GateCeremonySeamTests`
Expected: FAIL — `GateCeremony` undefined / `GateContext` has no `ceremony:` init.

- [ ] **Step 3: Add the protocol**

`Sources/CCGateCore/Signing/GateCeremony.swift`:
```swift
import Foundation
/// Client-side presence ceremony: method-specific UI that shows what is being signed and returns a
/// challenge-bound signature on approval, nil on deny/cancel/timeout. FIDO = osascript + armed key;
/// Touch ID = native biometric sheet. Lives in core; impls live in backends.
public protocol GateCeremony {
    func confirmAndSign(rendering: String, challenge: Data, displayName: String) -> Data?
}
```

- [ ] **Step 4: Swap `GateContext.signer` → `ceremony`**

`Sources/CCGateCore/GateContext.swift`:
```swift
import Foundation
public struct GateContext {
    public let profile: GateProfile
    public let ceremony: GateCeremony
    public let verifier: Verifier
    public let enroller: Enroller
    public init(profile: GateProfile, ceremony: GateCeremony, verifier: Verifier, enroller: Enroller) {
        self.profile = profile; self.ceremony = ceremony; self.verifier = verifier; self.enroller = enroller
    }
}
```

- [ ] **Step 5: Move `confirmAndSign` into `FidoCeremony`**

Delete the free `confirmAndSign` (Client.swift:4-54). In `runWrite`/`runApprove` change both call sites to:
```swift
guard let sig = ctx.ceremony.confirmAndSign(rendering: human, challenge: challenge, displayName: ctx.profile.displayName) else {
```
Create `Sources/CCFidoBackend/FidoCeremony.swift`, pasting the deleted body **verbatim** as the method:
```swift
import Foundation
import Darwin
import CCGateCore
public struct FidoCeremony: GateCeremony {
    let signer: Signer
    public init(signer: Signer) { self.signer = signer }
    public func confirmAndSign(rendering humanRendering: String, challenge: Data, displayName: String) -> Data? {
        // ---- exact body of the old free confirmAndSign, unchanged (uses scrubbedEnv(), public in core) ----
    }
}
```

- [ ] **Step 6: `makeFidoContext` passes `ceremony:`**

```swift
public func makeFidoContext(home: String) -> GateContext {
    let signer = FidoSigner(keygen: fidoSignKeygen, handlePath: fidoKeyHandle(home: home), namespace: fidoProfile.namespace)
    return GateContext(
        profile: fidoProfile,
        ceremony: FidoCeremony(signer: signer),
        verifier: FidoVerifier(keygen: fidoVerifyKeygen, allowedSigners: fidoProfile.allowedSigners,
                               principal: "gate-principal", namespace: fidoProfile.namespace, keydir: fidoProfile.keydir),
        enroller: FidoEnroller())
}
```

- [ ] **Step 7: Build + full suite**

Run: `swift build && swift test`
Expected: PASS. `GateCeremonySeamTests` green; all SP1 tests green; grep gate green.

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "refactor(core): GateCeremony seam; move confirmAndSign into FidoCeremony; GateContext.ceremony"
```

---

### Task 3: Optional `ns` domain-separator on `SignedDocument` (FIDO bytes unchanged)

**Files:**
- Modify: `Sources/CCGateCore/Canonical.swift` (add `ns: String?`; fold into `canonicalBytes` only when non-nil; `buildSignedDocument(..., ns: String? = nil)`)
- Create/Modify: `Tests/CCGateCoreTests/CanonicalNsTests.swift`

**Interfaces:**
- Produces: `SignedDocument.ns: String?`; `buildSignedDocument(...)` gains a trailing `ns: String? = nil`.

- [ ] **Step 1: Read the current `SignedDocument`/`canonicalBytes`/`buildSignedDocument`**

Read `Sources/CCGateCore/Canonical.swift`; note the current `CodingKeys`/field order and how `canonicalBytes` serializes (JSON key-sorted per SP1). The `ns` field must serialize deterministically like the rest.

- [ ] **Step 2: Write the failing tests (both directions)**

`Tests/CCGateCoreTests/CanonicalNsTests.swift`:
```swift
import XCTest
@testable import CCGateCore

final class CanonicalNsTests: XCTestCase {
    // Build a doc the way the current code does (fill with the real buildSignedDocument signature).
    func testNilNsProducesTodaysBytes() {
        let a = canonicalBytes(buildSignedDocument(/* current args */, ns: nil))
        let b = canonicalBytes(buildSignedDocument(/* SAME args, no ns param */))
        XCTAssertEqual(a, b, "ns:nil must not change FIDO canonical bytes")
        XCTAssertFalse(String(data: a, encoding: .utf8)!.contains("\"ns\""))
    }
    func testSetNsIsIncludedAndDiffers() {
        let withNs = canonicalBytes(buildSignedDocument(/* current args */, ns: "cc-touch-id-gate/v1"))
        let without = canonicalBytes(buildSignedDocument(/* current args */, ns: nil))
        XCTAssertTrue(String(data: withNs, encoding: .utf8)!.contains("\"ns\":\"cc-touch-id-gate/v1\""))
        XCTAssertNotEqual(withNs, without)
    }
}
```

- [ ] **Step 3: Run — verify it fails**

Run: `swift test --filter CCGateCoreTests.CanonicalNsTests`
Expected: FAIL — `buildSignedDocument` has no `ns:` parameter.

- [ ] **Step 4: Implement**

Add `public let ns: String?` to `SignedDocument`; add `ns` to `CodingKeys`; give `buildSignedDocument` a trailing `ns: String? = nil`. In `canonicalBytes`, ensure a **nil `ns` is omitted entirely** (not serialized as null) so existing bytes are unchanged — e.g. `encoder.outputFormatting` already sorts keys; make `ns` a normal optional so `JSONEncoder` omits nil (confirm the encoder's nil-handling; if it emits `null`, guard by building the dict without the key when nil).

- [ ] **Step 5: Run green + full suite (FIDO golden tests unchanged)**

Run: `swift test`
Expected: PASS including SP1 `CanonicalTests` golden values (proves FIDO bytes unchanged).

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat(core): optional ns domain-separator on SignedDocument (nil for FIDO, set for SE)"
```

---

### Task 4: `CCTouchIDBackend` target — port `SecureEnclave.swift` + `TouchIdVerifier` + ported [SW] tests

**Files:**
- Modify: `Package.swift` (add `CCTouchIDBackend` target + `CCTouchIDBackendTests`)
- Create: `Sources/CCTouchIDBackend/SecureEnclave.swift` (ported from the fork)
- Create: `Sources/CCTouchIDBackend/TouchIdConstants.swift` (`touchIdKeyTag`, `touchIdAppBinary`)
- Create: `Sources/CCTouchIDBackend/TouchIdVerifier.swift`
- Create: `Tests/CCTouchIDBackendTests/SecureEnclaveTests.swift` (ported), `TouchIdVerifierTests.swift`

**Interfaces:**
- Produces: the `se*` free functions (`seVerify`/`seSign`/`seCreateKey`/`seFetchKey`/`seExportPublicKey`/`seDeleteKey`/`seKeyExists`), `TouchIDCanceller`, `SEError`, `randomBytes`, `hexEncode`/`hexDecode`; `let touchIdKeyTag = "com.mobilitylabs.cctouchid.gate"`, `let touchIdAppBinary = "/opt/cc-touch-id-gate/cc-touch-id.app/Contents/MacOS/cc-touch-id"`; `struct TouchIdVerifier: Verifier` init `(allowedSigners: String)`.

- [ ] **Step 1: Add the target to `Package.swift`**

```swift
    .target(name: "CCTouchIDBackend", dependencies: ["CCGateCore"]),
    // …
    .testTarget(name: "CCTouchIDBackendTests", dependencies: ["CCTouchIDBackend", "CCGateCore"]),
```

- [ ] **Step 2: Port `SecureEnclave.swift` + constants**

Copy `worktree-touch-id-gate:Sources/CCTouchIDCore/SecureEnclave.swift` to `Sources/CCTouchIDBackend/SecureEnclave.swift` **verbatim**, then: replace the `Paths.keyTag` default in `seSign` with `touchIdKeyTag`. Create `TouchIdConstants.swift`:
```swift
import Foundation
public let touchIdKeyTag = "com.mobilitylabs.cctouchid.gate"
public let touchIdAppBinary = "/opt/cc-touch-id-gate/cc-touch-id.app/Contents/MacOS/cc-touch-id"
```

- [ ] **Step 3: Port the [SW] `seVerify` roundtrip tests**

Copy `worktree-touch-id-gate:Tests/CCTouchIDCoreTests/SecureEnclaveTests.swift` (the 4 software-key cases) to `Tests/CCTouchIDBackendTests/SecureEnclaveTests.swift`, updating the `@testable import` to `CCTouchIDBackend`.

- [ ] **Step 4: Write `TouchIdVerifier` + its test**

`Tests/CCTouchIDBackendTests/TouchIdVerifierTests.swift`:
```swift
import XCTest
import Security
@testable import CCTouchIDBackend

final class TouchIdVerifierTests: XCTestCase {
    private func softwareKeyAndPubHex() -> (SecKey, String) {
        var e: Unmanaged<CFError>?
        let priv = SecKeyCreateRandomKey([kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                                          kSecAttrKeySizeInBits as String: 256] as CFDictionary, &e)!
        let raw = SecKeyCopyExternalRepresentation(SecKeyCopyPublicKey(priv)!, &e)! as Data
        return (priv, hexEncode(raw))
    }
    private func sign(_ p: SecKey, _ m: Data) -> Data {
        var e: Unmanaged<CFError>?; return SecKeyCreateSignature(p, .ecdsaSignatureMessageX962SHA256, m as CFData, &e)! as Data
    }
    private func writeHex(_ hex: String) -> String {
        let path = NSTemporaryDirectory() + "tidpub-\(getpid())-\(hex.prefix(6))"
        try! hex.write(toFile: path, atomically: true, encoding: .utf8); return path
    }
    func testEnrolledKeyVerifies() {
        let (p, hex) = softwareKeyAndPubHex(); let c = Data("hi".utf8); let s = sign(p, c)
        XCTAssertTrue(TouchIdVerifier(allowedSigners: writeHex(hex)).verify(challenge: c, signature: s))
    }
    func testWrongKeyRejected() {
        let (p, _) = softwareKeyAndPubHex(); let (_, otherHex) = softwareKeyAndPubHex()
        let c = Data("hi".utf8); let s = sign(p, c)
        XCTAssertFalse(TouchIdVerifier(allowedSigners: writeHex(otherHex)).verify(challenge: c, signature: s))
    }
    func testTamperedChallengeRejected() {
        let (p, hex) = softwareKeyAndPubHex(); let s = sign(p, Data("hi".utf8))
        XCTAssertFalse(TouchIdVerifier(allowedSigners: writeHex(hex)).verify(challenge: Data("ho".utf8), signature: s))
    }
    func testMissingFileRejects() {
        XCTAssertFalse(TouchIdVerifier(allowedSigners: "/no/such").verify(challenge: Data("x".utf8), signature: Data([0])))
    }
}
```
Then `Sources/CCTouchIDBackend/TouchIdVerifier.swift`:
```swift
import Foundation
import CCGateCore
/// Broker-side. Reads the hex-encoded X9.63 enrolled pubkey and verifies via CryptoKit seVerify.
public struct TouchIdVerifier: Verifier {
    let allowedSigners: String
    public init(allowedSigners: String) { self.allowedSigners = allowedSigners }
    public func verify(challenge: Data, signature: Data) -> Bool {
        guard let hex = try? String(contentsOfFile: allowedSigners, encoding: .utf8),
              let pub = hexDecode(hex.trimmingCharacters(in: .whitespacesAndNewlines)), !pub.isEmpty
        else { return false }
        return seVerify(message: challenge, signatureDER: signature, publicKeyX963: pub)
    }
}
```

- [ ] **Step 5: Run [SW] tests + build**

Run: `swift test --filter CCTouchIDBackendTests && swift build`
Expected: PASS (4 ported seVerify cases + 4 TouchIdVerifier cases). SE create/sign are USER-RUN (Task 11).

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat(touchid): CCTouchIDBackend — port SecureEnclave.swift + TouchIdVerifier ([SW] roundtrips)"
```

---

### Task 5: `TouchIdSigner` + `TouchIdCeremony` (biometric sheet, LAContext cancel)

**Files:**
- Create: `Sources/CCTouchIDBackend/TouchIdCeremony.swift`
- Create: `Tests/CCTouchIDBackendTests/TouchIdCeremonyTests.swift`

**Interfaces:**
- Consumes: `GateCeremony`, `CeremonyCanceller` (core), `seSign`, `TouchIDCanceller`, `touchIdKeyTag`.
- Produces: `struct TouchIdCeremony: GateCeremony` init `()`; `struct TouchIdSigner: Signer` (optional — wraps `seSign` for parity, if used by the enroll positive-control).

- [ ] **Step 1: Write the [SW]-testable pieces' test**

Real SE sign is USER-RUN. [SW] can assert: (i) a `TouchIDCanceller.cancel()` is idempotent + non-crashing, (ii) `TouchIdCeremony` denies (nil) when no key is enrolled (`seFetchKey` → notFound). No assertion may depend on a live prompt.
`Tests/CCTouchIDBackendTests/TouchIdCeremonyTests.swift`:
```swift
import XCTest
@testable import CCTouchIDBackend
final class TouchIdCeremonyTests: XCTestCase {
    func testCancellerIdempotent() {
        let c = TouchIDCanceller(); c.cancel(); c.cancel(); XCTAssertTrue(c.isCancelled)
    }
    func testDeniesWhenNoKeyEnrolled() {
        seDeleteKey(tag: touchIdKeyTag)   // ensure clean
        // No enrolled key -> seSign throws notFound -> ceremony returns nil (deny).
        XCTAssertNil(TouchIdCeremony().confirmAndSign(rendering: "x", challenge: Data("x".utf8), displayName: "cc-touch-id"))
    }
}
```
> `TouchIDCanceller` has a public `init()` and `isCancelled` in the ported `SecureEnclave.swift`.

- [ ] **Step 2: Run — verify it fails**

Run: `swift test --filter CCTouchIDBackendTests.TouchIdCeremonyTests`
Expected: FAIL — `TouchIdCeremony` undefined.

- [ ] **Step 3: Implement `TouchIdCeremony`**

`Sources/CCTouchIDBackend/TouchIdCeremony.swift`:
```swift
import Foundation
import CCGateCore
/// Client-side. The native Touch ID sheet IS the presence ceremony (no osascript). reason = rendering
/// (verb-phrase; large writes already digest-mode in the shared humanRendering). Fail-closed → nil.
public final class TouchIdCeremony: GateCeremony {
    public init() {}
    public func confirmAndSign(rendering: String, challenge: Data, displayName: String) -> Data? {
        let canceller = TouchIDCanceller()
        return try? seSign(message: challenge, tag: touchIdKeyTag, reason: rendering, canceller: canceller)
    }
}
```
> The `displayName` is unused in the sheet (macOS prepends "cc-touch-id wants to …"); keep the seam signature uniform. If a `Signer` conformance is wanted for the enroll positive-control, add a trivial `TouchIdSigner` wrapping `seSign` — otherwise the enroller calls `seSign` directly (Task 7).

- [ ] **Step 4: Run [SW] tests + build**

Run: `swift test --filter CCTouchIDBackendTests.TouchIdCeremonyTests && swift build`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(touchid): TouchIdCeremony (seSign biometric sheet, TouchIDCanceller)"
```

---

### Task 6: Make `runEnroll` method-agnostic — expand `Enroller`, move FIDO enroll into `FidoEnroller`, retire the grep-gate carve-out

**Files:**
- Modify: `Sources/CCGateCore/Signing/Enroller.swift` (expand protocol)
- Modify: `Sources/CCGateCore/Enroll.swift` (thin, FIDO-free driver)
- Modify: `Sources/CCFidoBackend/FidoEnroller.swift` (implement `enroll`/`positiveControl`; keep `enrollPlan` internal)
- Modify: `Sources/cc-fido/main.swift:97-106` (new `runEnroll` call)
- Modify: `Tests/CCGateCoreTests/GrepGateTests.swift` (remove the `Enroll.swift` exclusion)
- Modify: `Tests/CCGateCoreTests/GateCeremonySeamTests.swift` (`NoopEnroller` → expanded shape)

**Interfaces:**
- Produces (expanded `Enroller`): `enroll(home:keys:profile:) throws`, `positiveControl(home:profile:) -> Bool`, `isEnrolled(home:) -> Bool`, `removeKeyMaterial(home:)`; **removes** protocol-level `enrollPlan` (stays a `FidoEnroller` method). `runEnroll(home:keys:enroller:profile:) throws`.

- [ ] **Step 1: Expand the protocol**

`Sources/CCGateCore/Signing/Enroller.swift`:
```swift
import Foundation
public protocol Enroller {
    func enroll(home: String, keys: Int, profile: GateProfile) throws
    func positiveControl(home: String, profile: GateProfile) -> Bool
    func isEnrolled(home: String) -> Bool
    func removeKeyMaterial(home: String)
}
```

- [ ] **Step 2: Thin, FIDO-free `Enroll.swift`**

```swift
import Foundation
public enum EnrollError: Error { case failed(String) }
public func runEnroll(home: String, keys: Int, enroller: Enroller, profile: GateProfile) throws {
    try enroller.enroll(home: home, keys: max(1, keys), profile: profile)
    if !enroller.positiveControl(home: home, profile: profile) {
        throw EnrollError.failed("positive control failed — presence not verified")
    }
}
```

- [ ] **Step 3: Move the FIDO enroll body into `FidoEnroller`**

Move the old `runEnroll` body into `FidoEnroller.enroll` (using `fidoSignKeygen`, `home + "/.ccfido"`, `fidoProfile.namespace` directly; keep `enrollPlan` as an internal method); implement `positiveControl` = `fidoNegativeBlinkTest(handle: "\(home)/.ccfido/gate_sk1", namespace: profile.namespace)`. (See rev-1 code sketch; unchanged.)

- [ ] **Step 4: Update `cc-fido/main.swift`**

```swift
case "enroll":
    if getuid() == 0 { FileHandle.standardError.write(Data("cc-fido enroll: run as your login user (not sudo)\n".utf8)); exit(1) }
    let keys = flagValue("--keys", in: args).flatMap { Int($0) } ?? 1
    let home = realLoginHome()
    do { try runEnroll(home: home, keys: keys, enroller: FidoEnroller(), profile: fidoProfile)
         print("cc-fido: enrolled. Next: sudo cc-fido activate"); exit(0) }
    catch { FileHandle.standardError.write(Data("cc-fido enroll failed: \(error)\n".utf8)); exit(1) }
```

- [ ] **Step 5: Remove the grep-gate carve-out + fix the `NoopEnroller` fake**

Delete the `.filter { $0.lastPathComponent != "Enroll.swift" }` in `GrepGateTests.swift`. Update `NoopEnroller` in `GateCeremonySeamTests.swift` to the expanded shape:
```swift
struct NoopEnroller: Enroller {
    func enroll(home: String, keys: Int, profile: GateProfile) throws {}
    func positiveControl(home: String, profile: GateProfile) -> Bool { true }
    func isEnrolled(home: String) -> Bool { false }
    func removeKeyMaterial(home: String) {}
}
```

- [ ] **Step 6: Build + full suite**

Run: `swift build && swift test`
Expected: PASS. `GrepGateTests` green including `Enroll.swift`; `FidoEnrollerTests` green (`enrollPlan` present).

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "refactor(core): method-agnostic runEnroll via Enroller.enroll/positiveControl; Enroll.swift FIDO-free"
```

---

### Task 7: `TouchIdEnroller` — SE key create, hex-X9.63 register, isEnrolled/removeKeyMaterial, sign→verify positive control

**Files:**
- Create: `Sources/CCTouchIDBackend/TouchIdEnroller.swift`
- Create: `Tests/CCTouchIDBackendTests/TouchIdEnrollerTests.swift`

**Interfaces:**
- Consumes: `Enroller`, `GateProfile`, `runPrivileged` (core), the `se*` functions, `TouchIdVerifier`, `touchIdKeyTag`.
- Produces: `struct TouchIdEnroller: Enroller` init `(priv: @escaping ([String]) -> Bool = { runPrivileged($0) })`; `func register(pubHex:profile:)`.

- [ ] **Step 1: Write the [SW]-testable tests**

`Tests/CCTouchIDBackendTests/TouchIdEnrollerTests.swift`:
```swift
import XCTest
@testable import CCTouchIDBackend
@testable import CCGateCore

final class TouchIdEnrollerTests: XCTestCase {
    private func profile() -> GateProfile {
        GateProfile(serviceAccount: "_cctouchid", accountRealName: "rn", namespace: "cc-touch-id-gate/v1",
            keydir: "/var/cctouchid", runDir: "/var/cctouchid-run", sock: "/var/cctouchid-run/g.sock",
            daemonLogErr: "/var/cctouchid/e.err", codeDir: "/opt/cc-touch-id-gate", policy: "/opt/cc-touch-id-gate/p.json",
            binaryName: "cc-touch-id", displayName: "cc-touch-id", launchdLabel: "com.cc-touch-id-gate.brokerd",
            plist: "/L/x.plist", daemonMatchPattern: "cc-touch-id daemon", claudeCodeDir: "/CC", managedSettings: "/CC/m.json")
    }
    func testIsEnrolledFalseWhenNoKey() {
        seDeleteKey(tag: touchIdKeyTag)
        XCTAssertFalse(TouchIdEnroller().isEnrolled(home: "/tmp/h"))
    }
    func testRegisterAppendsHexPubkeyNoPrincipal() {
        var captured: [[String]] = []
        TouchIdEnroller(priv: { captured.append($0); return true }).register(pubHex: "0401ab", profile: profile())
        let joined = captured.last!.joined(separator: " ")
        XCTAssertTrue(joined.contains("/var/cctouchid/allowed_signers"))
        XCTAssertTrue(joined.contains("0401ab"))
        XCTAssertFalse(joined.contains("gate-principal"))
    }
}
```

- [ ] **Step 2: Run — verify it fails**

Run: `swift test --filter CCTouchIDBackendTests.TouchIdEnrollerTests`
Expected: FAIL — `TouchIdEnroller` undefined.

- [ ] **Step 3: Implement `TouchIdEnroller`**

`Sources/CCTouchIDBackend/TouchIdEnroller.swift`:
```swift
import Foundation
import CCGateCore
public struct TouchIdEnroller: Enroller {
    let priv: ([String]) -> Bool
    public init(priv: @escaping ([String]) -> Bool = { runPrivileged($0) }) { self.priv = priv }

    /// Overwrite the single enrolled hex-X9.63 pubkey ($1 positional — never interpolated).
    public func register(pubHex: String, profile: GateProfile) {
        _ = priv(["/bin/sh", "-c", "printf '%s\\n' \"$1\" > \(profile.allowedSigners)", "sh", pubHex])
    }
    public func enroll(home: String, keys: Int, profile: GateProfile) throws {
        seDeleteKey(tag: touchIdKeyTag)                                   // idempotent re-enroll
        FileHandle.standardError.write(Data(">>> Creating the cc-touch-id Secure Enclave key <<<\n".utf8))
        _ = try seCreateKey(tag: touchIdKeyTag)                           // needs the entitled binary
        let pubHex = hexEncode(try seExportPublicKey(tag: touchIdKeyTag))
        register(pubHex: pubHex, profile: profile)
        _ = priv(["/usr/sbin/chown", profile.serviceAccount, profile.allowedSigners])
        _ = priv(["/bin/chmod", "600", profile.allowedSigners])
    }
    public func positiveControl(home: String, profile: GateProfile) -> Bool {
        let nonce = randomBytes(32)
        FileHandle.standardError.write(Data(">>> TOUCH to confirm enrollment <<<\n".utf8))
        guard let sig = try? seSign(message: nonce, tag: touchIdKeyTag, reason: "confirm cc-touch-id enrollment") else { return false }
        return TouchIdVerifier(allowedSigners: profile.allowedSigners).verify(challenge: nonce, signature: sig)
    }
    public func isEnrolled(home: String) -> Bool { seKeyExists(tag: touchIdKeyTag) }
    public func removeKeyMaterial(home: String) { _ = seDeleteKey(tag: touchIdKeyTag) }
}
```

- [ ] **Step 4: Run [SW] tests + build**

Run: `swift test --filter CCTouchIDBackendTests.TouchIdEnrollerTests && swift build`
Expected: PASS (register shape + clean-home isEnrolled). Full SE enroll is Task 11.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(touchid): TouchIdEnroller (SE key, hex-X9.63 register, sign->verify positive control)"
```

---

### Task 8: `touchIdProfile` + `makeTouchIdContext`

**Files:**
- Create: `Sources/CCTouchIDBackend/TouchIdProfile.swift`
- Create: `Tests/CCTouchIDBackendTests/TouchIdProfileTests.swift`

**Interfaces:**
- Produces: `public let touchIdProfile: GateProfile`; `public func makeTouchIdContext(home: String) -> GateContext`.

- [ ] **Step 1: Write the profile test**

```swift
import XCTest
@testable import CCTouchIDBackend
@testable import CCGateCore
final class TouchIdProfileTests: XCTestCase {
    func testProfileIdentity() {
        let p = touchIdProfile
        XCTAssertEqual(p.serviceAccount, "_cctouchid")
        XCTAssertEqual(p.binaryName, "cc-touch-id")
        XCTAssertEqual(p.namespace, "cc-touch-id-gate/v1")
        XCTAssertEqual(p.sock, "/var/cctouchid-run/gate.sock")
        XCTAssertEqual(p.allowedSigners, "/var/cctouchid/allowed_signers")
        XCTAssertEqual(p.launchdLabel, "com.cc-touch-id-gate.brokerd")
    }
    func testContextComposesTouchIdSeams() {
        let ctx = makeTouchIdContext(home: "/tmp/h")
        XCTAssertTrue(ctx.ceremony is TouchIdCeremony)
        XCTAssertTrue(ctx.verifier is TouchIdVerifier)
        XCTAssertTrue(ctx.enroller is TouchIdEnroller)
    }
}
```

- [ ] **Step 2: Run — verify it fails**

Run: `swift test --filter CCTouchIDBackendTests.TouchIdProfileTests`
Expected: FAIL — undefined.

- [ ] **Step 3: Implement**

```swift
import Foundation
import CCGateCore
public let touchIdProfile = GateProfile(
    serviceAccount: "_cctouchid", accountRealName: "cc-touch-id broker",
    namespace: "cc-touch-id-gate/v1",
    keydir: "/var/cctouchid", runDir: "/var/cctouchid-run", sock: "/var/cctouchid-run/gate.sock",
    daemonLogErr: "/var/cctouchid/brokerd.err",
    codeDir: "/opt/cc-touch-id-gate", policy: "/opt/cc-touch-id-gate/policy.json",
    binaryName: "cc-touch-id", displayName: "cc-touch-id",
    launchdLabel: "com.cc-touch-id-gate.brokerd",
    plist: "/Library/LaunchDaemons/com.cc-touch-id-gate.brokerd.plist",
    daemonMatchPattern: "cc-touch-id daemon",
    claudeCodeDir: "/Library/Application Support/ClaudeCode",
    managedSettings: "/Library/Application Support/ClaudeCode/managed-settings.json")

public func makeTouchIdContext(home: String) -> GateContext {
    GateContext(profile: touchIdProfile, ceremony: TouchIdCeremony(),
                verifier: TouchIdVerifier(allowedSigners: touchIdProfile.allowedSigners),
                enroller: TouchIdEnroller())
}
```

- [ ] **Step 4: Run green + build**

Run: `swift test --filter CCTouchIDBackendTests.TouchIdProfileTests && swift build`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(touchid): touchIdProfile + makeTouchIdContext composition"
```

---

### Task 9: `cc-touch-id` executable + dispatcher

**Files:**
- Modify: `Package.swift` (add `cc-touch-id` executable target)
- Create: `Sources/cc-touch-id/main.swift`

- [ ] **Step 1: Add the executable target**

```swift
    .executableTarget(name: "cc-touch-id", dependencies: ["CCGateCore", "CCTouchIDBackend"]),
```

- [ ] **Step 2: Write the dispatcher**

Mirror `Sources/cc-fido/main.swift` (and the fork's `Sources/cc-touch-id/main.swift`), with: `import CCTouchIDBackend`; context via `makeTouchIdContext`/`touchIdProfile`; user-facing strings `cc-touch-id`; `enroll` → `runEnroll(home:keys:1, enroller: TouchIdEnroller(), profile: touchIdProfile)`; add `_presence-test` (sign+verify self-test via `seSign`/`TouchIdVerifier`); add `_delete-key` (`seDeleteKey(tag: touchIdKeyTag)`); **drop** `_blink-test`; `_render-managed` passes `hookCmd = touchIdAppBinary + " hook"` (entitled binary); `_render-plist` targets the plain daemon binary `touchIdProfile.codeDir + "/" + touchIdProfile.binaryName`. All other cases (`install`/`activate`/`uninstall`/`status`/`enroll-file`/`enroll-dir`/`_verify-audit`/`_registry-add`/`_validate-policy`/`_render-policy`) copy the `cc-fido` bodies verbatim swapping `makeFidoContext`→`makeTouchIdContext`, `fidoProfile`→`touchIdProfile`.

- [ ] **Step 3: Build both executables + smoke**

Run: `swift build && swift test`
Then: `.build/debug/cc-touch-id status --json`
Expected: both binaries build; suites green; status prints all-negative JSON on an un-installed machine.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "feat(touchid): cc-touch-id executable + dispatcher"
```

---

### Task 10: Packaging (provisioned + notarized `.app`), marketplace, plugin, install skill

**Files:**
- Create: `packaging/project.yml`, `packaging/CCTouchID.entitlements` (ported + Developer-ID-adjusted per Task 1)
- Create: `packaging/build-signed.sh` (xcodegen → xcodebuild → Developer-ID re-sign → notarize → staple → strip get-task-allow)
- Modify: `.claude-plugin/marketplace.json`
- Create: `plugins/cc-touch-id/.claude-plugin/plugin.json`, `plugins/cc-touch-id/skills/install/SKILL.md`
- Create: `plugins/cc-touch-id/install/policy.json`, `plugins/cc-touch-id/install/POLICY.md`
- Create: `install/` scripts ported from the fork (`account-setup.sh`, install/enroll/activate/teardown)
- Modify: `README.md`

- [ ] **Step 1: Port packaging + write the signing script**

Copy the fork's `packaging/` (already staged in Task 1). Write `packaging/build-signed.sh` encoding the Task-1 recipe: `xcodegen generate` → `xcodebuild … -allowProvisioningUpdates build` → `codesign --force --options runtime --timestamp --entitlements CCTouchID.entitlements --sign "Developer ID Application: … (HH3SJBAS42)"` → `notarytool submit --wait` → `stapler staple` → assert `get-task-allow` absent. (If Task 1 chose the dev-signed fallback, the script uses the Apple-Development identity and skips notarize/staple, with a printed WARNING.)

- [ ] **Step 2: Marketplace + plugin.json**

`.claude-plugin/marketplace.json` add `{ "name": "cc-touch-id", "source": "./plugins/cc-touch-id" }`.
`plugins/cc-touch-id/.claude-plugin/plugin.json`:
```json
{ "name": "cc-touch-id", "description": "Require a Touch ID (Secure Enclave) presence check before high-risk Claude Code tool calls.", "version": "0.1.0" }
```

- [ ] **Step 3: Install scripts + policy**

Port the fork's `install/` + `scripts/userrun/task7_install.sh` shape into repo `install/` for `cc-touch-id`: create `_cctouchid`; dirs; copy plain daemon binary (ad-hoc codesign) + the notarized `.app` to `codeDir`; policy; chown/chmod; render+install plist (daemon → plain binary) + managed-settings (hook → `touchIdAppBinary`); enroll-circularity stop; `launchctl bootstrap`+`kickstart`; canary denial. Copy `plugins/cc-fido/install/policy.json`→`plugins/cc-touch-id/install/policy.json`; adapt `POLICY.md`.

- [ ] **Step 4: Install skill (Step-0 preflight + build)**

`plugins/cc-touch-id/skills/install/SKILL.md`: **Step 0** — `xcode-select -p`; `bioutil` (Touch ID hardware + enrolled fingerprint); **Developer ID Application cert present + notarization credential** (`security find-identity`; `notarytool` keychain profile) — if absent, offer the dev-signed fallback; then `packaging/build-signed.sh`; then install/enroll/activate one step at a time. Prominent note: **cc-touch-id and cc-fido do not coexist yet** (Pillar C); installing one replaces the other's managed hook.

- [ ] **Step 5: README**

Add a "Touch ID gate" section pointing at `/cc-touch-id:install`, the provisioned/notarized-build prerequisite, and the no-coexistence caveat.

- [ ] **Step 6: Validate + build**

Run: `swift build && swift test`; if available `claude plugin validate .`
Expected: build/tests PASS; plugin validates. (The `.app` build itself is USER-RUN — needs signing creds/hardware — in Task 11.)

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "feat(packaging): cc-touch-id provisioned+notarized .app, plugin, install skill, marketplace"
```

---

### Task 11: [USER-RUN] hardware acceptance — human runs, pastes output

**Files:**
- Create: `scripts/userrun/touchid_accept.sh`, `scripts/userrun/touchid_cancel.sh`

**Cannot be run by Claude** (needs signing credentials + sudo + a fingerprint). Authored here; human runs un-sandboxed and pastes output.

- [ ] **Step 1: Author `touchid_accept.sh`** (mirror `task7_accept.sh` for `cc-touch-id`): build-signed `.app` present → `sudo` install → `cc-touch-id enroll` (SE key + positive-control touch) → `sudo` activate → gated write → operator touches → assert write landed + `_verify-audit` shows `write_ok`. Guard against outer sudo.

- [ ] **Step 2: Author `touchid_cancel.sh`** (mirror the FIDO cancel script): gated write → Touch ID sheet → operator Cancels (and, second run, Escape/give-up) → assert prompt deny, no write (mtime/content unchanged), no successful touch.

- [ ] **Step 3: [USER-RUN] Approve+Touch** — human runs `sudo scripts/userrun/touchid_accept.sh`; confirms enroll positive-control, gate fires, real fingerprint approves a gated write, daemon verifies.

- [ ] **Step 4: [USER-RUN] Cancel + give-up** — human runs `touchid_cancel.sh`; confirms deny/no-write for both Cancel and Escape/give-up.

- [ ] **Step 5: [USER-RUN] Clean-machine install** — human runs `/cc-touch-id:install` where `command -v cc-touch-id` initially fails; confirms notarized build + reaches `status: active`.

- [ ] **Step 6: Commit (after human confirms)**

```bash
git add scripts/userrun/touchid_accept.sh scripts/userrun/touchid_cancel.sh
git commit -m "test(userrun): cc-touch-id acceptance (enroll+approve+touch; Cancel/give-up deny, no write)"
```

---

## Self-Review

**Spec coverage:** distribution-signing gate (Developer ID + notarization) → Task 1; `GateCeremony` + move `confirmAndSign` + `GateContext.ceremony` → Task 2; optional `ns` (FIDO-nil byte-identity) → Task 3; `CCTouchIDBackend` + ported `SecureEnclave.swift` + `TouchIdVerifier` + ported [SW] `seVerify` tests → Task 4; `TouchIdCeremony`/`TouchIDCanceller` → Task 5; method-agnostic `runEnroll` + Enroll.swift de-FIDO + grep-gate retired → Task 6; `TouchIdEnroller` (SE key, hex-X9.63 register, sign→verify positive control) → Task 7; `touchIdProfile`/`makeTouchIdContext` → Task 8; `cc-touch-id` executable → Task 9; provisioned+notarized packaging + plugin + install skill + marketplace → Task 10; USER-RUN device acceptance → Task 11. Pillar C correctly **absent** (no-coexistence caveat in Task 10).

**Placeholder scan:** no TBD/TODO; every code step shows complete code or an explicit verbatim port from a named fork file; the `buildSignedDocument(/* current args */)` markers in Task 3 are intentional — the implementer fills them from the file read in Task 3 Step 1 (the current signature is not yet in this plan's context).

**Type consistency:** `GateCeremony.confirmAndSign(rendering:challenge:displayName:)`, `GateContext(profile:ceremony:verifier:enroller:)`, `SignedDocument.ns: String?` / `buildSignedDocument(..., ns:)`, `Enroller.enroll(home:keys:profile:)`/`positiveControl(home:profile:)`/`isEnrolled(home:)`/`removeKeyMaterial(home:)`, `seVerify(message:signatureDER:publicKeyX963:)`, `seSign(message:tag:reason:canceller:)`, `seCreateKey(tag:)`, `seExportPublicKey(tag:)`, `seKeyExists(tag:)`, `seDeleteKey(tag:)`, `hexEncode`/`hexDecode`, `TouchIDCanceller()`, `touchIdKeyTag`/`touchIdAppBinary`, `TouchIdVerifier(allowedSigners:)`, `TouchIdCeremony()`, `TouchIdEnroller(priv:)`/`register(pubHex:profile:)`, `touchIdProfile`/`makeTouchIdContext(home:)` — consistent across tasks and matched to the fork's actual `SecureEnclave.swift` signatures.

**Note on strict-green execution:** Task 2's `NoopEnroller` uses the pre-Task-6 `Enroller` (with `enrollPlan`); Task 6 Step 5 switches it. Task 1 (signing gate) and Task 11 are USER-RUN.
