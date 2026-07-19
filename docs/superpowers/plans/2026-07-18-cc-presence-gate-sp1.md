# cc-presence-gate SP1 — Core Extraction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extract the method-agnostic enforcement engine into a `CCGateCore` library behind four seams (`Signer`/`Verifier`, `Enroller`, `CeremonyCanceller`, `GateProfile`) and restructure the repo into the `cc-presence-gate` monorepo + marketplace layout, with FIDO's runtime gate behavior unchanged.

**Architecture:** One SwiftPM package with three targets — `CCGateCore` (shared engine, zero FIDO identity), `CCFidoBackend` (FIDO conformances + `fidoProfile`), and the `cc-fido` executable (composes a `GateContext` and injects it). A `GateProfile` struct replaces the `Paths` constant bag; `Paths` is deleted so the compiler enumerates every reference. The [SW] test suite plus a USER-RUN e2e are the safety net — this is a pure refactor.

**Tech Stack:** Swift 5.9, SwiftPM, macOS 13+, XCTest. No new dependencies.

**Source spec:** `docs/superpowers/specs/2026-07-18-cc-presence-gate-sp1-core-extraction-design.md` (5-model reviewed, unanimous APPROVED).

## Global Constraints

- **Swift tools 5.9, macOS 13+** — do not change `Package.swift` platform/tools floor.
- **No runtime behavior change** to the FIDO gate. Every task ends with `swift build && swift test` green; expected *values* in existing tests do not change — only call-site signatures and import/target splits.
- **Grep gate (done-criterion):** after Task 9, `Sources/CCGateCore/` must contain **zero** matches for any of: `_ccfido` · `.ccfido` · `gate_sk` · `gate-principal` · `cc-fido` · `ccfido` · `/var/ccfido` · `cc-fido-gate@` · `com.cc-fido-gate` · `brokerd` (comments and error strings included). **Exception, by explicit user decision:** `Enroll.swift` is excluded from the sweep — its FIDO enroll-ceremony literals (`.ccfido`, `gate_sk`, `gate-principal`) are a documented SP2 residual; de-FIDO-ing `runEnroll` is deferred past SP1.
- **`normPath`'s firmlink set `["/var", "/etc", "/tmp"]` is a fixed platform constant** — never profile-derive it (`Broker.swift:19-28`).
- **`scrubEnv`/`scrubbedEnv` stays in `CCGateCore`** as the single env-allowlist for every child spawn — never stranded into a backend.
- **Fail-closed everywhere** — unreadable payload, missing policy, bad regex, `getpwnam` failure, unknown tool → deny. Preserve on every edited decision path.
- **`Signer.sign`'s `canceller` is non-optional.** The nil-canceller hang is the regression the seam exists to kill.
- **`cc-fido` product/binary name is unchanged** — the userrun scripts' `$REPO/.build/release/cc-fido` paths must survive the package rename.

---

### Task 1: Marketplace-clone mechanics spike (gates Task 8)

**Why first:** the skill's Step-0 binary bootstrap is written against whichever layout the marketplace actually delivers. This is an investigation task, not TDD; its written finding is the deliverable.

**Files:**
- Create: `docs/superpowers/spikes/2026-07-18-marketplace-clone-mechanics.md`

- [ ] **Step 1: Reproduce a local marketplace install**

Run, from the repo root:
```bash
claude plugin validate .            # if the CLI exposes it; else note "not available"
```
Then add the repo as a local marketplace and install the (not-yet-created) plugin dir per current Claude Code docs, and inspect what lands under `~/.claude`:
```bash
ls -la ~/.claude/plugins/ 2>/dev/null
find ~/.claude -maxdepth 4 -name 'plugin.json' 2>/dev/null
find ~/.claude -maxdepth 4 -name 'Package.swift' 2>/dev/null
```

- [ ] **Step 2: Record the answer to the one load-bearing question**

Write to the spike doc: does `/plugin install` place **the whole repo tree** (so `${CLAUDE_PLUGIN_ROOT}/..` reaches `Package.swift`) or **only the `plugins/cc-fido/` subtree**? Include the observed `find` output as evidence. If only the plugin dir ships, record the fallback (documented `git clone` + `swift build` prerequisite in the skill).

- [ ] **Step 3: Commit**

```bash
git add docs/superpowers/spikes/2026-07-18-marketplace-clone-mechanics.md
git commit -m "docs(spike): marketplace-clone mechanics for cc-fido plugin bootstrap"
```

---

### Task 2: Rename module `CCFidoCore` → `CCGateCore`, add empty `CCFidoBackend` target (stays green)

**Files:**
- Modify: `Package.swift`
- Rename dir: `Sources/CCFidoCore/` → `Sources/CCGateCore/`
- Rename dir: `Tests/CCFidoCoreTests/` → `Tests/CCGateCoreTests/`
- Modify: `Sources/cc-fido/main.swift:2` (`import CCFidoCore` → `import CCGateCore`)
- Modify: all 15 test files' `@testable import CCFidoCore` → `@testable import CCGateCore`
- Create: `Sources/CCFidoBackend/Placeholder.swift` (empty stub so the target compiles)

**Interfaces:**
- Produces: module `CCGateCore` (same public API as `CCFidoCore` today), empty library `CCFidoBackend`.

- [ ] **Step 1: Rename the source and test directories**

```bash
git mv Sources/CCFidoCore Sources/CCGateCore
git mv Tests/CCFidoCoreTests Tests/CCGateCoreTests
```

- [ ] **Step 2: Rewrite `Package.swift`**

```swift
// swift-tools-version:5.9
import PackageDescription
let package = Package(
  name: "cc-presence-gate",
  platforms: [.macOS(.v13)],
  targets: [
    .target(name: "CCGateCore"),
    .target(name: "CCFidoBackend", dependencies: ["CCGateCore"]),
    .executableTarget(name: "cc-fido", dependencies: ["CCGateCore", "CCFidoBackend"]),
    .testTarget(name: "CCGateCoreTests", dependencies: ["CCGateCore"]),
    .testTarget(name: "CCFidoBackendTests", dependencies: ["CCFidoBackend", "CCGateCore"]),
  ]
)
```

- [ ] **Step 3: Fix every import in one sweep**

```bash
# main.swift + all test files
grep -rl 'import CCFidoCore' Sources Tests | xargs sed -i '' 's/import CCFidoCore/import CCGateCore/g'
```
Then create the backend stub and an empty backend test dir:
```bash
printf 'import CCGateCore\n' > Sources/CCFidoBackend/Placeholder.swift
mkdir -p Tests/CCFidoBackendTests
printf 'import XCTest\nfinal class BackendPlaceholderTests: XCTestCase { func testPlaceholder() { XCTAssertTrue(true) } }\n' > Tests/CCFidoBackendTests/PlaceholderTests.swift
```

- [ ] **Step 4: Verify build + full suite green**

Run: `swift build && swift test`
Expected: PASS — same test count as before plus the one backend placeholder; no behavior change.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "refactor: rename CCFidoCore→CCGateCore, add empty CCFidoBackend target"
```

---

### Task 3: Define the four seam protocols + `GateProfile` in `CCGateCore` (compile-only)

**Files:**
- Create: `Sources/CCGateCore/Signing/CeremonyCanceller.swift`
- Create: `Sources/CCGateCore/Signing/Signer.swift`
- Create: `Sources/CCGateCore/Signing/Verifier.swift`
- Create: `Sources/CCGateCore/Signing/Enroller.swift`
- Create: `Sources/CCGateCore/Profile/GateProfile.swift`

**Interfaces:**
- Produces:
  - `protocol CeremonyCanceller { func cancel() }`
  - `protocol Signer { func makeCanceller() -> CeremonyCanceller; func sign(challenge: Data, canceller: CeremonyCanceller) throws -> Data }`
  - `protocol Verifier { func verify(challenge: Data, signature: Data) -> Bool }`
  - `protocol Enroller { func enrollPlan(home: String, index: Int) -> [[String]]; func isEnrolled(home: String) -> Bool; func removeKeyMaterial(home: String) }`
  - `struct GateProfile` with the fields below and derived control paths.

- [ ] **Step 1: Write the protocols**

`Signing/CeremonyCanceller.swift`:
```swift
import Foundation
/// Abstract, transport-agnostic cancellation handle for an in-flight signing ceremony.
/// FIDO supplies a Process-terminating impl; Secure Enclave will supply an LAContext-invalidating one.
public protocol CeremonyCanceller { func cancel() }
```

`Signing/Signer.swift`:
```swift
import Foundation
public protocol Signer {
    /// A fresh cancellation handle, one per ceremony. `confirmAndSign` mints one and threads it into `sign`.
    func makeCanceller() -> CeremonyCanceller
    /// Non-optional: every ceremony must pass a handle so the nil-canceller hang is unrepresentable.
    func sign(challenge: Data, canceller: CeremonyCanceller) throws -> Data
}
```

`Signing/Verifier.swift`:
```swift
import Foundation
public protocol Verifier {
    /// Broker-side. Returns true iff `signature` is a valid signature over `challenge` from an enrolled key.
    func verify(challenge: Data, signature: Data) -> Bool
}
```

`Signing/Enroller.swift`:
```swift
import Foundation
public protocol Enroller {
    /// Ordered privileged steps to create + register key #index (1-based). Backend-specific.
    func enrollPlan(home: String, index: Int) -> [[String]]
    /// Is a gate key present for this user? FIDO = key file on disk; SE = keychain query.
    func isEnrolled(home: String) -> Bool
    /// Delete this method's key material (uninstall). FIDO = rm key files; SE = keychain delete.
    func removeKeyMaterial(home: String)
}
```

- [ ] **Step 2: Write `GateProfile` with derived control paths**

`Profile/GateProfile.swift`:
```swift
import Foundation
/// All per-product filesystem topology + identity. Replaces the old `Paths` constant bag.
/// Crypto-primitive details (keygen paths, key handle, ssh signing principal) do NOT live here —
/// they are backend constructor args.
public struct GateProfile {
    public let serviceAccount: String      // e.g. "_ccfido"
    public let accountRealName: String     // e.g. "cc-fido broker"
    public let namespace: String           // signing-domain separator, e.g. "cc-fido-gate@example.test"
    public let keydir: String              // e.g. "/var/ccfido"
    public let runDir: String              // e.g. "/var/ccfido-run"
    public let sock: String                // e.g. "/var/ccfido-run/gate.sock"
    public let daemonLogErr: String        // e.g. "/var/ccfido/brokerd.err"
    public let codeDir: String             // e.g. "/opt/cc-fido-gate"
    public let policy: String              // e.g. "/opt/cc-fido-gate/policy.json"
    public let binaryName: String          // e.g. "cc-fido"
    public let displayName: String         // dialog title, e.g. "cc-fido-gate"
    public let launchdLabel: String        // e.g. "com.cc-fido-gate.brokerd"
    public let plist: String               // e.g. "/Library/LaunchDaemons/com.cc-fido-gate.brokerd.plist"
    public let daemonMatchPattern: String  // pkill -f arg, e.g. "cc-fido daemon"
    public let claudeCodeDir: String       // "/Library/Application Support/ClaudeCode"
    public let managedSettings: String     // claudeCodeDir + "/managed-settings.json"

    public init(serviceAccount: String, accountRealName: String, namespace: String,
                keydir: String, runDir: String, sock: String, daemonLogErr: String,
                codeDir: String, policy: String, binaryName: String, displayName: String,
                launchdLabel: String, plist: String, daemonMatchPattern: String,
                claudeCodeDir: String, managedSettings: String) {
        self.serviceAccount = serviceAccount; self.accountRealName = accountRealName
        self.namespace = namespace; self.keydir = keydir; self.runDir = runDir; self.sock = sock
        self.daemonLogErr = daemonLogErr; self.codeDir = codeDir; self.policy = policy
        self.binaryName = binaryName; self.displayName = displayName; self.launchdLabel = launchdLabel
        self.plist = plist; self.daemonMatchPattern = daemonMatchPattern
        self.claudeCodeDir = claudeCodeDir; self.managedSettings = managedSettings
    }

    // Control files are DERIVED from roots so the deny logic lives in one place.
    public var allowedSigners: String { keydir + "/allowed_signers" }
    public var audit: String { keydir + "/audit.log" }
    public var custody: String { keydir + "/custody.json" }
    public var ceremonyLock: String { keydir + "/ceremony.lock" }
    /// Same six entries as today's Paths.controlDenylist, derived.
    public var controlDenylist: [String] { [allowedSigners, audit, custody, ceremonyLock, sock, policy] }
}
```

- [ ] **Step 3: Verify build (types compile, unused)**

Run: `swift build`
Expected: PASS with "never used" warnings on the new types — acceptable at this step.

- [ ] **Step 4: Commit**

```bash
git add Sources/CCGateCore/Signing Sources/CCGateCore/Profile
git commit -m "feat(core): Signer/Verifier/Enroller/CeremonyCanceller protocols + GateProfile"
```

---

### Task 4: Move FIDO crypto into `CCFidoBackend`; keep `scrubEnv` in core

**Files:**
- Modify: `Sources/CCGateCore/Crypto.swift` — **keep** `scrubbedEnv()`, `MAX_SIG`, `SignError`; **remove** `sign`, `verify`, `SignCanceller` (they move to the backend). Rename the remaining file responsibility: it now holds only the shared env-scrub + sign error type.
- Create: `Sources/CCFidoBackend/FidoSigner.swift` — `SignCanceller` (conforming to `CeremonyCanceller`) + `FidoSigner` (owns `signKeygen`, `keyHandle`).
- Create: `Sources/CCFidoBackend/FidoVerifier.swift` — `FidoVerifier` (owns `verifyKeygen`, `signPrincipal`, `allowedSigners`).
- Delete stub: `Sources/CCFidoBackend/Placeholder.swift`

**Interfaces:**
- Consumes: `scrubbedEnv()` (public in core), `CeremonyCanceller`, `Signer`, `Verifier`.
- Produces:
  - `final class SignCanceller: CeremonyCanceller` (Process-terminating; `func adopt(_:) -> Bool`, `func cancel()`, `var isCancelled`).
  - `struct FidoSigner: Signer` init `(keygen: String, handlePath: String, namespace: String)`.
  - `struct FidoVerifier: Verifier` init `(keygen: String, allowedSigners: String, principal: String, namespace: String, keydir: String)`.

- [ ] **Step 1: Make `scrubbedEnv`/`scrubEnv` public in core (if not already) and strip Crypto.swift to the shared parts**

In `Sources/CCGateCore/Crypto.swift`, keep only: `SignError`, `MAX_SIG`, and `scrubbedEnv()`. Delete the `sign(...)`, `verify(...)`, and `SignCanceller` declarations (they move in Step 2-3). Ensure `public func scrubbedEnv()` and `public func scrubEnv(_:)` (in `HookLogic.swift`) remain public.

- [ ] **Step 2: Create `FidoSigner.swift` in the backend (moves `sign` + `SignCanceller` verbatim, wrapped)**

`Sources/CCFidoBackend/FidoSigner.swift` — move the existing `SignCanceller` class and `sign(...)` free function here **byte-for-byte** (do not "tidy"), then add the `Signer` conformance:
```swift
import Foundation
import Darwin
import CCGateCore

public final class SignCanceller: CeremonyCanceller {
    // ... exact body moved from old Crypto.swift:16-24 ...
}

// (moved verbatim from old Crypto.swift:26-54 — default keygen now injected, no Paths reference)
func fidoSign(challenge: Data, handlePath: String, namespace: String,
              retries: Int = 3, keygen: String, canceller: SignCanceller?) throws -> Data { /* ...verbatim... */ }

public struct FidoSigner: Signer {
    let keygen: String; let handlePath: String; let namespace: String
    public init(keygen: String, handlePath: String, namespace: String) {
        self.keygen = keygen; self.handlePath = handlePath; self.namespace = namespace
    }
    public func makeCanceller() -> CeremonyCanceller { SignCanceller() }
    public func sign(challenge: Data, canceller: CeremonyCanceller) throws -> Data {
        try fidoSign(challenge: challenge, handlePath: handlePath, namespace: namespace,
                     keygen: keygen, canceller: canceller as? SignCanceller)
    }
}
```

- [ ] **Step 3: Create `FidoVerifier.swift` (moves `verify` verbatim, wrapped)**

`Sources/CCFidoBackend/FidoVerifier.swift` — move the `verify(...)` free function here byte-for-byte (path params now injected), then:
```swift
public struct FidoVerifier: Verifier {
    let keygen: String; let allowedSigners: String; let principal: String
    let namespace: String; let keydir: String
    public init(keygen: String, allowedSigners: String, principal: String, namespace: String, keydir: String) {
        self.keygen = keygen; self.allowedSigners = allowedSigners; self.principal = principal
        self.namespace = namespace; self.keydir = keydir
    }
    public func verify(challenge: Data, signature: Data) -> Bool {
        fidoVerify(challenge: challenge, signature: signature, allowedSigners: allowedSigners,
                   principal: principal, namespace: namespace, keygen: keygen, keydir: keydir)
    }
}
```
Delete `Sources/CCFidoBackend/Placeholder.swift`.

- [ ] **Step 4: Verify build green**

Run: `swift build`
Expected: PASS. `CCGateCore` no longer references ssh-keygen for sign/verify; the backend owns them. (Existing `CryptoTests` still call the moved free functions — they will be ported in Task 8; for now, temporarily keep `fidoSign`/`fidoVerify` accessible to the old test file, OR move those tests in this task. Move them: see Task 8 note — if executing strictly green, port `CryptoTests` here now.)

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "refactor(backend): FidoSigner/FidoVerifier + SignCanceller to CCFidoBackend; scrubEnv stays in core"
```

---

### Task 5: Introduce `GateContext` + `fidoProfile`; compose in `main.swift`

**Files:**
- Create: `Sources/CCGateCore/GateContext.swift`
- Create: `Sources/CCFidoBackend/FidoProfile.swift`
- Modify: `Sources/cc-fido/main.swift` (build the context, pass into entry points — wiring completed in Tasks 6-7)

**Interfaces:**
- Produces:
  - `struct GateContext { let profile: GateProfile; let signer: Signer; let verifier: Verifier; let enroller: Enroller }`
  - `public let fidoProfile: GateProfile` (the exact FIDO values).
  - `func makeFidoContext(home: String) -> GateContext`.

- [ ] **Step 1: `GateContext.swift`**

```swift
import Foundation
public struct GateContext {
    public let profile: GateProfile
    public let signer: Signer
    public let verifier: Verifier
    public let enroller: Enroller
    public init(profile: GateProfile, signer: Signer, verifier: Verifier, enroller: Enroller) {
        self.profile = profile; self.signer = signer; self.verifier = verifier; self.enroller = enroller
    }
}
```

- [ ] **Step 2: `FidoProfile.swift` — the exact current values**

```swift
import Foundation
import CCGateCore
public let fidoProfile = GateProfile(
    serviceAccount: "_ccfido", accountRealName: "cc-fido broker",
    namespace: "cc-fido-gate@example.test",
    keydir: "/var/ccfido", runDir: "/var/ccfido-run", sock: "/var/ccfido-run/gate.sock",
    daemonLogErr: "/var/ccfido/brokerd.err",
    codeDir: "/opt/cc-fido-gate", policy: "/opt/cc-fido-gate/policy.json",
    binaryName: "cc-fido", displayName: "cc-fido-gate",
    launchdLabel: "com.cc-fido-gate.brokerd",
    plist: "/Library/LaunchDaemons/com.cc-fido-gate.brokerd.plist",
    daemonMatchPattern: "cc-fido daemon",
    claudeCodeDir: "/Library/Application Support/ClaudeCode",
    managedSettings: "/Library/Application Support/ClaudeCode/managed-settings.json")

// FIDO key handle is HOME-relative — composed here, NEVER a literal "~".
public func fidoKeyHandle(home: String) -> String { home + "/.ccfido/gate_sk" }
public let fidoSignKeygen = "/opt/homebrew/opt/openssh/bin/ssh-keygen"   // TODO Task 8 preflight: arch-aware
public let fidoVerifyKeygen = "/usr/bin/ssh-keygen"

public func makeFidoContext(home: String) -> GateContext {
    GateContext(
        profile: fidoProfile,
        signer: FidoSigner(keygen: fidoSignKeygen, handlePath: fidoKeyHandle(home: home), namespace: fidoProfile.namespace),
        verifier: FidoVerifier(keygen: fidoVerifyKeygen, allowedSigners: fidoProfile.allowedSigners,
                               principal: "gate-principal", namespace: fidoProfile.namespace, keydir: fidoProfile.keydir),
        enroller: FidoEnroller())   // FidoEnroller created in Task 6
}
```

- [ ] **Step 3: Verify build**

Run: `swift build`
Expected: FAIL only on `FidoEnroller` (created next task) — acceptable; do NOT commit until Task 6 restores green. If executing strictly green, temporarily stub `FidoEnroller` returning empty plans, then flesh out in Task 6.

- [ ] **Step 4: Commit (after Task 6 restores green — or stub-then-commit)**

```bash
git add Sources/CCGateCore/GateContext.swift Sources/CCFidoBackend/FidoProfile.swift Sources/cc-fido/main.swift
git commit -m "feat: GateContext + fidoProfile composition"
```

---

### Task 6: `FidoEnroller` + move FIDO enroll/probe/cleanup out of core into the backend

**Files:**
- Create: `Sources/CCFidoBackend/FidoEnroller.swift`
- Modify: `Sources/CCGateCore/Enroll.swift` (`enrollPlan`, `runEnroll` — remove FIDO argv; keep orchestration that takes an `Enroller`)
- Modify: `Sources/CCGateCore/Status.swift:59` (replace inline `~/.ccfido/gate_sk` check with `enroller.isEnrolled(home:)`)
- Modify: `Sources/CCGateCore/Install.swift:104-105` (replace `gate_sk*` deletion with `enroller.removeKeyMaterial(home:)`)

**Interfaces:**
- Consumes: `Enroller`, `GateContext`, `negativeBlinkTest`.
- Produces: `struct FidoEnroller: Enroller`.

- [ ] **Step 1: Write the failing test for `FidoEnroller.enrollPlan`**

`Tests/CCFidoBackendTests/FidoEnrollerTests.swift`:
```swift
import XCTest
@testable import CCFidoBackend
final class FidoEnrollerTests: XCTestCase {
    func testEnrollPlanContainsSkKeygenAndAllowedSignersAppend() {
        let plan = FidoEnroller().enrollPlan(home: "/tmp/h", index: 1)
        // ssh-keygen -t ed25519-sk step present
        XCTAssertTrue(plan.contains { $0.contains("ed25519-sk") })
        // allowed_signers append uses the literal gate-principal
        XCTAssertTrue(plan.contains { $0.joined(separator: " ").contains("gate-principal") })
    }
    func testIsEnrolledChecksKeyFile() {
        XCTAssertFalse(FidoEnroller().isEnrolled(home: "/nonexistent-xyz"))
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `swift test --filter CCFidoBackendTests.FidoEnrollerTests`
Expected: FAIL — `FidoEnroller` not defined.

- [ ] **Step 3: Implement `FidoEnroller`**

Move the FIDO-specific enroll argv from `Enroll.swift` (`enrollPlan`, `Enroll.swift:8-9,24,26,34,39-43`) into `FidoEnroller`, injecting `home`/`allowedSigners`/`namespace`. Implement:
```swift
import Foundation
import CCGateCore
public struct FidoEnroller: Enroller {
    public init() {}
    public func enrollPlan(home: String, index: Int) -> [[String]] {
        let dir = home + "/.ccfido"; let key = "\(dir)/gate_sk\(index)"
        return [
            ["/bin/mkdir", "-p", dir],
            ["/usr/bin/ssh-keygen", "-t", "ed25519-sk", "-C", "cc-fido-key\(index)", "-N", "", "-f", key],
            ["/bin/chmod", "600", key],
            // allowed_signers append with the literal principal (must match FidoVerifier's -I)
            ["/bin/sh", "-c", "printf 'gate-principal %s\\n' \"$1\" >> \(fidoProfile.allowedSigners)", "sh", "PUBKEY_PLACEHOLDER"],
        ]
    }
    public func isEnrolled(home: String) -> Bool {
        FileManager.default.fileExists(atPath: home + "/.ccfido/gate_sk")
    }
    public func removeKeyMaterial(home: String) {
        for f in ["gate_sk", "gate_sk.pub", "gate_sk1", "gate_sk1.pub", "gate_sk2", "gate_sk2.pub"] {
            try? FileManager.default.removeItem(atPath: "\(home)/.ccfido/\(f)")
        }
    }
}
```
(Note: the pubkey read + blink-test orchestration stays in `runEnroll` in core, which now takes an `Enroller`; the exact runtime pubkey substitution keeps the current positional-`$1` form — do not interpolate the pubkey into the shell string.)

Then update `Status.swift:59` → `let keyEnrolled = ctx.enroller.isEnrolled(home: home)` and `Install.swift:104-105` → `ctx.enroller.removeKeyMaterial(home: home)`.

- [ ] **Step 4: Run tests green**

Run: `swift test --filter CCFidoBackendTests.FidoEnrollerTests && swift build`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(backend): FidoEnroller (enroll plan + isEnrolled + removeKeyMaterial); core uses the seam"
```

---

### Task 7: Thread `GateProfile`/`GateContext` through Broker, Client, Install, Status, Enroll, Platform; delete `Paths`

**Files:**
- Modify: `Sources/CCGateCore/Broker.swift` (init takes `GateProfile`; `normPath`/`isControlPath`/`isEnrolledTarget`/`uchgWrite`/verify call sites read the profile + injected `Verifier`)
- Modify: `Sources/CCGateCore/Client.swift` (`confirmAndSign` takes `Signer` + `displayName`; uses `signer.makeCanceller()`)
- Modify: `Sources/CCGateCore/Install.swift`, `Status.swift`, `Enroll.swift`, `Platform.swift`, `CLIHelpers.swift`, `Custody.swift`, `HookLogic.swift`
- Delete: `Sources/CCGateCore/Paths.swift`
- Modify: `Sources/cc-fido/main.swift` (pass `ctx` into every entry point)

**Interfaces:**
- Consumes: `GateContext`, `GateProfile`, `Signer`, `Verifier`.
- Produces: `Broker.init(profile: GateProfile, verifier: Verifier)`; `confirmAndSign(_:challenge:signer:displayName:)`; `runWrite`/`runApprove`/`hookMain` taking `GateContext`.

- [ ] **Step 1: Delete `Paths` and let the compiler enumerate**

```bash
git rm Sources/CCGateCore/Paths.swift
swift build 2>&1 | grep -c "cannot find 'Paths'"   # the exhaustive worklist
```
Expected: a nonzero count — each is a site to rewrite in Steps 2-4.

- [ ] **Step 2: Broker — profile + injected verifier; firmlink set stays constant**

`Broker.swift`: add `let profile: GateProfile; let verifier: Verifier` and `init(profile:verifier:)`. Make `normPath`/`isControlPath`/`isEnrolledTarget` **instance** methods (or pass the profile) reading `profile.controlDenylist`, `profile.keydir`, `profile.codeDir`. **Keep the `["/var","/etc","/tmp"]` firmlink loop verbatim** (`Broker.swift:23`). Replace `getpwnam("_ccfido")` (`Broker.swift:54`) with `getpwnam(profile.serviceAccount)`. Replace the verify calls (`Broker.swift:131-132,165-166`) with `verifier.verify(challenge:signature:)`. Genericize the error strings at `:55`/`:73` and comments at `:49,:50,:230` to drop `_ccfido`.

- [ ] **Step 3: Client — inject the Signer + use `makeCanceller()`**

`confirmAndSign` signature becomes:
```swift
func confirmAndSign(_ humanRendering: String, challenge: Data, signer: Signer, displayName: String) -> Data? {
    // ... osascript dialog: substitute the title with displayName (was literal "cc-fido-gate", Client.swift:14) ...
    let canceller = signer.makeCanceller()               // was `SignCanceller()` at Client.swift:21
    // signer thread: try signer.sign(challenge: challenge, canceller: canceller)   // was free `sign(...)`
    // dialog/backstop call canceller.cancel() unchanged
}
```
`runWrite`/`runApprove` take the `GateContext` and pass `ctx.signer` + `ctx.profile.displayName` into `confirmAndSign`, and `ctx.profile.sock` for the socket. Remove the `Paths.*` default args.

- [ ] **Step 4: Install/Status/Enroll/Platform/CLIHelpers/Custody/HookLogic — thread the profile**

Rewrite every remaining `Paths.*` reference to `profile.*` / `ctx.profile.*`. Specifically:
- `Install.swift:14` `serviceAccountExists/create "_ccfido"` → `profile.serviceAccount`; `:16` hookCmd `Paths.code + "/cc-fido hook"` → `profile.codeDir + "/" + profile.binaryName + " hook"`.
- `Platform.swift:71` `RealName "cc-fido broker"` → `profile.accountRealName`; `:101` `pkill -f "cc-fido daemon"` → `profile.daemonMatchPattern`.
- `CLIHelpers.swift:9-14` `renderPlist`/`renderManagedSettings` take the profile; substitute `launchdLabel`, `serviceAccount`, `daemonLogErr`, hookCmd.
- `Custody.swift:5,9` `chown "_ccfido"` → `profile.serviceAccount`.
- `Status.swift:50` `_ccfido` existence → `profile.serviceAccount`.
- `HookLogic.swift:3` nudge `cc-fido write` → `"\(profile.binaryName) write"`; drop the "FIDO-locked" wording → generic "gate-locked".

- [ ] **Step 5: Update `main.swift` to compose + inject**

Build `let ctx = makeFidoContext(home: realLoginHome())` once and pass into `hookMain(ctx:)`, `runWrite(ctx:path:content:)`, `runApprove(ctx:...)`, `Broker(profile: ctx.profile, verifier: ctx.verifier).serve()`.

- [ ] **Step 6: Verify build + full suite green (existing tests take call-site updates only)**

Run: `swift build && swift test`
Expected: PASS. Expected *values* unchanged; only signatures/imports updated in `BrokerAllowlistTests`, `BrokerLogicTests`, `InstallTests`, `PlatformTests`, `StatusTests`, `CLIHelperTests`, `HookTests`.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "refactor: thread GateProfile/GateContext through core; delete Paths"
```

---

### Task 8: Backend regression guards — `isControlPath` outcomes + one-sided-anchored roundtrip

**Files:**
- Create: `Tests/CCFidoBackendTests/FidoBarrierTests.swift`
- Move: the roundtrip cases from old `CryptoTests.swift` into `CCFidoBackendTests` (retire `CryptoTests` from the core test target)

**Interfaces:**
- Consumes: `fidoProfile`, `Broker.isControlPath`, `FidoSigner`, `FidoVerifier`.

- [ ] **Step 1: Write the `isControlPath` outcome guard (behavior, not array equality)**

```swift
import XCTest
@testable import CCGateCore
@testable import CCFidoBackend
final class FidoBarrierTests: XCTestCase {
    let b = Broker(profile: fidoProfile, verifier: FidoVerifier(keygen: "/usr/bin/ssh-keygen",
        allowedSigners: fidoProfile.allowedSigners, principal: "gate-principal",
        namespace: fidoProfile.namespace, keydir: fidoProfile.keydir))
    func testControlPathOutcomesMatchHardcodedFidoBarrier() {
        for p in ["/var/ccfido/allowed_signers", "/var/ccfido-run/gate.sock", "/var/ccfido/audit.log",
                  "/opt/cc-fido-gate/policy.json", "/opt/cc-fido-gate/cc-fido",
                  "/private/var/ccfido/allowed_signers", "/private/var/ccfido-run/gate.sock"] {
            XCTAssertTrue(b.isControlPath(p), "\(p) must be control")
        }
        XCTAssertFalse(b.isControlPath("/Users/x/project/.env"), "enrolled-style target must NOT be control")
    }
}
```
(Anchor on the hardcoded literal strings above — do NOT build expected values from `fidoProfile`.)

- [ ] **Step 2: Write the one-sided-anchored sign→verify roundtrip (port of CryptoTests)**

```swift
func testVerifierUsesSignPrincipal_oneSidedAnchor() throws {
    // temp topology; software ed25519 key; injected /usr/bin/ssh-keygen (no touch → [SW])
    let tmp = NSTemporaryDirectory() + "ccfido-test-\(getpid())"
    try? FileManager.default.createDirectory(atPath: tmp, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(atPath: tmp) }
    // 1. software key
    _ = run("/usr/bin/ssh-keygen", ["-t", "ed25519", "-N", "", "-f", tmp + "/k"])
    let pub = try String(contentsOfFile: tmp + "/k.pub", encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines)
    // 2. allowed_signers anchored on the HARDCODED literal "gate-principal" (mirrors enroll)
    try "gate-principal \(pub)\n".write(toFile: tmp + "/allowed", atomically: true, encoding: .utf8)
    let challenge = Data("hello".utf8)
    let sig = try fidoSign(challenge: challenge, handlePath: tmp + "/k",
                           namespace: fidoProfile.namespace, keygen: "/usr/bin/ssh-keygen", canceller: nil)
    // 3. verifier driven from the PROFILE/constructor principal — must equal the literal for verify to pass
    let good = FidoVerifier(keygen: "/usr/bin/ssh-keygen", allowedSigners: tmp + "/allowed",
                            principal: "gate-principal", namespace: fidoProfile.namespace, keydir: tmp)
    XCTAssertTrue(good.verify(challenge: challenge, signature: sig))
    // a miswire to the service account fails (this is the rename-regression guard)
    let bad = FidoVerifier(keygen: "/usr/bin/ssh-keygen", allowedSigners: tmp + "/allowed",
                           principal: "_ccfido", namespace: fidoProfile.namespace, keydir: tmp)
    XCTAssertFalse(bad.verify(challenge: challenge, signature: sig))
}
```

- [ ] **Step 3: Run green; retire old CryptoTests from core**

Run: `swift test --filter CCFidoBackendTests.FidoBarrierTests`
Expected: PASS. Delete the now-duplicated `Tests/CCGateCoreTests/CryptoTests.swift`.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "test(backend): isControlPath outcome guard + one-sided-anchored roundtrip; retire CryptoTests"
```

---

### Task 9: Core seam tests + grep gate

**Files:**
- Create: `Tests/CCGateCoreTests/GateProfileTests.swift`
- Create: `Tests/CCGateCoreTests/CancellationSeamTests.swift`
- Create: `Tests/CCGateCoreTests/GrepGateTests.swift`

- [ ] **Step 1: Derivation-mechanism + cross-profile isolation (synthetic profiles, no FIDO strings)**

```swift
import XCTest
@testable import CCGateCore
final class GateProfileTests: XCTestCase {
    func mk(_ tag: String) -> GateProfile {
        GateProfile(serviceAccount: "_svc\(tag)", accountRealName: "rn\(tag)", namespace: "ns\(tag)",
            keydir: "/var/k\(tag)", runDir: "/var/r\(tag)", sock: "/var/r\(tag)/g.sock",
            daemonLogErr: "/var/k\(tag)/e.err", codeDir: "/opt/c\(tag)", policy: "/opt/c\(tag)/p.json",
            binaryName: "bin\(tag)", displayName: "d\(tag)", launchdLabel: "lbl\(tag)",
            plist: "/L/lbl\(tag).plist", daemonMatchPattern: "bin\(tag) daemon",
            claudeCodeDir: "/CC", managedSettings: "/CC/m.json")
    }
    func testControlDenylistDerivesFromRoots() {
        let p = mk("A")
        XCTAssertEqual(p.controlDenylist, ["/var/kA/allowed_signers", "/var/kA/audit.log",
            "/var/kA/custody.json", "/var/kA/ceremony.lock", "/var/rA/g.sock", "/opt/cA/p.json"])
    }
    func testTwoProfilesDoNotLeakAcrossEachOther() {
        let a = mk("A"), b = mk("B")
        XCTAssertNotEqual(a.serviceAccount, b.serviceAccount)
        XCTAssertTrue(Set(a.controlDenylist).isDisjoint(with: Set(b.controlDenylist)))
        XCTAssertNotEqual(a.daemonMatchPattern, b.daemonMatchPattern)
    }
}
```

- [ ] **Step 2: Cancellation-seam test — BELOW confirmAndSign, no osascript**

```swift
import XCTest
@testable import CCGateCore
final class CancellationSeamTests: XCTestCase {
    final class FakeCanceller: CeremonyCanceller {
        let sem = DispatchSemaphore(value: 0)
        func cancel() { sem.signal() }
    }
    struct FakeSigner: Signer {
        let c = FakeCanceller()
        func makeCanceller() -> CeremonyCanceller { c }
        func sign(challenge: Data, canceller: CeremonyCanceller) throws -> Data {
            // block until THIS handle is cancelled
            (canceller as! FakeCanceller).sem.wait()
            throw SignError.failed("cancelled")
        }
    }
    func testCancelHandleAbortsBlockedSignPromptly() {
        let signer = FakeSigner()
        let handle = signer.makeCanceller()
        let started = expectation(description: "sign returned")
        DispatchQueue.global().async {
            _ = try? signer.sign(challenge: Data(), canceller: handle)
            started.fulfill()
        }
        handle.cancel()
        wait(for: [started], timeout: 2.0)   // promptly, not the 90s backstop
    }
}
```

- [ ] **Step 3: Grep gate**

> **As shipped:** the enumeration excludes `Enroll.swift` (`.filter { $0.lastPathComponent != "Enroll.swift" }`), per the Global Constraints exception above — see that file's own FIDO enroll-ceremony literals, deferred to SP2. The code block below is the original plan text; it predates that carve-out.

```swift
import XCTest
final class GrepGateTests: XCTestCase {
    func testCoreCarriesNoFidoIdentity() throws {
        let root = URL(fileURLWithPath: #filePath)  // .../Tests/CCGateCoreTests/GrepGateTests.swift
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Sources/CCGateCore")
        let tokens = ["_ccfido", ".ccfido", "gate_sk", "gate-principal", "cc-fido",
                      "ccfido", "/var/ccfido", "cc-fido-gate@", "com.cc-fido-gate", "brokerd"]
        let fm = FileManager.default
        let files = fm.enumerator(at: root, includingPropertiesForKeys: nil)!
            .compactMap { $0 as? URL }.filter { $0.pathExtension == "swift" }
        var hits: [String] = []
        for f in files {
            let txt = try String(contentsOf: f, encoding: .utf8)
            for t in tokens where txt.contains(t) { hits.append("\(f.lastPathComponent): \(t)") }
        }
        XCTAssertTrue(hits.isEmpty, "CCGateCore carries FIDO identity: \(hits)")
    }
}
```

- [ ] **Step 4: Run all + build green**

Run: `swift build && swift test`
Expected: PASS including the grep gate (if it fails, fix the remaining literal in `CCGateCore`, don't weaken the test).

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "test(core): GateProfile derivation + cancellation seam + grep gate"
```

---

### Task 10: Marketplace restructure + install skill (bootstrap, rename, doc fixes)

**Files:**
- Create: `.claude-plugin/marketplace.json`
- Create: `plugins/cc-fido/.claude-plugin/plugin.json`
- Move: `.claude/skills/cc-fido-install/SKILL.md` → `plugins/cc-fido/skills/install/SKILL.md`; **delete** `.claude/skills/cc-fido-install/`
- Move: `install/policy.json`, `install/POLICY.md` → `plugins/cc-fido/install/`
- Modify: `README.md` (install section → `/cc-fido:install`); `CLAUDE.md` (remove dead `task7_install/enroll/teardown` pointers — only `task7_accept.sh` survives)

- [ ] **Step 1: `marketplace.json`**

```json
{ "name": "cc-presence-gate", "owner": { "name": "Sean Perkins" },
  "plugins": [ { "name": "cc-fido", "source": "./plugins/cc-fido" } ] }
```

- [ ] **Step 2: `plugin.json`**

```json
{ "name": "cc-fido", "description": "Require a physical FIDO security-key touch before high-risk Claude Code tool calls.", "version": "0.1.0" }
```

- [ ] **Step 3: Move + rename the skill, add the Step-0 bootstrap, delete the old dir**

```bash
mkdir -p plugins/cc-fido/skills/install plugins/cc-fido/install
git mv .claude/skills/cc-fido-install/SKILL.md plugins/cc-fido/skills/install/SKILL.md
git mv install/policy.json plugins/cc-fido/install/policy.json
git mv install/POLICY.md plugins/cc-fido/install/POLICY.md
git rm -r .claude/skills/cc-fido-install 2>/dev/null || rmdir .claude/skills/cc-fido-install
```
Edit `plugins/cc-fido/skills/install/SKILL.md`: prepend a **Step 0** — preflight (probe `xcode-select -p` for `swift`; probe Homebrew OpenSSH at the arch-correct prefix: ARM `/opt/homebrew/opt/openssh`, Intel `/usr/local/opt/openssh`) then `swift build -c release` from the repo root located via `${CLAUDE_PLUGIN_ROOT}` (per Task 1's spike finding). Update the `--policy` path to `plugins/cc-fido/install/policy.json`.

- [ ] **Step 4: Fix docs**

Update `README.md` install steps to reference `/cc-fido:install`. In `CLAUDE.md`, delete the `scripts/userrun/task7_install.sh`/`task7_enroll.sh`/`task7_teardown.sh` references (they no longer exist; only `task7_accept.sh` does).

- [ ] **Step 5: Validate + build**

Run: `swift build && swift test` (unchanged) and, if available, `claude plugin validate .`
Expected: build/tests PASS; plugin validates.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat(packaging): cc-presence-gate marketplace + cc-fido plugin (/cc-fido:install, Step-0 bootstrap)"
```

---

### Task 11: [USER-RUN] hardware acceptance — human runs, pastes output

**Files:**
- Modify: `scripts/userrun/task7_accept.sh` (add a cancellation case) — or a new `scripts/userrun/task7_cancel.sh`

**This task CANNOT be run by Claude** (needs sudo + a physical key touch). It is authored here; the human runs it un-sandboxed and pastes output back.

- [ ] **Step 1: Add the cancellation acceptance case**

In `scripts/userrun/task7_cancel.sh`: install+enroll+activate (or assume active), trigger a gated write, and instruct the operator to **click Cancel** (and, in a second run, let the dialog hit the 60s give-up) while signing is armed. Assert the command **exits promptly (< 5s for Cancel), denies, performs no write, and required no touch**. Compare the target file's mtime/content before/after to prove no write.

- [ ] **Step 2: [USER-RUN] APPROVE+TOUCH path**

Human runs `sudo scripts/userrun/task7_accept.sh` on hardware; confirms the gate fires and a real touch approves a gated write.

- [ ] **Step 3: [USER-RUN] Cancel + give-up path**

Human runs `scripts/userrun/task7_cancel.sh`; confirms prompt denial with no touch and no write, for both explicit Cancel and 60s give-up.

- [ ] **Step 4: Commit (after human confirms both paths pass)**

```bash
git add scripts/userrun/task7_cancel.sh
git commit -m "test(userrun): cancellation acceptance (Cancel + give-up → prompt deny, no write, no touch)"
```

---

## Self-Review

**Spec coverage:** module topology → Tasks 2,5; four seams → Task 3; `GateProfile` field table + derived control paths → Tasks 3,9; crypto→backend + `scrubEnv`-stays → Task 4; `GateContext` composition + free-function threading → Tasks 5,7; `Enroller.isEnrolled`/`removeKeyMaterial` → Task 6; delete `Paths` + literal sweep + `Platform` threading → Task 7; grep gate → Task 9; `isControlPath` outcome guard + one-sided-anchored roundtrip → Task 8; cancellation seam test (below `confirmAndSign`) → Task 9; non-optional canceller → Task 3; marketplace + `/cc-fido:install` + Step-0 bootstrap + preflight + doc fixes + delete old skill → Task 10; marketplace-clone spike → Task 1; USER-RUN APPROVE + new Cancel/give-up case → Task 11; mutual-exclusion → correctly **absent** (descoped to SP2). All covered.

**Type consistency:** `GateProfile` fields, `Signer.makeCanceller()`/`sign(challenge:canceller:)` (non-optional), `Verifier.verify(challenge:signature:)`, `Enroller.enrollPlan/isEnrolled/removeKeyMaterial`, `GateContext(profile:signer:verifier:enroller:)`, `fidoProfile`, `makeFidoContext(home:)` — used consistently across Tasks 3–9.

**Note on strict-green execution:** Tasks 4-6 have a brief interdependency (`FidoEnroller` referenced in Task 5's `makeFidoContext` before Task 6 creates it). If executing strictly green per commit, stub `FidoEnroller` with empty plans at the end of Task 4 and flesh it out in Task 6; otherwise commit Tasks 5+6 together.
