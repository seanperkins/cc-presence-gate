# Guided Install Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the install→enroll→install circularity and the `task7_*.sh` test scripts with idempotent `cc-fido install/enroll/activate/status/uninstall` subcommands behind a `Platform` seam, plus a Claude-guided `/cc-fido:install` skill.

**Architecture:** OS-specific privileged primitives (dscl account, launchd, managed-settings, chflags-immutable) sit behind a `Platform` protocol with a `MacOSPlatform` impl (root-context) and a `MockPlatform` for tests. Orchestration functions in `CCFidoCore` (install/enroll/activate/uninstall/status) delegate to `Platform` and are unit-tested against the mock. `main.swift` adds thin dispatch cases. The privileged subcommands run as root in one process (`sudo cc-fido install|activate|uninstall`); `status`/`enroll` run as the login user (enroll does one escalated `allowed_signers` write). A skill sequences them, reading `cc-fido status --json`.

**Tech Stack:** Swift (SwiftPM), Foundation `Process`/`JSONEncoder`, macOS `dscl`/`launchctl`/`codesign`/`chflags`, POSIX sockets (reuse `connectSock`).

**Spec:** `docs/superpowers/specs/2026-07-17-guided-install-design.md`

## Global Constraints

- **Privileged subcommands run as one root process.** `install`/`activate`/`uninstall` assume EUID 0 (invoked via `sudo cc-fido …`); they must refuse with a clear message if not root (`getuid() != 0`). `status`/`enroll` run as the login user. Claude never types a password — the skill hands the user the `sudo cc-fido …` line.
- **Idempotent + fail-closed:** every subcommand is safely re-runnable; `activate` refuses if no key is enrolled; a failed privileged step exits non-zero with a specific stderr message and does not leave a half-broken policy (reuse the existing render→candidate→mv discipline).
- **`Platform` isolates ALL OS-specific install ops** — no `dscl`/`launchctl`/`chflags`/managed-settings path appears outside `MacOSPlatform`. macOS-only (`#if os(macOS)`); a `LinuxPlatform` is a future spec.
- The installed policy stays root-owned 0644; `/var/ccfido` is `_ccfido` 0700; `/var/ccfido-run` is `_ccfido` 0755 (traversable — clients need it).
- Reuse existing helpers verbatim where they exist: `renderPolicy`/`Policy.fromDict` (policy), `renderPlist`/`renderManagedSettings`/`ccVersion` (`CLIHelpers.swift`), `connectSock` (`Client.swift`), `CustodyRegistry`/`Broker.loadRegistry` (enrolled targets).
- No new third-party dependencies. Full `swift test` green before every commit. Conventional commits.
- The launchd label is `com.cc-fido-gate.brokerd`; the plist lives at `/Library/LaunchDaemons/com.cc-fido-gate.brokerd.plist`; managed-settings at `/Library/Application Support/ClaudeCode/managed-settings.json`.

---

### Task 1: `Platform` seam + path constants

**Files:**
- Create: `Sources/CCFidoCore/Platform.swift`
- Modify: `Sources/CCFidoCore/Paths.swift`
- Test: `Tests/CCFidoCoreTests/PlatformTests.swift`

**Interfaces:**
- Produces:
  - `public protocol Platform { … }` (methods below)
  - `public struct MacOSPlatform: Platform` (real impl, root-context)
  - `Paths.plist`, `Paths.managedSettings`, `Paths.claudeCodeDir`, `Paths.ccVersionFile`, `Paths.launchdLabel`, `Paths.optDir` constants
  - In the test target: `final class MockPlatform: Platform` recording calls
- Consumes: nothing.

- [ ] **Step 1: Add path constants to `Paths.swift`**

Append inside `enum Paths` (`Paths.code` already exists = `/opt/cc-fido-gate`; do NOT re-add it):
```swift
    public static let launchdLabel = "com.cc-fido-gate.brokerd"
    public static let plist = "/Library/LaunchDaemons/com.cc-fido-gate.brokerd.plist"
    public static let claudeCodeDir = "/Library/Application Support/ClaudeCode"
    public static let managedSettings = "/Library/Application Support/ClaudeCode/managed-settings.json"
```

- [ ] **Step 2: Write the failing `MockPlatform` protocol-conformance test**

`Tests/CCFidoCoreTests/PlatformTests.swift`:
```swift
import XCTest
@testable import CCFidoCore

// A Platform double that records the OS ops the orchestration requests, so install/activate/uninstall
// logic can be unit-tested without touching the real system.
final class MockPlatform: Platform {
    var calls: [String] = []
    var accountExists = false
    var daemon: (loaded: Bool, running: Bool, pid: Int?) = (false, false, nil)
    func createServiceAccount(name: String) throws { calls.append("createAccount(\(name))"); accountExists = true }
    func deleteServiceAccount(name: String) throws { calls.append("deleteAccount(\(name))"); accountExists = false }
    func serviceAccountExists(name: String) -> Bool { accountExists }
    func installDaemonPlist(_ xml: String) throws { calls.append("installPlist") }
    func activateDaemon() throws { calls.append("activateDaemon"); daemon = (true, true, 1234) }
    func bootoutDaemon() throws { calls.append("bootoutDaemon"); daemon = (false, false, nil) }
    func daemonState() -> (loaded: Bool, running: Bool, pid: Int?) { daemon }
    func writeManagedSettings(_ json: String) throws { calls.append("writeManaged") }
    func removeManagedSettings() throws { calls.append("removeManaged") }
    func makeImmutable(_ path: String) throws { calls.append("uchg(\(path))") }
    func clearImmutable(_ path: String) throws { calls.append("nouchg(\(path))") }
}

final class PlatformTests: XCTestCase {
    func testMockRecordsAccountLifecycle() throws {
        let p = MockPlatform()
        XCTAssertFalse(p.serviceAccountExists(name: "_ccfido"))
        try p.createServiceAccount(name: "_ccfido")
        XCTAssertTrue(p.serviceAccountExists(name: "_ccfido"))
        XCTAssertEqual(p.calls, ["createAccount(_ccfido)"])
    }
}
```

- [ ] **Step 3: Run to verify failure**

Run: `swift test --filter PlatformTests 2>&1 | tail -20`
Expected: FAIL — `Platform` protocol undefined.

- [ ] **Step 4: Implement `Platform.swift`**

```swift
import Foundation
import Darwin

/// OS-specific install-time privileged primitives. macOS impl below; a LinuxPlatform is a future spec.
/// The mutating methods assume the process is root (install/activate/uninstall run via `sudo cc-fido …`).
public protocol Platform {
    func serviceAccountExists(name: String) -> Bool
    func createServiceAccount(name: String) throws       // dscl  (Linux: useradd)
    func deleteServiceAccount(name: String) throws
    func installDaemonPlist(_ xml: String) throws         // write the LaunchDaemon plist
    func activateDaemon() throws                          // bootout||true → bootstrap → kickstart -k
    func bootoutDaemon() throws
    func daemonState() -> (loaded: Bool, running: Bool, pid: Int?)
    func writeManagedSettings(_ json: String) throws
    func removeManagedSettings() throws
    func makeImmutable(_ path: String) throws             // chflags uchg (Linux: chattr +i)
    func clearImmutable(_ path: String) throws
}

public enum PlatformError: Error { case failed(String) }

#if os(macOS)
/// Runs a command to completion, returns (exit, stdout, stderr). Direct (no sudo) — the caller is root.
@discardableResult
func run(_ path: String, _ args: [String]) -> (Int32, String, String) {
    let p = Process(); p.executableURL = URL(fileURLWithPath: path); p.arguments = args
    p.environment = scrubbedEnv()
    let o = Pipe(), e = Pipe(); p.standardOutput = o; p.standardError = e
    do { try p.run() } catch { return (-1, "", "\(error)") }
    let out = String(data: o.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
    let err = String(data: e.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
    p.waitUntilExit()
    return (p.terminationStatus, out, err)
}

public struct MacOSPlatform: Platform {
    public init() {}
    public func serviceAccountExists(name: String) -> Bool {
        run("/usr/bin/dscl", [".", "-read", "/Users/\(name)"]).0 == 0
    }
    public func createServiceAccount(name: String) throws {
        if serviceAccountExists(name: name) { return }               // idempotent
        // Pick a free uid in the 200-400 service range (mirrors account-setup.sh).
        let list = run("/usr/bin/dscl", [".", "-list", "/Users", "UniqueID"]).1
        let used = list.split(separator: "\n").compactMap { Int($0.split(whereSeparator: { $0 == " " }).last ?? "") }
        let uid = (used.filter { $0 >= 200 && $0 < 400 }.max() ?? 299) + 1
        for arg in [["-create", "/Users/\(name)"],
                    ["-create", "/Users/\(name)", "UserShell", "/usr/bin/false"],
                    ["-create", "/Users/\(name)", "RealName", "cc-fido broker"],
                    ["-create", "/Users/\(name)", "UniqueID", String(uid)],
                    ["-create", "/Users/\(name)", "PrimaryGroupID", "20"],
                    ["-create", "/Users/\(name)", "NFSHomeDirectory", "/var/empty"],
                    ["-create", "/Users/\(name)", "IsHidden", "1"]] {
            let r = run("/usr/bin/dscl", ["."] + arg)
            if r.0 != 0 { throw PlatformError.failed("dscl \(arg): \(r.2)") }
        }
    }
    public func deleteServiceAccount(name: String) throws {
        _ = run("/usr/bin/dscl", [".", "-delete", "/Users/\(name)"])   // idempotent; ignore "not found"
    }
    public func installDaemonPlist(_ xml: String) throws {
        try xml.write(toFile: Paths.plist, atomically: true, encoding: .utf8)
        _ = run("/usr/sbin/chown", ["root:wheel", Paths.plist]); _ = run("/bin/chmod", ["644", Paths.plist])
    }
    public func activateDaemon() throws {
        _ = run("/bin/launchctl", ["bootout", "system", Paths.plist])                 // ||true — may not be loaded
        let b = run("/bin/launchctl", ["bootstrap", "system", Paths.plist])
        if b.0 != 0 { throw PlatformError.failed("bootstrap: \(b.2)") }
        _ = run("/bin/launchctl", ["kickstart", "-k", "system/\(Paths.launchdLabel)"]) // fresh socket
    }
    public func bootoutDaemon() throws {
        _ = run("/bin/launchctl", ["bootout", "system", Paths.plist])
        _ = run("/usr/bin/pkill", ["-f", "cc-fido daemon"])
    }
    public func daemonState() -> (loaded: Bool, running: Bool, pid: Int?) {
        // Socket-reachability is the authoritative "running" signal and works as any uid (0666 socket).
        let reachable = { () -> Bool in let fd = connectSock(Paths.sock); if fd >= 0 { close(fd); return true }; return false }()
        let loaded = FileManager.default.fileExists(atPath: Paths.plist)
        return (loaded, reachable, nil)
    }
    public func writeManagedSettings(_ json: String) throws {
        try FileManager.default.createDirectory(atPath: Paths.claudeCodeDir, withIntermediateDirectories: true)
        try json.write(toFile: Paths.managedSettings, atomically: true, encoding: .utf8)
        _ = run("/usr/sbin/chown", ["root:wheel", Paths.managedSettings]); _ = run("/bin/chmod", ["644", Paths.managedSettings])
    }
    public func removeManagedSettings() throws { try? FileManager.default.removeItem(atPath: Paths.managedSettings) }
    public func makeImmutable(_ path: String) throws {
        if run("/usr/bin/chflags", ["uchg", path]).0 != 0 { throw PlatformError.failed("chflags uchg \(path)") }
    }
    public func clearImmutable(_ path: String) throws { _ = run("/usr/bin/chflags", ["nouchg", path]) }
}
#endif
```

- [ ] **Step 5: Run to verify pass**

Run: `swift test --filter PlatformTests 2>&1 | tail -6` → PASS. Then `swift test 2>&1 | grep -E "Executed [0-9]+ tests"` → 0 failures.

- [ ] **Step 6: Commit**

```bash
git add Sources/CCFidoCore/Platform.swift Sources/CCFidoCore/Paths.swift Tests/CCFidoCoreTests/PlatformTests.swift
git commit -m "feat(platform): Platform seam (MacOSPlatform + MockPlatform) isolating dscl/launchd/chflags/managed-settings"
```

---

### Task 2: `status` — state report + `--json` + rollup

**Files:**
- Create: `Sources/CCFidoCore/Status.swift`
- Modify: `Sources/cc-fido/main.swift` (dispatch + `usage()`)
- Test: `Tests/CCFidoCoreTests/StatusTests.swift`

**Interfaces:**
- Consumes: `Platform` (Task 1), `Policy.fromFile`, `Paths`.
- Produces:
  - `public struct StatusReport: Codable { … }` with `public var rollup: String`
  - `public func gatherStatus(platform: Platform) -> StatusReport`
  - `status [--json]` subcommand.

- [ ] **Step 1: Write the failing rollup test**

`Tests/CCFidoCoreTests/StatusTests.swift`:
```swift
import XCTest
@testable import CCFidoCore

final class StatusTests: XCTestCase {
    func testRollupClean() {
        let s = StatusReport(account: false, dirs: false, binary: false, policyValid: false,
                             keyEnrolled: false, daemonRunning: false, managedSettings: false)
        XCTAssertEqual(s.rollup, "clean")
    }
    func testRollupPrereqsOnly() {
        let s = StatusReport(account: true, dirs: true, binary: true, policyValid: true,
                             keyEnrolled: false, daemonRunning: false, managedSettings: true)
        XCTAssertEqual(s.rollup, "prereqs-only")
    }
    func testRollupEnrolled() {
        let s = StatusReport(account: true, dirs: true, binary: true, policyValid: true,
                             keyEnrolled: true, daemonRunning: false, managedSettings: true)
        XCTAssertEqual(s.rollup, "enrolled")
    }
    func testRollupActive() {
        let s = StatusReport(account: true, dirs: true, binary: true, policyValid: true,
                             keyEnrolled: true, daemonRunning: true, managedSettings: true)
        XCTAssertEqual(s.rollup, "active")
    }
    func testRollupDegraded() {   // daemon running but a prereq is missing ⇒ degraded
        let s = StatusReport(account: true, dirs: true, binary: true, policyValid: false,
                             keyEnrolled: true, daemonRunning: true, managedSettings: true)
        XCTAssertEqual(s.rollup, "degraded")
    }
    func testJSONEncodes() throws {
        let s = StatusReport(account: true, dirs: true, binary: true, policyValid: true,
                             keyEnrolled: true, daemonRunning: true, managedSettings: true)
        let data = try JSONEncoder().encode(s)
        let obj = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        XCTAssertEqual(obj["rollup"] as? String, "active")
        XCTAssertEqual(obj["daemon_running"] as? Bool, true)
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `swift test --filter StatusTests 2>&1 | tail -15`
Expected: FAIL — `StatusReport` undefined.

- [ ] **Step 3: Implement `Status.swift`**

```swift
import Foundation

public struct StatusReport: Codable {
    public let account, dirs, binary, policyValid, keyEnrolled, daemonRunning, managedSettings: Bool
    public init(account: Bool, dirs: Bool, binary: Bool, policyValid: Bool,
                keyEnrolled: Bool, daemonRunning: Bool, managedSettings: Bool) {
        self.account = account; self.dirs = dirs; self.binary = binary; self.policyValid = policyValid
        self.keyEnrolled = keyEnrolled; self.daemonRunning = daemonRunning; self.managedSettings = managedSettings
    }
    /// Overall lifecycle stage. `degraded` = the daemon is running but a prereq is missing/broken.
    public var rollup: String {
        let prereqs = account && dirs && binary && policyValid
        if daemonRunning && !prereqs { return "degraded" }
        if daemonRunning { return "active" }
        if prereqs && keyEnrolled { return "enrolled" }        // ready to activate
        if prereqs { return "prereqs-only" }
        if !account && !dirs && !binary { return "clean" }
        return "degraded"
    }
    enum CodingKeys: String, CodingKey {
        case account, dirs, binary
        case policyValid = "policy_valid", keyEnrolled = "key_enrolled"
        case daemonRunning = "daemon_running", managedSettings = "managed_settings", rollupKey = "rollup"
    }
    public func encode(to enc: Encoder) throws {
        var c = enc.container(keyedBy: CodingKeys.self)
        try c.encode(account, forKey: .account); try c.encode(dirs, forKey: .dirs); try c.encode(binary, forKey: .binary)
        try c.encode(policyValid, forKey: .policyValid); try c.encode(keyEnrolled, forKey: .keyEnrolled)
        try c.encode(daemonRunning, forKey: .daemonRunning); try c.encode(managedSettings, forKey: .managedSettings)
        try c.encode(rollup, forKey: .rollupKey)
    }
}

public func gatherStatus(platform: Platform) -> StatusReport {
    let fm = FileManager.default
    let account = platform.serviceAccountExists(name: "_ccfido")
    let dirs = fm.fileExists(atPath: Paths.keydir) && fm.fileExists(atPath: Paths.runDir)
    let binary = fm.fileExists(atPath: Paths.code + "/cc-fido")
    let policyValid = (try? Policy.fromFile(Paths.policy)) != nil
    let keyEnrolled = fm.fileExists(atPath: Paths.allowedSigners)
        && ((try? String(contentsOfFile: Paths.allowedSigners, encoding: .utf8))?.isEmpty == false)
    let daemonRunning = platform.daemonState().running
    let managed = fm.fileExists(atPath: Paths.managedSettings)
    return StatusReport(account: account, dirs: dirs, binary: binary, policyValid: policyValid,
                        keyEnrolled: keyEnrolled, daemonRunning: daemonRunning, managedSettings: managed)
}
```
(Note: `Paths.code` = `/opt/cc-fido-gate`; the binary path is `Paths.code + "/cc-fido"`. `Paths.policy` = `/opt/cc-fido-gate/policy.json`.)

- [ ] **Step 4: Add the `status` dispatch case in `main.swift`**

Inside the `switch cmd` (before `default`):
```swift
case "status":
    let report = gatherStatus(platform: MacOSPlatform())
    if args.contains("--json") {
        let data = try JSONEncoder().encode(report)
        print(String(data: data, encoding: .utf8)!)
    } else {
        func mark(_ b: Bool) -> String { b ? "✓" : "·" }
        print("""
        cc-fido status: \(report.rollup)
          \(mark(report.account)) account   \(mark(report.dirs)) dirs   \(mark(report.binary)) binary
          \(mark(report.policyValid)) policy   \(mark(report.keyEnrolled)) key   \(mark(report.daemonRunning)) daemon   \(mark(report.managedSettings)) managed-settings
        """)
    }
    exit(0)
```
Add `status [--json]` to the `usage()` string.

- [ ] **Step 5: Run tests + build**

Run: `swift test --filter StatusTests 2>&1 | tail -6` → PASS; `swift build 2>&1 | tail -3` → Build complete; full `swift test` → 0 failures.

- [ ] **Step 6: Commit**

```bash
git add Sources/CCFidoCore/Status.swift Sources/cc-fido/main.swift Tests/CCFidoCoreTests/StatusTests.swift
git commit -m "feat(cli): status subcommand — component report + rollup + --json contract"
```

---

### Task 3: `install` subcommand (root-context prereqs)

**Files:**
- Create: `Sources/CCFidoCore/Install.swift`
- Modify: `Sources/cc-fido/main.swift`
- Test: `Tests/CCFidoCoreTests/InstallTests.swift`

**Interfaces:**
- Consumes: `Platform`, `renderPolicy`/`Policy.fromDict` (policy), `renderPlist`/`renderManagedSettings`/`ccVersion`, `Paths`.
- Produces: `public func installPrereqs(policySrc: String, home: String, binarySource: String, platform: Platform) throws` + `install [--policy PATH]` subcommand.

- [ ] **Step 1: Write the failing MockPlatform install-order test**

`Tests/CCFidoCoreTests/InstallTests.swift`:
```swift
import XCTest
@testable import CCFidoCore

final class InstallTests: XCTestCase {
    func testInstallRequestsPlatformOpsAndIsIdempotent() throws {
        let p = MockPlatform()
        // installPrereqs must: create account (once), install the plist, write managed-settings.
        try installOrchestration(platform: p)          // pure part under test (see impl note)
        try installOrchestration(platform: p)          // re-run: account already exists ⇒ not re-created
        XCTAssertEqual(p.calls.filter { $0.hasPrefix("createAccount") }.count, 1)
        XCTAssertTrue(p.calls.contains("installPlist"))
        XCTAssertTrue(p.calls.contains("writeManaged"))
        XCTAssertFalse(p.calls.contains("activateDaemon"))   // install never starts the daemon
    }
}
```
Implementation note: split the Platform-driven part into a testable `installOrchestration(platform:)` that does account+plist+managed-settings (no filesystem/policy writes), and keep the filesystem/binary/policy writes (which need root + a real FS) in `installPrereqs`, which calls `installOrchestration`. The unit test exercises `installOrchestration` against the mock; the real FS/policy path is USER-RUN-verified.

- [ ] **Step 2: Run to verify failure**

Run: `swift test --filter InstallTests 2>&1 | tail -15`
Expected: FAIL — `installOrchestration` undefined.

- [ ] **Step 3: Implement `Install.swift`**

```swift
import Foundation

public enum InstallError: Error { case notRoot, failed(String) }

/// Platform-driven prereqs: account + daemon plist + managed-settings. Unit-tested against MockPlatform.
public func installOrchestration(platform: Platform) throws {
    if !platform.serviceAccountExists(name: "_ccfido") { try platform.createServiceAccount(name: "_ccfido") }
    try platform.installDaemonPlist(renderPlist())
    try platform.writeManagedSettings(renderManagedSettings(hookCmd: Paths.code + "/cc-fido hook"))
}

/// Full root-context install: dirs, binary, policy (render+validate+install), then installOrchestration.
/// `binarySource` is the just-built/-run binary to copy into /opt; `policySrc` is the template (or --policy).
public func installPrereqs(policySrc: String, home: String, binarySource: String, platform: Platform) throws {
    guard getuid() == 0 else { throw InstallError.notRoot }
    let fm = FileManager.default
    for d in [Paths.code, Paths.keydir, Paths.runDir] {
        try fm.createDirectory(atPath: d, withIntermediateDirectories: true)
    }
    // binary + codesign
    try? fm.removeItem(atPath: Paths.code + "/cc-fido")
    try fm.copyItem(atPath: binarySource, toPath: Paths.code + "/cc-fido")
    if run("/usr/bin/codesign", ["--force", "--options", "runtime", "--sign", "-", Paths.code + "/cc-fido"]).0 != 0 {
        throw InstallError.failed("codesign")
    }
    // policy: render (substitute+validate+lint) → validate dict → atomic write. Reuses renderPolicy.
    let rendered = try renderPolicy(srcPath: policySrc, home: home)
    guard let obj = try JSONSerialization.jsonObject(with: rendered) as? [String: Any] else { throw InstallError.failed("policy not an object") }
    let policy = try Policy.fromDict(obj)                 // throws on invalid
    let (fatal, _) = policy.lint(); if !fatal.isEmpty { throw InstallError.failed("policy: \(fatal.joined(separator: "; "))") }
    let cand = Paths.policy + ".new"
    try rendered.write(to: URL(fileURLWithPath: cand))
    try fm.moveItem(atPath: cand, toPath: Paths.policy)   // atomic
    // perms
    _ = run("/usr/sbin/chown", ["-R", "root:wheel", Paths.code]); _ = run("/bin/chmod", ["755", Paths.code])
    _ = run("/bin/chmod", ["644", Paths.policy])
    _ = run("/usr/sbin/chown", ["_ccfido", Paths.keydir]); _ = run("/usr/sbin/chown", ["_ccfido", Paths.runDir])
    _ = run("/bin/chmod", ["700", Paths.keydir]); _ = run("/bin/chmod", ["755", Paths.runDir])
    // account + plist + managed-settings
    try installOrchestration(platform: platform)
}
```

- [ ] **Step 4: Add the `install` dispatch case in `main.swift`**

```swift
case "install":
    guard getuid() == 0 else {
        FileHandle.standardError.write(Data("cc-fido install: must run as root — use: sudo cc-fido install\n".utf8)); exit(1)
    }
    let policySrc = args.firstIndex(of: "--policy").map { args[$0 + 1] } ?? (installRepoPolicyDefault())
    let home = realLoginHome()   // login user's home (from SUDO_USER), NOT root's /var/root
    do {
        try installPrereqs(policySrc: policySrc, home: home, binarySource: CommandLine.arguments[0], platform: MacOSPlatform())
        print("cc-fido: prereqs installed. Next: cc-fido enroll  (then: sudo cc-fido activate)")
        exit(0)
    } catch { FileHandle.standardError.write(Data("cc-fido install failed: \(error)\n".utf8)); exit(1) }
```
Add helpers near the top of `main.swift`:
```swift
// Under `sudo`, HOME is root's; the policy's __HOME__ must be the LOGIN user's home. Derive from SUDO_USER.
func realLoginHome() -> String {
    if let u = ProcessInfo.processInfo.environment["SUDO_USER"], let pw = getpwnam(u) { return String(cString: pw.pointee.pw_dir) }
    return NSHomeDirectory()
}
func installRepoPolicyDefault() -> String { Paths.code + "/policy.json.template" }  // see Task 7 note
```
Add `install [--policy PATH]` to `usage()`. **Ambiguity resolved:** the default policy source for a live `cc-fido install` is the template shipped alongside the binary. Task 7 makes `install` also install `install/policy.json` → `/opt/cc-fido-gate/policy.json.template` so a re-run/`--policy`-less install has a source. (During bring-up the caller passes `--policy /path/to/repo/install/policy.json`.)

**Important — `$HOME` under sudo:** `sudo cc-fido install` runs as root, so `$HOME=/var/root`. `realLoginHome()` derives the login user's home from `SUDO_USER` (fail-safe to `NSHomeDirectory()`), and `renderPolicy` still rejects `/var/root`/empty — so a mis-derived home fails closed rather than baking a wrong `allow_tier`.

- [ ] **Step 5: Build + unit test + a real smoke (USER-RUN, noted)**

Run: `swift build 2>&1 | tail -3` → Build complete; `swift test 2>&1 | grep Executed` → 0 failures. (The real `sudo cc-fido install` is USER-RUN, Task 8/skill.)

- [ ] **Step 6: Commit**

```bash
git add Sources/CCFidoCore/Install.swift Sources/cc-fido/main.swift Tests/CCFidoCoreTests/InstallTests.swift
git commit -m "feat(cli): install subcommand — root-context prereqs (dirs/binary/policy/account/plist/managed) + orchestration unit test"
```

---

### Task 4: `enroll` subcommand (user-context keygen + one escalation)

**Files:**
- Create: `Sources/CCFidoCore/Enroll.swift`
- Modify: `Sources/cc-fido/main.swift`
- Test: `Tests/CCFidoCoreTests/EnrollTests.swift`

**Interfaces:**
- Consumes: `runPrivileged` (CLIHelpers), `negativeBlinkTest`, `Paths.signKeygen`, `Paths.handle`.
- Produces: `public func enrollPlan(home: String, keys: Int) -> [[String]]` (the keygen commands, testable) + `enroll [--keys N]` subcommand.

- [ ] **Step 1: Write the failing plan test**

`Tests/CCFidoCoreTests/EnrollTests.swift`:
```swift
import XCTest
@testable import CCFidoCore

final class EnrollTests: XCTestCase {
    func testEnrollPlanGeneratesKeygenPerKey() {
        let plan = enrollPlan(home: "/Users/x", keys: 2)
        XCTAssertEqual(plan.count, 2)
        // each entry is a ssh-keygen -t ed25519-sk invocation writing gate_sk<N>
        XCTAssertTrue(plan[0].contains("ed25519-sk"))
        XCTAssertTrue(plan[0].contains("/Users/x/.ccfido/gate_sk1"))
        XCTAssertTrue(plan[1].contains("/Users/x/.ccfido/gate_sk2"))
    }
}
```

- [ ] **Step 2: Run to verify failure** → `enrollPlan` undefined.

- [ ] **Step 3: Implement `Enroll.swift`** (ports `task7_enroll.sh` exactly)

```swift
import Foundation

public enum EnrollError: Error { case failed(String) }

/// The `ssh-keygen -t ed25519-sk` argv per key (touch required). Pure/testable.
public func enrollPlan(home: String, keys: Int) -> [[String]] {
    (1...max(1, keys)).map { n in
        ["-t", "ed25519-sk", "-O", "application=ssh:cc-fido-gate", "-N", "", "-C", "cc-fido-key\(n)",
         "-f", "\(home)/.ccfido/gate_sk\(n)"]
    }
}

/// Runs as the LOGIN user. Generates key(s) (touch), registers pubkeys in allowed_signers (one escalation),
/// symlinks the handle (private+public), and blink-tests key #1.
public func runEnroll(home: String, keys: Int) throws {
    let dir = "\(home)/.ccfido"
    try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
    _ = run("/bin/chmod", ["700", dir])
    for (i, argv) in enrollPlan(home: home, keys: keys).enumerated() {
        let n = i + 1
        FileHandle.standardError.write(Data(">>> TOUCH to enroll key #\(n) of \(keys) <<<\n".utf8))
        if run(Paths.signKeygen, argv).0 != 0 { throw EnrollError.failed("ssh-keygen key #\(n)") }
        _ = run("/bin/chmod", ["600", "\(dir)/gate_sk\(n)"])
        let pub = (try? String(contentsOfFile: "\(dir)/gate_sk\(n).pub", encoding: .utf8))?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        // one escalation: append to the root-owned allowed_signers
        if !runPrivileged(["/bin/sh", "-c", "printf 'gate-principal %s\\n' '\(pub)' >> \(Paths.allowedSigners)"]) {
            throw EnrollError.failed("register key #\(n)")
        }
    }
    // active handle = key #1 (BOTH private and public — a stale .pub aborts signing)
    _ = run("/bin/ln", ["-sf", "\(dir)/gate_sk1", Paths.handle])
    _ = run("/bin/ln", ["-sf", "\(dir)/gate_sk1.pub", Paths.handle + ".pub"])
    _ = runPrivileged(["/usr/sbin/chown", "_ccfido", Paths.allowedSigners])
    _ = runPrivileged(["/bin/chmod", "600", Paths.allowedSigners])
    if !negativeBlinkTest(handle: "\(dir)/gate_sk1", namespace: Paths.namespace) {
        throw EnrollError.failed("blink-test (touch-required not verified)")
    }
}
```
(`Paths.handle` = `~/.ccfido/gate_sk`. Note `Paths.signKeygen` = the Homebrew ssh-keygen that can sign sk keys.)

- [ ] **Step 4: Add the `enroll` dispatch case in `main.swift`**

```swift
case "enroll":
    if getuid() == 0 { FileHandle.standardError.write(Data("cc-fido enroll: run as your login user (not sudo) — it needs your key + a touch\n".utf8)); exit(1) }
    let keys = args.firstIndex(of: "--keys").flatMap { Int(args[$0 + 1]) } ?? 1
    do { try runEnroll(home: NSHomeDirectory(), keys: keys); print("cc-fido: enrolled. Next: sudo cc-fido activate"); exit(0) }
    catch { FileHandle.standardError.write(Data("cc-fido enroll failed: \(error)\n".utf8)); exit(1) }
```
Add `enroll [--keys N]` to `usage()`.

- [ ] **Step 5: Build + test** → Build complete, 0 failures.

- [ ] **Step 6: Commit**

```bash
git add Sources/CCFidoCore/Enroll.swift Sources/cc-fido/main.swift Tests/CCFidoCoreTests/EnrollTests.swift
git commit -m "feat(cli): enroll subcommand — sk keygen + allowed_signers registration + handle symlinks + blink-test"
```

---

### Task 5: `activate` subcommand

**Files:**
- Modify: `Sources/CCFidoCore/Install.swift`, `Sources/cc-fido/main.swift`
- Test: `Tests/CCFidoCoreTests/InstallTests.swift`

**Interfaces:**
- Produces: `public func activate(platform: Platform) throws` + `activate` subcommand.

- [ ] **Step 1: Write the failing test** (append to `InstallTests.swift`)

```swift
    func testActivateRefusesWithoutKey_thenActivates() throws {
        // activate must refuse if allowed_signers is absent; with a key present, it calls activateDaemon.
        let p = MockPlatform()
        XCTAssertThrowsError(try activate(platform: p, keyEnrolled: false))
        XCTAssertFalse(p.calls.contains("activateDaemon"))
        try activate(platform: p, keyEnrolled: true)
        XCTAssertTrue(p.calls.contains("activateDaemon"))
    }
```

- [ ] **Step 2: Run to verify failure** → `activate` undefined.

- [ ] **Step 3: Implement `activate` in `Install.swift`**

```swift
/// Boots the LaunchDaemon (fresh socket). Refuses if no key is enrolled (the daemon would deny everything).
/// `keyEnrolled` is injected so it's unit-testable; the subcommand passes the real allowed_signers check.
public func activate(platform: Platform, keyEnrolled: Bool) throws {
    guard keyEnrolled else { throw InstallError.failed("no key enrolled — run `cc-fido enroll` first") }
    try platform.activateDaemon()
}
```

- [ ] **Step 4: Add the `activate` dispatch case in `main.swift`**

```swift
case "activate":
    guard getuid() == 0 else { FileHandle.standardError.write(Data("cc-fido activate: must run as root — use: sudo cc-fido activate\n".utf8)); exit(1) }
    let enrolled = (try? String(contentsOfFile: Paths.allowedSigners, encoding: .utf8))?.isEmpty == false
    do {
        try activate(platform: MacOSPlatform(), keyEnrolled: enrolled)
        usleep(1_000_000)
        let running = MacOSPlatform().daemonState().running
        print("cc-fido: daemon activated — socket \(running ? "reachable" : "NOT reachable (re-run activate)")")
        exit(running ? 0 : 1)
    } catch { FileHandle.standardError.write(Data("cc-fido activate failed: \(error)\n".utf8)); exit(1) }
```
Add `activate` to `usage()`.

- [ ] **Step 5: Build + test** → 0 failures.

- [ ] **Step 6: Commit**

```bash
git add Sources/CCFidoCore/Install.swift Sources/cc-fido/main.swift Tests/CCFidoCoreTests/InstallTests.swift
git commit -m "feat(cli): activate subcommand — key-gated daemon bootstrap+kickstart (fresh socket)"
```

---

### Task 6: `uninstall` subcommand

**Files:**
- Modify: `Sources/CCFidoCore/Install.swift`, `Sources/cc-fido/main.swift`
- Test: `Tests/CCFidoCoreTests/InstallTests.swift`

**Interfaces:**
- Produces: `public func uninstall(platform: Platform, enrolledTargets: [String], home: String) throws` + `uninstall` subcommand.

- [ ] **Step 1: Write the failing test** (append to `InstallTests.swift`)

```swift
    func testUninstallUnlocksTargetsThenTearsDown() throws {
        let p = MockPlatform(); p.accountExists = true; p.daemon = (true, true, 9)
        try uninstall(platform: p, enrolledTargets: ["/Users/Shared/x.txt"], home: "/Users/x")
        XCTAssertTrue(p.calls.contains("nouchg(/Users/Shared/x.txt)"))  // unlocked before deletion
        XCTAssertTrue(p.calls.contains("bootoutDaemon"))
        XCTAssertTrue(p.calls.contains("removeManaged"))
        XCTAssertTrue(p.calls.contains("deleteAccount(_ccfido)"))
        // unlock must precede account deletion
        XCTAssertLessThan(p.calls.firstIndex(of: "nouchg(/Users/Shared/x.txt)")!, p.calls.firstIndex(of: "deleteAccount(_ccfido)")!)
    }
```

- [ ] **Step 2: Run to verify failure** → `uninstall` undefined.

- [ ] **Step 3: Implement `uninstall` in `Install.swift`** (ports `task7_teardown.sh`)

```swift
/// Full teardown. Order matters: bootout daemon → remove managed-settings → UNLOCK every enrolled target
/// (before deleting the registry/account, else they're stuck immutable) → rm tree/state → delete account.
public func uninstall(platform: Platform, enrolledTargets: [String], home: String) throws {
    guard getuid() == 0 else { throw InstallError.notRoot }
    try? platform.bootoutDaemon()
    try? platform.removeManagedSettings()
    try? FileManager.default.removeItem(atPath: Paths.plist)
    for t in enrolledTargets where FileManager.default.fileExists(atPath: t) {
        try? platform.clearImmutable(t)                              // nouchg
        _ = run("/usr/sbin/chown", ["-R", loginOwner(home: home), t])
    }
    for d in [Paths.code, Paths.keydir, Paths.runDir] { try? FileManager.default.removeItem(atPath: d) }
    try? platform.deleteServiceAccount(name: "_ccfido")
    // key material (login user's home)
    for f in ["gate_sk", "gate_sk.pub", "gate_sk1", "gate_sk1.pub", "gate_sk2", "gate_sk2.pub"] {
        try? FileManager.default.removeItem(atPath: "\(home)/.ccfido/\(f)")
    }
}
func loginOwner(home: String) -> String {
    let user = (home as NSString).lastPathComponent
    return "\(user):staff"
}
```
The subcommand reads the enrolled targets from the registry before deletion:
```swift
case "uninstall":
    guard getuid() == 0 else { FileHandle.standardError.write(Data("cc-fido uninstall: must run as root — use: sudo cc-fido uninstall\n".utf8)); exit(1) }
    let targets = Broker().loadRegistry()          // reads custody.json while it still exists
    let home = realLoginHome()
    do { try uninstall(platform: MacOSPlatform(), enrolledTargets: targets, home: home)
         let r = gatherStatus(platform: MacOSPlatform())
         print("cc-fido: uninstalled — status now \(r.rollup)"); exit(0) }
    catch { FileHandle.standardError.write(Data("cc-fido uninstall failed: \(error)\n".utf8)); exit(1) }
```
(`Broker().loadRegistry()` returns the enrolled file paths from `custody.json`. If enroll-dir targets need inclusion, extend `loadRegistry` or read `dirs` too — verify against `Custody.swift` during implementation and include both `files` and `dirs`.)
Add `uninstall` to `usage()`.

- [ ] **Step 4: Build + test** → 0 failures.

- [ ] **Step 5: Commit**

```bash
git add Sources/CCFidoCore/Install.swift Sources/cc-fido/main.swift Tests/CCFidoCoreTests/InstallTests.swift
git commit -m "feat(cli): uninstall subcommand — unlock-then-teardown (daemon/managed/tree/account/keys)"
```

---

### Task 7: Retire `task7_*.sh`, ship the policy template alongside the binary, update docs

**Files:**
- Modify: `Sources/CCFidoCore/Install.swift` (install the policy template)
- Delete: `scripts/userrun/task7_install.sh`, `scripts/userrun/task7_enroll.sh`, `scripts/userrun/task7_teardown.sh`
- Modify: `README.md` (install instructions), `docs/FOLLOWUPS.md` (note the retirement)

**Interfaces:** none new.

- [ ] **Step 1: Make `installPrereqs` also stage the policy template**

So a re-run / `--policy`-less install has a default source, add to `installPrereqs` after the policy install:
```swift
    // Ship the (unsubstituted) template next to the binary so re-installs have a default source.
    if FileManager.default.fileExists(atPath: policySrc) {
        try? FileManager.default.removeItem(atPath: Paths.code + "/policy.json.template")
        try? FileManager.default.copyItem(atPath: policySrc, toPath: Paths.code + "/policy.json.template")
    }
```
(This makes `installRepoPolicyDefault()` from Task 3 resolve.)

- [ ] **Step 2: Delete the retired scripts**

```bash
git rm scripts/userrun/task7_install.sh scripts/userrun/task7_enroll.sh scripts/userrun/task7_teardown.sh
```
(Keep `task7_accept.sh` — it's the deep acceptance test, now driven manually or by the skill.)

- [ ] **Step 3: Update `README.md` install section** to the new flow:

Replace any `task7_install`/`enroll`/`teardown` references with:
```markdown
## Install
Guided (recommended): run the `/cc-fido:install` skill and follow the prompts.
Manual:
1. `sudo cc-fido install --policy install/policy.json`   # prereqs + policy
2. `cc-fido enroll`                                        # generate + register your key (touch)
3. `sudo cc-fido activate`                                 # start the daemon
Check state any time: `cc-fido status`. Remove everything: `sudo cc-fido uninstall`.
```

- [ ] **Step 4: Note the retirement in `docs/FOLLOWUPS.md`** (one line under the configurable-policy section): the task7 install/enroll/teardown scripts are replaced by `cc-fido` subcommands; `task7_accept.sh` retained.

- [ ] **Step 5: Build + full test** → 0 failures.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "refactor(install): retire task7 install/enroll/teardown scripts for cc-fido subcommands; ship policy template; docs"
```

---

### Task 8: The `/cc-fido:install` guided skill

**Files:**
- Create: `.claude/skills/cc-fido-install/SKILL.md`

**Interfaces:** consumes `cc-fido status --json` + the subcommands.

- [ ] **Step 1: Write the skill**

`.claude/skills/cc-fido-install/SKILL.md`:
```markdown
---
name: cc-fido-install
description: Guided install/enroll/activate (and repair/uninstall) of cc-fido-gate. Use when the user wants to install, set up, activate, check, repair, or remove cc-fido-gate — it drives the privileged cc-fido subcommands, prompting the user for sudo/touch at each step.
---

# Guided cc-fido-gate install

You orchestrate the `cc-fido` subcommands. You CANNOT type the user's sudo password or touch their key —
you are a guide: tell the user the ONE command to run next, have them run it in their terminal (with the
`! ` prefix, so sudo can prompt and the key can blink), read the output, and advance.

## Always start by reading state
Ask the user to run `cc-fido status --json` (or run it yourself if unprivileged reads suffice) and parse
the `rollup`. Branch:
- `clean` → Step 1 (install)
- `prereqs-only` → Step 2 (enroll)
- `enrolled` → Step 3 (activate)
- `active` → already installed; offer `status`, a smoke test, or `uninstall`
- `degraded` → diagnose which component is false in the JSON and repair (usually re-run install or activate)

## Step 1 — Prereqs (0 touches; one sudo prompt)
Tell the user: `! sudo cc-fido install --policy <path-to-their-policy-or-install/policy.json>`
(If they haven't authored a policy, note the default gates sensitive/home paths; a `/cc-fido:policy`
skill can build one.) Confirm `status` rollup is now `prereqs-only`.

## Step 2 — Enroll a key (touch; runs as the user)
Tell the user: `! cc-fido enroll`  (add `--keys 2` if they want a backup, enrolled one at a time).
Tell them to TOUCH the key when it blinks. If they see `invalid format` swapping two keys, that's the
authenticator not settling — retry with the intended key plugged in. Confirm rollup is now `enrolled`.

## Step 3 — Activate the daemon (one sudo prompt)
Tell the user: `! sudo cc-fido activate`. It prints whether the socket is reachable. If NOT reachable,
have them run it again (it re-kickstarts a fresh socket — the known stale-socket fix). Confirm `active`.

## Verify
`cc-fido status` should read `active`. Optionally have them prove the gate end-to-end via
`scripts/userrun/task7_accept.sh` (needs a touch).

## Repair / Uninstall
- Broker unreachable / stale socket → `! sudo cc-fido activate`.
- Full reset → `! sudo cc-fido uninstall` → confirm `status` = `clean`.

Never run a `sudo` command yourself — always hand it to the user. After each step, re-read `status` before
advancing; every subcommand is idempotent, so resuming after an interruption is safe.
```

- [ ] **Step 2: Sanity-check the frontmatter/format** matches the repo's other skills (compare against an existing `.claude/skills/*/SKILL.md` if present, or the plugin skill format). Fix any format drift.

- [ ] **Step 3: Commit**

```bash
git add .claude/skills/cc-fido-install/SKILL.md
git commit -m "feat(skill): /cc-fido:install — guided install/enroll/activate/repair over the cc-fido subcommands"
```

---

## Notes for the implementer
- `run(...)` (Task 1) is the direct (non-sudo) command runner used by the root-context subcommands; `runPrivileged` (existing, sudo) is used ONLY by `enroll` for its one `allowed_signers` escalation.
- The privileged subcommands can't be unit-tested for real system mutation — unit tests exercise the Platform-driven orchestration against `MockPlatform`; the real end-to-end is USER-RUN (the skill drives it). Do NOT attempt to run `sudo`/`dscl`/`launchctl` in `swift test`.
- Keep every OS-specific string (`dscl`, `launchctl`, `chflags`, managed-settings path) inside `MacOSPlatform` — the reviewer will check the seam holds.
- Verify `Broker().loadRegistry()` returns both file and dir enrolled targets before relying on it in `uninstall` (read `Custody.swift`); include both so dir-custody targets get unlocked.
- Full `swift test` must stay green; the privileged Swift is new surface but the tests are mock-based and fast.
