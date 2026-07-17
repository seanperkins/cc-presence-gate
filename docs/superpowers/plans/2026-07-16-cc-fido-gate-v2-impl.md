# cc-fido-gate v2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the capability-split FIDO gate: a console-session client signs a physical-touch challenge, an unprivileged `_ccfido` daemon verifies it and performs the privileged file write behind a kernel `uchg` lock, plus a best-effort `PreToolUse` hook for the broad advisory set.

**Architecture:** Two equal partners driven by one FIDO key (spec §"What v2 guarantees"). (1) **Hard guarantee** — crown-jewel files owned by `_ccfido` + `uchg`; the agent-uid can't write/delete/rename them; legit changes go through a broker whose ceremony is: client signs a daemon-issued challenge → daemon verifies (no USB) → daemon does `nouchg → write → fsync → uchg`, **but only for a path in the `_ccfido`-owned enrolled-custody registry and never a daemon control file**. (2) **Best-effort** — a managed `PreToolUse` hook gates the advisory tiers, honestly defeatable by a same-uid agent (Task 0.1 fail-open). Signing lives in the console session because a system LaunchDaemon can't reach USB (broker-gate Q1); verification is USB-free, which is what makes the split work.

**Tech Stack:** Swift (Swift Package Manager, one `cc-fido` binary with subcommands: `daemon`/`hook`/`write`/`enroll`/`install`/`enroll-file`/`enroll-dir`/`_render-plist`/`_render-managed`/`_blink-test`), native Darwin BSD sockets + `xucred`/`LOCAL_PEERCRED`, native `chflags(2)` (`UF_IMMUTABLE`), CryptoKit `SHA256`, `Foundation.Process` shelling to `ssh-keygen -Y sign/verify` and `osascript`, macOS `launchd` + managed-settings, `codesign --options runtime` for the hardened-runtime daemon signature.

## Global Constraints

Every task's requirements implicitly include this section. Values are verbatim; do not paraphrase paths or flags.

- **Language:** Swift, one SPM package. Library target `CCFidoCore` holds all testable logic; executable target `cc-fido` is a thin subcommand dispatcher. **No third-party dependencies** — Foundation, Darwin, CryptoKit only. Build `swift build -c release`; test `swift test`.
- **Hardened runtime:** the shipped binary is codesigned `codesign --options runtime --sign - <binary>` (adhoc) at install (Task 7). The daemon also runs as a different uid (`_ccfido`) than the agent (`sean`), so cross-uid attach is denied regardless (0.7).
- **Sign side (client only):** `/opt/homebrew/opt/openssh/bin/ssh-keygen`. Stock `/usr/bin/ssh-keygen` (10.2p1) **cannot sign** `sk-` keys.
- **Verify side (daemon only):** `/usr/bin/ssh-keygen` — stock **verifies** `sk-` keys and needs **no USB**.
- **Signature transport (corrected — see Round-1 review):** the daemon writes the received signature to a **freshly `mkstemp`'d file inside `KEYDIR` (`0700`, `_ccfido`-owned, agent-unreachable)**, passes that path to `ssh-keygen -Y verify -s`, then `unlink`s it; the message rides the child's **stdin** (inherited). **Do NOT** try to hand the child an inherited pipe fd via `/dev/fd/N` — `Foundation.Process` spawns with `POSIX_SPAWN_CLOEXEC_DEFAULT` and closes it, so `-s /dev/fd/N` fails `Bad file descriptor` (empirically verified in Round-1 review). Probe 0.4 proved only that *`ssh-keygen` accepts a non-seekable `/dev/fd` under bash process substitution* — that does not transfer to `Foundation.Process`. The keydir temp file is TOCTOU-safe **because the agent cannot enter the `0700` keydir**, which is the exact property NEW-8's "no agent-swappable temp file" rule requires.
- **Signature options:** `-O resident=no` is **invalid** (non-resident is the default) — never pass it. Sign namespace and verify namespace must match exactly.
- **Dialog:** shell to `/usr/bin/osascript -l AppleScript`, passing the rendering as an **AppleScript `on run argv` argument (argv, never `-e` string interpolation)** per the design's argv rule (design.md §"gate flow"). `display dialog` needs StandardAdditions, which **won't load under sandbox-exec** (`-10810`) — the client/hook run **un-sandboxed**. Every spawned child (`ssh-keygen`, `osascript`) gets `Process.environment = scrubEnv(...)`.
- **Service account:** `_ccfido`, hidden, uid in 200–400, shell `/usr/bin/false` (created by `task0-broker/probes/account-setup.sh`, reused verbatim). `sean` (uid 501) cannot become it.
- **Canonical paths** (create in Task 1 bootstrap; reuse in every task):
  - `KEYDIR = /var/ccfido` — `_ccfido`-owned, mode `0700` (unreachable by `sean`). Holds `allowed_signers`, `audit.log`, `custody.json`, `ceremony.lock`, and transient verify temp files.
  - `RUNDIR = /var/ccfido-run` — `_ccfido`-owned, mode `0755` (traversable, so `sean` can reach the socket). Holds `gate.sock`.
  - `SOCK = /var/ccfido-run/gate.sock`
  - `ALLOWED_SIGNERS = /var/ccfido/allowed_signers` — `_ccfido`-owned, `0600`.
  - `AUDIT = /var/ccfido/audit.log` — `_ccfido`-owned, `0600`.
  - `CUSTODY = /var/ccfido/custody.json` — **`_ccfido`-owned, `0600`. The enrolled-crown-jewel registry: the ONLY paths `execute-write` may touch.** Agent can't read or write it (wrong uid + `0700` keydir).
  - `POLICY = /opt/cc-fido-gate/policy.json` — **root-owned, `0644`.** Hook gating tiers. The hook runs as `sean` and must be able to read it, so it lives outside the `0700` keydir; root ownership keeps the agent from *writing* it. (Moved here in Round-1 review — the keydir is agent-untraversable, so a keydir policy made every hook fail closed.)
  - `HANDLE = ~/.ccfido/gate_sk` — **login-user-owned (`sean`), `0600`** (capability-split option A).
  - `CODE = /opt/cc-fido-gate` — **root-owned, `0755`**; the codesigned `cc-fido` binary + `policy.json` live here.
  - `PLIST = /Library/LaunchDaemons/com.cc-fido-gate.brokerd.plist` — root-owned.
  - `MANAGED = /Library/Application Support/ClaudeCode/managed-settings.json` — root-owned.
- **File-custody scope:** file-custody is for crown-jewels the agent-uid does **not** need to read/write at runtime. **Live credentials the login user actively uses (e.g. `~/.ssh/id_*` you `git push` with) are credential-custody = out of scope for v2** — making them `_ccfido:0600` would break the tool that reads them. Enroll those only when you accept losing your own access.
- **Namespace / principal:** namespace `cc-fido-gate@example.test`, principal `gate-principal`.
- **Socket framing:** 4-byte big-endian unsigned length prefix + UTF-8 JSON body. Byte-valued fields base64. Peer uid via `getsockopt(fd, 0 /*SOL_LOCAL*/, LOCAL_PEERCRED, &xucred, &len)` → `xucred.cr_uid`; **on failure return `-1`, never `0`** (audit honesty).
- **`SIGPIPE`:** the daemon and client call `signal(SIGPIPE, SIG_IGN)` at startup — a peer that closes mid-write must yield `EPIPE`, not kill the process.
- **Immutable flag:** the daemon toggles the lock at runtime with native `chflags(path, UInt32(UF_IMMUTABLE))` / `chflags(path, 0)`. Enroll-time locking (Task 4/7) runs under `sudo` and may use `/usr/bin/chflags` since the agent can't (that is a one-time privileged step, not the runtime path).
- **Fail closed:** every ambiguity, timeout, malformed message, unknown tool, unenrolled target, or control-file target → deny / retain gating. Never silently allow. Policy load failure → the hook denies (exit 2), never passes.
- **Device-busy retry (0.4):** a hard-killed ceremony can leave the key transiently `device not found`; the next `sign` retries with short backoff.
- **Audit authentication:** `_ccfido`-owned append-only + **sha256 hash-chain** (`seq` + `prev_hash`), **chained from the first line written (Task 1)** so `verifyChain` never faces an unchained prefix. Agent can't write/truncate (wrong uid + `0700` keydir).
- **Test-execution convention:**
  - **`[SW]`** — software-only, deterministic, **no hardware and no sudo**. A subagent writes *and runs* these via `swift test` (software `ed25519` key as `sk-` stand-in per probe 0.4, `socketpair(2)`, `NSTemporaryDirectory()`).
  - **`[USER-RUN]`** — needs **sudo and/or a physical touch**. A subagent writes the script but **must not execute it**; the **user runs it un-sandboxed and pastes output**. Each `[USER-RUN]` step names its file and expected output.
- **Commit style:** conventional commits, committed directly to `main`.

### Accepted decisions

1. **Compiled Swift** — resolves the spec's "hardened-runtime signed daemon" via `codesign --options runtime`.
2. **Audit = `_ccfido`-owned append-only + sha256 hash-chain**, not keyed HMAC.
3. **Dialog stays `osascript`** (argv form) — proven under env-scrub in 0.5; NSAlert parked.
4. **Two-file trust split:** `_ccfido`-owned `custody.json` (the hard-guarantee target allowlist) vs root-owned `policy.json` (advisory hook tiers).

---

## File Structure

Developed in-repo; the built binary + `policy.json` are copied to `CODE` by `cc-fido install` (Task 7).

- `Package.swift` — SPM manifest (Task 1).
- `Sources/CCFidoCore/Paths.swift` — path + namespace constants (Task 1).
- `Sources/CCFidoCore/Wire.swift` — framing `sendMsg`/`recvMsg` + `peerUID` (Task 1).
- `Sources/CCFidoCore/Crypto.swift` — `sign()` + `verify()` (keydir temp file) + `scrubEnv` application (Task 1).
- `Sources/CCFidoCore/Canonical.swift` — `SignedDocument`, `canonicalBytes`, `canonicalJSON`, `humanRendering` (Task 1 → Task 2).
- `Sources/CCFidoCore/Audit.swift` — hash-chained append-only log (Task 1 → Task 3 adds `verifyChain`).
- `Sources/CCFidoCore/Custody.swift` — `CustodyRegistry`, `planEnrollFile/Dir`, `checkAncestors` (Task 4).
- `Sources/CCFidoCore/Broker.swift` — `Broker`: server, `execute-write` (allowlisted) + `approve`, serialization, watchdog (Task 1 → Task 3).
- `Sources/CCFidoCore/Client.swift` — dialog (argv) + arm/sign, `runWrite`/`runApprove` (Task 1 → Task 3).
- `Sources/CCFidoCore/Policy.swift` — `Policy.decide`, `matchPath`, tiers (Task 5).
- `Sources/CCFidoCore/HookLogic.swift` — `scrubEnv`, `decideAndEmit`, `hookMain` (Task 6).
- `Sources/CCFidoCore/CLIHelpers.swift` — `renderPlist`, `renderManagedSettings`, `ccVersion`, `negativeBlinkTest`, `runPrivileged` (Task 7).
- `Sources/cc-fido/main.swift` — subcommand dispatch (grows each task).
- `install/policy.json` — default hook tiers (Task 5).
- `Tests/CCFidoCoreTests/*.swift` — mirrors the core sources.
- `tests/userrun/*.sh` — `[USER-RUN]` scripts.

---

## Task 1: Walking skeleton — end-to-end split ceremony

The spine, composing pieces the feasibility gate proved (socket Q4, owner `uchg`-toggle+write Q1/Q3-owner, client sign 0.4, USB-free verify 0.4). It already enforces the **custody-registry allowlist** and **control-file denylist** (C-3), a correct **keydir-temp-file `verify()`** (C-1), and a **fully error-checked `uchgWrite`**.

**Files:**
- Create: `Package.swift`, `Sources/CCFidoCore/{Paths,Wire,Crypto,Canonical,Audit,Broker,Client}.swift`, `Sources/cc-fido/main.swift`
- Test: `Tests/CCFidoCoreTests/{Wire,Crypto,Canonical,BrokerAllowlist}Tests.swift`
- Test (USER-RUN): `tests/userrun/bootstrap.sh`, `tests/userrun/task1_e2e.sh`

**Interfaces produced:**
- `Paths` enum: `keydir, runDir, sock, allowedSigners, audit, custody, policy, code, namespace, principal, handle, signKeygen, verifyKeygen, controlDenylist` (`[String]`).
- `sendMsg(_ fd: Int32, _ obj: [String: Any]) throws` / `recvMsg(_ fd: Int32) throws -> [String: Any]` (`WireError.eof/.tooLarge/.badBody`)
- `peerUID(_ fd: Int32) -> Int` (`-1` on failure)
- `sign(challenge: Data, handlePath: String, namespace: String, retries: Int = 3, keygen: String = Paths.signKeygen) throws -> Data`
- `verify(challenge: Data, signature: Data, allowedSigners: String, principal: String, namespace: String, keygen: String = Paths.verifyKeygen) -> Bool`
- `SignedDocument: Codable, Equatable` + `canonicalBytes<T: Encodable>(_:) throws -> Data` + `buildSignedDocument(...)`
- `auditAppend(_ entry: [String: Any], path: String = Paths.audit) throws` (chained)
- `Broker(...).serve() throws`; `Broker.isEnrolledTarget(_ path: String, registry: [String]) -> Bool`; `Broker.isControlPath(_ path: String) -> Bool`
- `runWrite(path: String, content: Data, sockPath: String = Paths.sock) -> Int32`

- [ ] **Step 1: `Package.swift` + `Paths.swift`**

```swift
// Package.swift
// swift-tools-version:5.9
import PackageDescription
let package = Package(
  name: "cc-fido-gate",
  platforms: [.macOS(.v13)],
  targets: [
    .target(name: "CCFidoCore"),
    .executableTarget(name: "cc-fido", dependencies: ["CCFidoCore"]),
    .testTarget(name: "CCFidoCoreTests", dependencies: ["CCFidoCore"]),
  ]
)
```

```swift
// Sources/CCFidoCore/Paths.swift
import Foundation

public enum Paths {
    public static let keydir = "/var/ccfido"
    public static let runDir = "/var/ccfido-run"
    public static let sock = "/var/ccfido-run/gate.sock"
    public static let allowedSigners = "/var/ccfido/allowed_signers"
    public static let audit = "/var/ccfido/audit.log"
    public static let custody = "/var/ccfido/custody.json"
    public static let ceremonyLock = "/var/ccfido/ceremony.lock"
    public static let policy = "/opt/cc-fido-gate/policy.json"
    public static let code = "/opt/cc-fido-gate"
    public static let handle = (NSHomeDirectory() as NSString).appendingPathComponent(".ccfido/gate_sk")
    public static let namespace = "cc-fido-gate@example.test"
    public static let principal = "gate-principal"
    public static let signKeygen = "/opt/homebrew/opt/openssh/bin/ssh-keygen"
    public static let verifyKeygen = "/usr/bin/ssh-keygen"
    // execute-write is UNCONDITIONALLY denied to these + anything under keydir/code:
    public static let controlDenylist = [allowedSigners, audit, custody, ceremonyLock, sock, policy]
}
```

- [ ] **Step 2: `[SW]` Failing wire test**

```swift
// Tests/CCFidoCoreTests/WireTests.swift
import XCTest
import Darwin
@testable import CCFidoCore

final class WireTests: XCTestCase {
    private func pair() -> (Int32, Int32) {
        var fds: [Int32] = [0, 0]
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &fds), 0)
        return (fds[0], fds[1])
    }
    func testRoundtrip() throws {
        let (a, b) = pair(); defer { close(a); close(b) }
        try sendMsg(a, ["op": "execute-write", "path": "/x", "content_b64": "aGk="])
        let got = try recvMsg(b)
        XCTAssertEqual(got["op"] as? String, "execute-write")
        XCTAssertEqual(got["content_b64"] as? String, "aGk=")
    }
    func testRecvOnClosedPeerThrows() {
        let (a, b) = pair(); close(a)
        XCTAssertThrowsError(try recvMsg(b)) { _ in close(b) }
    }
    func testOversizeLengthRejected() {
        let (a, b) = pair(); defer { close(a); close(b) }
        var len = UInt32(0x7fffffff).bigEndian
        withUnsafeBytes(of: &len) { _ = send(a, $0.baseAddress, 4, 0) }
        XCTAssertThrowsError(try recvMsg(b))
    }
    func testInvalidJSONRaisesBadBody() throws {
        let (a, b) = pair(); defer { close(a); close(b) }
        let body = Data("{not json".utf8)
        var len = UInt32(body.count).bigEndian
        var frame = Data(bytes: &len, count: 4); frame.append(body)
        _ = frame.withUnsafeBytes { send(a, $0.baseAddress, frame.count, 0) }
        XCTAssertThrowsError(try recvMsg(b)) { XCTAssertEqual($0 as? WireError, .badBody) }
    }
    func testPeerUIDMatchesSelf() {
        let (a, b) = pair(); defer { close(a); close(b) }
        XCTAssertEqual(peerUID(a), Int(getuid()))
    }
}
```

- [ ] **Step 3: `[SW]` Run — expect FAIL** (`cannot find 'sendMsg'`). Run: `swift test --filter WireTests`

- [ ] **Step 4: Implement `Wire.swift`** (EINTR retry, unaligned load, `badBody`, checked peer uid)

```swift
// Sources/CCFidoCore/Wire.swift
import Foundation
import Darwin

public enum WireError: Error, Equatable { case eof, tooLarge, badBody }
public let MAX_MSG = 8 * 1024 * 1024

func recvRetry(_ fd: Int32, _ buf: UnsafeMutableRawPointer, _ n: Int) -> Int {
    while true { let r = recv(fd, buf, n, 0); if r < 0 && errno == EINTR { continue }; return r }
}
func sendRetry(_ fd: Int32, _ buf: UnsafeRawPointer, _ n: Int) -> Int {
    while true { let r = send(fd, buf, n, 0); if r < 0 && errno == EINTR { continue }; return r }
}

func readExactly(_ fd: Int32, _ n: Int) throws -> Data {
    var buf = Data(); buf.reserveCapacity(n)
    let chunk = 64 * 1024
    var tmp = [UInt8](repeating: 0, count: min(max(n, 1), chunk))
    while buf.count < n {
        let want = min(n - buf.count, tmp.count)
        let r = tmp.withUnsafeMutableBytes { recvRetry(fd, $0.baseAddress!, want) }
        if r <= 0 { throw WireError.eof }
        buf.append(contentsOf: tmp[0..<r])
    }
    return buf
}
func writeAll(_ fd: Int32, _ data: Data) throws {
    try data.withUnsafeBytes { raw in
        var off = 0
        while off < data.count {
            let w = sendRetry(fd, raw.baseAddress!.advanced(by: off), data.count - off)
            if w <= 0 { throw WireError.eof }
            off += w
        }
    }
}
public func sendMsg(_ fd: Int32, _ obj: [String: Any]) throws {
    guard let body = try? JSONSerialization.data(withJSONObject: obj) else { throw WireError.badBody }
    if body.count > MAX_MSG { throw WireError.tooLarge }
    var len = UInt32(body.count).bigEndian
    var frame = Data(bytes: &len, count: 4); frame.append(body)
    try writeAll(fd, frame)
}
public func recvMsg(_ fd: Int32) throws -> [String: Any] {
    let header = try readExactly(fd, 4)
    let length = Int(UInt32(bigEndian: header.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) }))
    if length > MAX_MSG { throw WireError.tooLarge }
    let body = try readExactly(fd, length)
    guard let obj = (try? JSONSerialization.jsonObject(with: body)) as? [String: Any] else {
        throw WireError.badBody
    }
    return obj
}
public func peerUID(_ fd: Int32) -> Int {
    var cred = xucred()
    var len = socklen_t(MemoryLayout<xucred>.size)
    let rc = getsockopt(fd, 0, LOCAL_PEERCRED, &cred, &len)
    return rc == 0 ? Int(cred.cr_uid) : -1   // fail-honest, never 0
}
```

- [ ] **Step 5: `[SW]` Run — expect PASS** (5 passed). Run: `swift test --filter WireTests`

- [ ] **Step 6: `[SW]` Failing crypto test — including a guard that the OLD `/dev/fd` approach would have failed**

```swift
// Tests/CCFidoCoreTests/CryptoTests.swift
import XCTest
import Foundation
@testable import CCFidoCore

final class CryptoTests: XCTestCase {
    private func mkSoftwareKey() throws -> (key: String, allowed: String, keydir: String) {
        let dir = NSTemporaryDirectory() + "ccfg-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        let key = dir + "/id"
        let p = Process(); p.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-keygen")
        p.arguments = ["-t", "ed25519", "-N", "", "-C", "gate-principal", "-f", key]
        p.standardOutput = FileHandle.nullDevice; p.standardError = FileHandle.nullDevice
        try p.run(); p.waitUntilExit()
        let pub = try String(contentsOfFile: key + ".pub", encoding: .utf8)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let allowed = dir + "/allowed_signers"
        try "gate-principal \(pub)\n".write(toFile: allowed, atomically: true, encoding: .utf8)
        return (key, allowed, dir)
    }
    func testSignVerifyRoundtrip() throws {
        let (key, allowed, dir) = try mkSoftwareKey()
        let challenge = Data("canonical challenge bytes".utf8)
        let sig = try sign(challenge: challenge, handlePath: key, namespace: Paths.namespace,
                           keygen: "/usr/bin/ssh-keygen")
        XCTAssertTrue(String(data: sig, encoding: .utf8)!.contains("BEGIN SSH SIGNATURE"))
        // verify() must use a real, readable sig path — the keydir temp file. Pass dir as the temp root.
        XCTAssertTrue(verify(challenge: challenge, signature: sig, allowedSigners: allowed,
                             principal: "gate-principal", namespace: Paths.namespace, keydir: dir))
    }
    func testTamperRejected() throws {
        let (key, allowed, dir) = try mkSoftwareKey()
        let sig = try sign(challenge: Data("original".utf8), handlePath: key,
                           namespace: Paths.namespace, keygen: "/usr/bin/ssh-keygen")
        XCTAssertFalse(verify(challenge: Data("tampered".utf8), signature: sig, allowedSigners: allowed,
                              principal: "gate-principal", namespace: Paths.namespace, keydir: dir))
    }
    func testWrongNamespaceRejected() throws {
        let (key, allowed, dir) = try mkSoftwareKey()
        let sig = try sign(challenge: Data("m".utf8), handlePath: key,
                           namespace: Paths.namespace, keygen: "/usr/bin/ssh-keygen")
        XCTAssertFalse(verify(challenge: Data("m".utf8), signature: sig, allowedSigners: allowed,
                              principal: "gate-principal", namespace: "other@example.test", keydir: dir))
    }
}
```

- [ ] **Step 7: `[SW]` Run — expect FAIL** (`cannot find 'sign'`)

- [ ] **Step 8: Implement `Crypto.swift`** — keydir temp-file verify (C-1 fix), scrubbed env, size-capped signature

```swift
// Sources/CCFidoCore/Crypto.swift
import Foundation
import Darwin

public enum SignError: Error { case failed(String) }
public let MAX_SIG = 64 * 1024   // sk signatures are < 1 KiB; cap defensively

public func scrubbedEnv() -> [String: String] {
    var keep: [String: String] = [:]
    let env = ProcessInfo.processInfo.environment
    for k in ["HOME", "USER", "LANG", "__CF_USER_TEXT_ENCODING"] { if let v = env[k] { keep[k] = v } }
    keep["PATH"] = "/usr/bin:/bin:/usr/sbin:/sbin"
    return keep
}

public func sign(challenge: Data, handlePath: String, namespace: String,
                 retries: Int = 3, keygen: String = Paths.signKeygen) throws -> Data {
    var lastErr = ""
    for attempt in 0..<retries {
        let p = Process(); p.executableURL = URL(fileURLWithPath: keygen)
        p.arguments = ["-Y", "sign", "-f", handlePath, "-n", namespace]
        p.environment = scrubbedEnv()
        let inP = Pipe(), outP = Pipe(), errP = Pipe()
        p.standardInput = inP; p.standardOutput = outP; p.standardError = errP
        try p.run()
        inP.fileHandleForWriting.write(challenge)
        try? inP.fileHandleForWriting.close()
        let out = outP.fileHandleForReading.readDataToEndOfFile()
        let err = errP.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        if p.terminationStatus == 0, out.range(of: Data("BEGIN SSH SIGNATURE".utf8)) != nil { return out }
        lastErr = String(data: err, encoding: .utf8) ?? ""
        if lastErr.contains("device not found") && attempt < retries - 1 {
            Thread.sleep(forTimeInterval: 1.5 * Double(attempt + 1)); continue
        }
        break
    }
    throw SignError.failed(lastErr)
}

/// Daemon-side. Writes the signature to a temp file inside `keydir` (0700, agent-unreachable),
/// message on stdin, then unlinks. NOT an inherited /dev/fd pipe (Foundation.Process closes it).
public func verify(challenge: Data, signature: Data, allowedSigners: String,
                   principal: String, namespace: String,
                   keygen: String = Paths.verifyKeygen, keydir: String = Paths.keydir) -> Bool {
    if signature.count > MAX_SIG || signature.isEmpty { return false }
    var tmpl = Array((keydir + "/.sig.XXXXXX").utf8CString)
    let fd = mkstemp(&tmpl)
    if fd < 0 { return false }
    let sigPath = String(cString: tmpl)
    defer { unlink(sigPath) }
    let ok = signature.withUnsafeBytes { raw -> Bool in
        var off = 0
        while off < signature.count {
            let w = write(fd, raw.baseAddress!.advanced(by: off), signature.count - off)
            if w < 0 && errno == EINTR { continue }
            if w <= 0 { return false }; off += w
        }
        return true
    }
    if close(fd) != 0 { return false }
    if !ok { return false }
    let p = Process(); p.executableURL = URL(fileURLWithPath: keygen)
    p.arguments = ["-Y", "verify", "-f", allowedSigners, "-I", principal, "-n", namespace, "-s", sigPath]
    p.environment = scrubbedEnv()
    let inP = Pipe(); p.standardInput = inP
    p.standardOutput = FileHandle.nullDevice; p.standardError = FileHandle.nullDevice
    do { try p.run() } catch { return false }
    inP.fileHandleForWriting.write(challenge)
    try? inP.fileHandleForWriting.close()
    p.waitUntilExit()
    return p.terminationStatus == 0
}
```

- [ ] **Step 9: `[SW]` Run — expect PASS** (3 passed). Run: `swift test --filter CryptoTests`

- [ ] **Step 10: `[SW]` Failing canonical test (golden bytes + `canonicalJSON`)**

```swift
// Tests/CCFidoCoreTests/CanonicalTests.swift
import XCTest
@testable import CCFidoCore

final class CanonicalTests: XCTestCase {
    func testGoldenSignedDocumentBytes() throws {
        let doc = buildSignedDocument(op: "execute-write", path: "/tmp/x", contentSha256: "ab",
                                      cwd: "/tmp", nonceHex: "00", callerUid: 501, contentMode: "inline")
        let expected = #"{"caller_uid":501,"content_mode":"inline","content_sha256":"ab","cwd":"/tmp","nonce":"00","op":"execute-write","path":"/tmp/x","v":1}"#
        XCTAssertEqual(String(data: try canonicalBytes(doc), encoding: .utf8), expected)
    }
    func testCanonicalJSONSortsKeys() throws {
        let a = try canonicalJSON(["b": 1, "a": 2])
        XCTAssertEqual(String(data: a, encoding: .utf8), #"{"a":2,"b":1}"#)
    }
    func testCanonicalJSONNestedDeterministic() throws {
        let a = try canonicalJSON(["input": ["z": 1, "a": 2], "tool": "Bash"])
        let b = try canonicalJSON(["tool": "Bash", "input": ["a": 2, "z": 1]])
        XCTAssertEqual(a, b)
    }
}
```

- [ ] **Step 11: `[SW]` Run — expect FAIL** (`cannot find 'buildSignedDocument'`)

- [ ] **Step 12: Implement `Canonical.swift` (v0 — renderer in Task 2)**

```swift
// Sources/CCFidoCore/Canonical.swift
import Foundation

public enum CanonicalError: Error { case notEncodable }

public struct SignedDocument: Codable, Equatable {
    public let v: Int
    public let op: String
    public let path: String
    public let contentSha256: String
    public let cwd: String
    public let nonce: String
    public let callerUid: Int
    public let contentMode: String
    enum CodingKeys: String, CodingKey {
        case v, op, path, cwd, nonce
        case contentSha256 = "content_sha256"
        case callerUid = "caller_uid"
        case contentMode = "content_mode"
    }
}
public func buildSignedDocument(op: String, path: String, contentSha256: String, cwd: String,
                                nonceHex: String, callerUid: Int,
                                contentMode: String = "inline") -> SignedDocument {
    SignedDocument(v: 1, op: op, path: path, contentSha256: contentSha256, cwd: cwd,
                   nonce: nonceHex, callerUid: callerUid, contentMode: contentMode)
}
public func canonicalBytes<T: Encodable>(_ obj: T) throws -> Data {
    let enc = JSONEncoder()
    enc.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    return try enc.encode(obj)
}
/// Canonical bytes for an arbitrary already-parsed JSON object (the `approve` payload).
/// .sortedKeys sorts nested keys too; compact by default.
public func canonicalJSON(_ obj: [String: Any]) throws -> Data {
    guard JSONSerialization.isValidJSONObject(obj) else { throw CanonicalError.notEncodable }
    return try JSONSerialization.data(withJSONObject: obj, options: [.sortedKeys, .withoutEscapingSlashes])
}
```

- [ ] **Step 13: `[SW]` Run — expect PASS** (3 passed)

- [ ] **Step 14: Implement `Audit.swift` (chained from the first line)**

```swift
// Sources/CCFidoCore/Audit.swift
import Foundation
import Darwin
import CryptoKit

public func sha256Hex(_ data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}
func auditLines(_ path: String) -> [String] {
    (try? String(contentsOfFile: path, encoding: .utf8))?.split(separator: "\n").map(String.init) ?? []
}
public func auditAppend(_ entry: [String: Any], path: String = Paths.audit) throws {
    let lines = auditLines(path)
    var rec = entry
    rec["seq"] = lines.count
    rec["prev_hash"] = lines.last.map { sha256Hex(Data($0.utf8)) } ?? String(repeating: "0", count: 64)
    rec["ts"] = Date().timeIntervalSince1970
    var line = String(data: try JSONSerialization.data(withJSONObject: rec, options: [.sortedKeys]),
                      encoding: .utf8)! + "\n"
    let fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0o600)
    guard fd >= 0 else { throw WireError.eof }
    defer { close(fd) }
    let ok = line.withUTF8 { p -> Bool in
        var off = 0
        while off < p.count { let w = write(fd, p.baseAddress!.advanced(by: off), p.count - off)
            if w <= 0 { return false }; off += w }
        return true
    }
    fsync(fd)
    if !ok { throw WireError.eof }
}
```

- [ ] **Step 15: `[SW]` Failing allowlist test (C-3 core — no socket, no hardware)**

```swift
// Tests/CCFidoCoreTests/BrokerAllowlistTests.swift
import XCTest
@testable import CCFidoCore

final class BrokerAllowlistTests: XCTestCase {
    func testControlPathsAlwaysDenied() {
        for p in [Paths.allowedSigners, Paths.audit, Paths.custody, Paths.policy,
                  "/var/ccfido/anything", "/opt/cc-fido-gate/cc-fido"] {
            XCTAssertTrue(Broker.isControlPath(p), "\(p) must be a control path")
        }
    }
    func testEnrolledTargetGate() {
        let reg = ["/Users/sean/secret.txt"]
        XCTAssertTrue(Broker.isEnrolledTarget("/Users/sean/secret.txt", registry: reg))
        XCTAssertFalse(Broker.isEnrolledTarget("/Users/sean/other.txt", registry: reg))
    }
    func testControlPathBeatsEnrollment() {
        // even if somehow present in the registry, a control path is denied
        XCTAssertTrue(Broker.isControlPath(Paths.allowedSigners))
    }
    // round-3: F_GETPATH returns /private-firmlinked paths; normalization must fold them so the
    // post-open re-check and the denylist still match (this exact case the prior tests missed).
    func testNormPathFoldsPrivateFirmlink() {
        XCTAssertEqual(Broker.normPath("/private/var/ccfido/allowed_signers"), "/var/ccfido/allowed_signers")
        XCTAssertEqual(Broker.normPath("/private/tmp/x"), "/tmp/x")
        XCTAssertEqual(Broker.normPath("/private/etc/x"), "/etc/x")
        XCTAssertEqual(Broker.normPath("/private/foo"), "/private/foo")  // NOT a firmlink — must NOT fold
        XCTAssertTrue(Broker.isControlPath("/private/var/ccfido/allowed_signers"))     // F_GETPATH form still denied
        XCTAssertTrue(Broker.isEnrolledTarget("/private/var/lib/x", registry: ["/var/lib/x"]))  // firmlinked enroll matches
    }
}
```

*(The intermediate-symlink redirect itself (F_GETPATH catching an ancestor swap into the keydir) is a `[USER-RUN]` test — add to `task4_custody.sh`: enroll `/Users/Shared/audit.log`, run the ceremony, and between the touch and the write `mv` its parent to a symlink pointing at `/var/ccfido`; assert the daemon logs `write_error … post-open path escaped` and `/var/ccfido/audit.log` is untouched. It needs a real open+fd, so it can't be `[SW]`.)*

- [ ] **Step 16: `[SW]` Run — expect FAIL**, then implement `Broker.swift` (v0 — allowlisted `execute-write`, error-checked `uchgWrite`, `SIGPIPE` ignore, checked socket)

```swift
// Sources/CCFidoCore/Broker.swift
import Foundation
import Darwin

public enum BrokerError: Error { case writeFailed(String) }

public final class Broker {
    let sockPath: String
    let allowedSigners: String
    public init(sockPath: String = Paths.sock, allowedSigners: String = Paths.allowedSigners) {
        self.sockPath = sockPath; self.allowedSigners = allowedSigners
    }

    // --- authorization helpers (pure, [SW]-tested) ---
    /// Canonical comparison form: standardize + strip the macOS `/private` firmlink prefix, so `/var…`
    /// and `/private/var…` (the form `F_GETPATH` returns) map to ONE string. NO `realpath` — realpathing
    /// only `norm` forked `/var` vs `/private/var` against the lexical constants + registry (round-3
    /// regression). Symlink-redirect defense is the `F_GETPATH` post-open re-check in `uchgWrite`, not
    /// this string normalization.
    public static func normPath(_ path: String) -> String {
        let p = (path as NSString).standardizingPath
        // Only the ACTUAL macOS firmlinked roots fold — NOT every /private/* path (else /private/foo→/foo,
        // which could alias registry auth onto the wrong object). Verification-pass codex HIGH.
        for root in ["/var", "/etc", "/tmp"] {
            if p == "/private" + root { return root }
            if p.hasPrefix("/private" + root + "/") { return String(p.dropFirst("/private".count)) }
        }
        return p
    }
    public static func isControlPath(_ path: String) -> Bool {
        let p = normPath(path)
        if Paths.controlDenylist.map(normPath).contains(p) { return true }
        return p.hasPrefix(Paths.keydir + "/") || p == Paths.keydir
            || p.hasPrefix(Paths.code + "/") || p == Paths.code
    }
    public static func isEnrolledTarget(_ path: String, registry: [String]) -> Bool {
        let p = normPath(path)
        return registry.contains { normPath($0) == p }
    }
    func loadRegistry() -> [String] {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: Paths.custody)),
              let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
              let files = obj["files"] as? [String] else { return [] }
        return files
    }

    // nouchg -> O_NOFOLLOW open (NO O_TRUNC) -> validate the OPEN FD -> ftruncate -> write -> fsync -> checked uchg.
    // Round-3 fixes (codex CRITICAL + pentester HIGH): DO NOT O_TRUNC before validating — a redirect would
    // truncate the target before the fstat guard catches it, so we open without O_TRUNC and only ftruncate
    // AFTER every check passes. fstat asserts regular + st_nlink==1 + owner==_ccfido, FAIL-CLOSED if the
    // _ccfido lookup fails. Then F_GETPATH re-derives the ACTUALLY-OPENED path (fully symlink-resolved) and
    // re-runs the control/enrolled checks on it — this is what closes the intermediate-directory-symlink
    // redirect that O_NOFOLLOW (final-component only) cannot. `norm` is the already-validated enrolled target.
    func uchgWrite(_ norm: String, _ content: Data, registry: [String]) throws {
        guard let ccfidoUID = getpwnam("_ccfido").map({ $0.pointee.pw_uid }) else {
            throw BrokerError.writeFailed("_ccfido lookup failed — refusing (fail closed)")
        }
        var relocked = false
        func relock() throws {
            if relocked { return }
            if chflags(norm, UInt32(UF_IMMUTABLE)) != 0 {
                throw BrokerError.writeFailed("RELOCK FAILED — target left unlocked: \(String(cString: strerror(errno)))")
            }
            relocked = true
        }
        chflags(norm, 0)  // unlock; on the failure paths below we relock via the catch
        do {
            let fd = open(norm, O_WRONLY | O_CREAT | O_NOFOLLOW, 0o600)   // NOTE: no O_TRUNC
            if fd < 0 { throw BrokerError.writeFailed("open: \(String(cString: strerror(errno)))") }
            defer { close(fd) }   // (close() errno on a write fd is not meaningfully recoverable after fsync)
            var st = stat()
            guard fstat(fd, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG,
                  st.st_nlink == 1, st.st_uid == ccfidoUID else {
                throw BrokerError.writeFailed("target is not a lone _ccfido-owned regular file (nlink/owner)")
            }
            // Re-check the path the fd ACTUALLY points at (defeats intermediate-symlink ancestor swap):
            var pbuf = [Int8](repeating: 0, count: Int(PATH_MAX))
            guard fcntl(fd, F_GETPATH, &pbuf) == 0 else { throw BrokerError.writeFailed("F_GETPATH") }
            let real = Broker.normPath(String(cString: pbuf))
            // `norm` was already validated (non-control + enrolled) in handle(); requiring the OPENED
            // path to equal it is strictly stronger than membership — it also closes the enrolled→enrolled
            // basename-collision redirect (pentester-verify residual 1). isControlPath(real) kept as an
            // explicit belt. (A legit target with a symlinked ancestor over-denies here — fail-closed, and
            // checkAncestors already WARNed at enroll time.)
            guard real == norm, !Broker.isControlPath(real), Broker.isEnrolledTarget(real, registry: registry) else {
                throw BrokerError.writeFailed("post-open path escaped: \(real) (norm=\(norm))")
            }
            if ftruncate(fd, 0) != 0 { throw BrokerError.writeFailed("ftruncate: \(String(cString: strerror(errno)))") }
            try content.withUnsafeBytes { raw in
                var off = 0
                while off < content.count {
                    let w = write(fd, raw.baseAddress!.advanced(by: off), content.count - off)
                    if w < 0 && errno == EINTR { continue }
                    if w <= 0 { throw BrokerError.writeFailed("write: \(String(cString: strerror(errno)))") }
                    off += w
                }
            }
            if fsync(fd) != 0 { throw BrokerError.writeFailed("fsync failed") }
        } catch {
            try? relock(); throw error   // best-effort relock on failure; original error propagates
        }
        try relock()   // MUST succeed on the success path or we throw (caller logs write_error, not write_ok)
    }

    func handle(_ fd: Int32) throws {
        let caller = peerUID(fd)
        let req = try recvMsg(fd)
        guard req["op"] as? String == "execute-write",
              let path = req["path"] as? String,
              let b64 = req["content_b64"] as? String,
              let content = Data(base64Encoded: b64) else {
            try sendMsg(fd, ["phase": "result", "status": "deny", "reason": "bad request"]); return
        }
        let norm = Broker.normPath(path)    // /private-stripped; same string feeds the checks AND uchgWrite's open
        let reg = loadRegistry()
        if Broker.isControlPath(norm) || !Broker.isEnrolledTarget(norm, registry: reg) {
            try auditAppend(["event": "deny_target", "path": norm, "caller": caller])
            try sendMsg(fd, ["phase": "result", "status": "deny", "reason": "not an enrolled target"]); return
        }
        let nonce = (0..<16).map { _ in String(format: "%02x", UInt8.random(in: 0...255)) }.joined()
        let doc = buildSignedDocument(op: "execute-write", path: norm,
                                      contentSha256: sha256Hex(content),
                                      cwd: req["cwd"] as? String ?? "", nonceHex: nonce, callerUid: caller)
        let challenge = try canonicalBytes(doc)
        try sendMsg(fd, ["phase": "challenge", "challenge_b64": challenge.base64EncodedString(),
                         "human_rendering": "WRITE \(norm)\n\(content.count) bytes  sha256:\(doc.contentSha256)"])
        let reply = try recvMsg(fd)
        guard reply["phase"] as? String == "signature",
              let sigB64 = reply["signature_b64"] as? String, let sig = Data(base64Encoded: sigB64),
              verify(challenge: challenge, signature: sig, allowedSigners: allowedSigners,
                     principal: Paths.principal, namespace: Paths.namespace) else {
            try auditAppend(["event": "deny", "path": norm, "caller": caller])
            try sendMsg(fd, ["phase": "result", "status": "deny", "reason": "no valid touch"]); return
        }
        do { try uchgWrite(norm, content, registry: reg) }
        catch {
            try auditAppend(["event": "write_error", "path": norm, "caller": caller, "err": "\(error)"])
            try sendMsg(fd, ["phase": "result", "status": "deny", "reason": "write failed"]); return
        }
        try auditAppend(["event": "write_ok", "path": norm, "caller": caller,
                         "content_sha256": doc.contentSha256])
        try sendMsg(fd, ["phase": "result", "status": "ok"])
    }

    public func serve() throws {
        signal(SIGPIPE, SIG_IGN)
        unlink(sockPath)
        let s = socket(AF_UNIX, SOCK_STREAM, 0)
        if s < 0 { throw BrokerError.writeFailed("socket()") }
        var addr = sockaddr_un(); addr.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = Array(sockPath.utf8)
        if pathBytes.count >= MemoryLayout.size(ofValue: addr.sun_path) {
            throw BrokerError.writeFailed("socket path too long")
        }
        withUnsafeMutablePointer(to: &addr.sun_path) {
            $0.withMemoryRebound(to: CChar.self, capacity: pathBytes.count + 1) { dst in
                for (i, b) in pathBytes.enumerated() { dst[i] = CChar(bitPattern: b) }; dst[pathBytes.count] = 0
            }
        }
        let sz = socklen_t(MemoryLayout<sockaddr_un>.size)
        let bindRC = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(s, $0, sz) }
        }
        if bindRC != 0 { throw BrokerError.writeFailed("bind: \(String(cString: strerror(errno)))") }
        chmod(sockPath, 0o666)      // any local caller; auth is by touch, not identity
        if listen(s, 16) != 0 { throw BrokerError.writeFailed("listen") }
        while true {
            let conn = accept(s, nil, nil)
            if conn < 0 { if errno == EINTR { continue }; usleep(100_000); continue }
            // per-connection thread so one slow ceremony never starves accept (DoS fix)
            Thread.detachNewThread { [weak self] in self?.handleGuarded(conn) }
        }
    }

    static let ceremonyDeadline: TimeInterval = 90

    func handleGuarded(_ conn: Int32) {
        defer { close(conn) }
        // REAL absolute wall-clock cap (round-2 fix): SO_RCVTIMEO is only a per-recv idle timeout and a
        // slow-drip peer can reset it forever, holding the ceremony flock and starving every other write.
        // A one-shot watchdog thread shutdown()s the connection at start+deadline, which unblocks any
        // recv AND (because the fd is force-closed) collapses the ceremony so the flock defer releases.
        var tv = timeval(tv_sec: 90, tv_usec: 0)   // belt: per-recv idle bound
        setsockopt(conn, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        let done = DispatchSemaphore(value: 0)
        Thread.detachNewThread {
            if done.wait(timeout: .now() + Broker.ceremonyDeadline) == .timedOut {
                shutdown(conn, SHUT_RDWR)   // absolute cap: force the blocked recv/handle to error out
            }
        }
        defer { done.signal() }
        // flock is load-bearing BEYOND serialization: auditAppend is read-modify-write (reads all lines to
        // compute seq/prev_hash, then appends) and is NOT atomic — two concurrent ceremonies would both write
        // seq=N and corrupt the chain. The flock serializes them. Do NOT drop it when tuning the watchdog;
        // if per-connection concurrency is ever wanted, give auditAppend its own flock on the audit file.
        let lockFD = open(Paths.ceremonyLock, O_CREAT | O_RDWR, 0o600)
        if lockFD < 0 { return }
        if flock(lockFD, LOCK_EX) != 0 { close(lockFD); return }
        defer { flock(lockFD, LOCK_UN); close(lockFD) }
        do { try handle(conn) } catch { /* malformed/aborted/deadline: drop */ }
    }
}
```

- [ ] **Step 17: `[SW]` Run allowlist test — expect PASS**, build the target. Run: `swift build && swift test --filter BrokerAllowlistTests`

- [ ] **Step 18: Implement `Client.swift` (argv-form dialog, scrubbed env) + `main.swift` dispatch**

```swift
// Sources/CCFidoCore/Client.swift
import Foundation
import Darwin

/// Softened WYSIWYS dialog. Rendering passed as an AppleScript argv item, never interpolated into -e.
func dialog(_ humanRendering: String) -> Bool {
    let p = Process(); p.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
    p.arguments = ["-l", "AppleScript",
        "-e", "on run argv",
        "-e", "display dialog (item 1 of argv) buttons {\"Cancel\", \"Approve\"} default button \"Cancel\" with title \"cc-fido-gate\" giving up after 60",
        "-e", "end run",
        humanRendering]
    p.environment = scrubbedEnv()
    let out = Pipe(); p.standardOutput = out; p.standardError = FileHandle.nullDevice
    do { try p.run() } catch { return false }
    let data = out.fileHandleForReading.readDataToEndOfFile(); p.waitUntilExit()
    let s = String(data: data, encoding: .utf8) ?? ""
    return p.terminationStatus == 0 && s.contains("button returned:Approve") && !s.contains("gave up:true")
}

func connectSock(_ path: String) -> Int32 {
    signal(SIGPIPE, SIG_IGN)
    let s = socket(AF_UNIX, SOCK_STREAM, 0)
    var addr = sockaddr_un(); addr.sun_family = sa_family_t(AF_UNIX)
    let pb = Array(path.utf8)
    withUnsafeMutablePointer(to: &addr.sun_path) {
        $0.withMemoryRebound(to: CChar.self, capacity: pb.count + 1) { dst in
            for (i, b) in pb.enumerated() { dst[i] = CChar(bitPattern: b) }; dst[pb.count] = 0 }
    }
    let sz = socklen_t(MemoryLayout<sockaddr_un>.size)
    let rc = withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(s, $0, sz) } }
    return rc == 0 ? s : -1
}

public func runWrite(path: String, content: Data, sockPath: String = Paths.sock) -> Int32 {
    let fd = connectSock(sockPath)
    guard fd >= 0 else { FileHandle.standardError.write(Data("cc-fido: broker unreachable\n".utf8)); return 1 }
    defer { close(fd) }
    do {
        try sendMsg(fd, ["op": "execute-write", "path": path,
                         "content_b64": content.base64EncodedString(), "cwd": ""])
        let msg = try recvMsg(fd)
        guard msg["phase"] as? String == "challenge", let human = msg["human_rendering"] as? String,
              let chB64 = msg["challenge_b64"] as? String, let challenge = Data(base64Encoded: chB64) else {
            let reason = (msg["reason"] as? String) ?? "protocol error"
            FileHandle.standardError.write(Data("cc-fido: \(reason)\n".utf8)); return 1
        }
        if !dialog(human) { try sendMsg(fd, ["phase": "abort", "reason": "cancelled"]); return 1 }
        let sig: Data
        do { sig = try sign(challenge: challenge, handlePath: Paths.handle, namespace: Paths.namespace) }
        catch { try sendMsg(fd, ["phase": "abort", "reason": "sign failed"]); return 1 }
        try sendMsg(fd, ["phase": "signature", "signature_b64": sig.base64EncodedString()])
        let result = try recvMsg(fd)
        if result["status"] as? String == "ok" { print("cc-fido: wrote \(path)"); return 0 }
        FileHandle.standardError.write(Data("cc-fido: denied (\(result["reason"] ?? ""))\n".utf8)); return 1
    } catch { return 1 }
}
```

```swift
// Sources/cc-fido/main.swift
import Foundation
import CCFidoCore

let args = Array(CommandLine.arguments.dropFirst())
func usage() -> Never {
    FileHandle.standardError.write(Data("usage: cc-fido {daemon|hook|write <path>|enroll|install|enroll-file <path> [mode]|enroll-dir <path>}\n".utf8))
    exit(2)
}
guard let cmd = args.first else { usage() }
switch cmd {
case "daemon":
    try Broker().serve()
case "write":
    guard args.count >= 2 else { usage() }
    exit(runWrite(path: args[1], content: FileHandle.standardInput.readDataToEndOfFile()))
default:
    FileHandle.standardError.write(Data("cc-fido: unknown command \(cmd)\n".utf8)); exit(2)
}
```

- [ ] **Step 19: `[SW]` Build + run all software suites, then commit**

Run: `swift build && swift test`
Expected: Wire/Crypto/Canonical/BrokerAllowlist all pass.

```bash
git add Package.swift Sources Tests
git commit -m "feat(broker): walking-skeleton spine — allowlisted execute-write, keydir-temp verify, error-checked uchgWrite (SW-tested)"
```

- [ ] **Step 20: `[USER-RUN]` Bootstrap script** (reuses proven probes; the user runs it)

```bash
# tests/userrun/bootstrap.sh — one-time setup for the Task 1 e2e. Requires sudo + ONE enrollment touch.
#!/bin/bash
set -eu
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
SIGN=/opt/homebrew/opt/openssh/bin/ssh-keygen
sudo bash "$REPO/task0-broker/probes/account-setup.sh"
sudo mkdir -p /var/ccfido /var/ccfido-run
sudo chown _ccfido /var/ccfido /var/ccfido-run
sudo chmod 700 /var/ccfido ; sudo chmod 755 /var/ccfido-run
mkdir -p "$HOME/.ccfido" ; chmod 700 "$HOME/.ccfido"
echo ">>> TOUCH THE KEY WHEN IT BLINKS (enrollment) <<<"
"$SIGN" -t ed25519-sk -O application=ssh:cc-fido-gate -N '' -C 'cc-fido-broker' -f "$HOME/.ccfido/gate_sk"
chmod 600 "$HOME/.ccfido/gate_sk"
sudo sh -c "printf 'gate-principal %s\n' \"\$(cat '$HOME/.ccfido/gate_sk.pub')\" > /var/ccfido/allowed_signers"
sudo chown _ccfido /var/ccfido/allowed_signers ; sudo chmod 600 /var/ccfido/allowed_signers
# crown-jewel target OUTSIDE the keydir (isControlPath denies keydir targets) + register it in the allowlist.
# Same path task1_e2e.sh uses, so the enrolled-target write path is actually exercised.
TARGET=/Users/Shared/ccfido-target.txt
echo seed | sudo tee "$TARGET" >/dev/null
sudo chown _ccfido "$TARGET" ; sudo chflags uchg "$TARGET"
printf '{"files":["%s"],"dirs":[]}' "$TARGET" | sudo tee /var/ccfido/custody.json >/dev/null
sudo chown _ccfido /var/ccfido/custody.json ; sudo chmod 600 /var/ccfido/custody.json
echo "expect denied (keydir unreadable by sean):"; cat /var/ccfido/allowed_signers 2>&1 | head -1 || true
echo "bootstrap complete."
```

- [ ] **Step 21: `[USER-RUN]` Run the bootstrap** — `! bash tests/userrun/bootstrap.sh`
Expected: account created (or exists), one enrollment touch, `/Users/Shared/ccfido-target.txt` `uchg` + registered in `custody.json`, keydir read denied.

- [ ] **Step 22: `[USER-RUN]` e2e ceremony test**

```bash
# tests/userrun/task1_e2e.sh — daemon as _ccfido, client ceremony, ONE touch writes the enrolled target.
#!/bin/bash
set -u
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
TARGET=/Users/Shared/ccfido-target.txt
swift build -c release --package-path "$REPO"; BIN="$REPO/.build/release/cc-fido"
BEFORE=$(sudo cat "$TARGET" 2>/dev/null)
sudo -u _ccfido "$BIN" daemon & DPID=$!; sleep 1
echo ">>> APPROVE the dialog, then TOUCH the key <<<"
printf 'WRITTEN-BY-CEREMONY' | "$BIN" write "$TARGET"; RC=$?
sudo kill "$DPID" 2>/dev/null
AFTER=$(sudo cat "$TARGET" 2>/dev/null)
echo "before=$BEFORE after=$AFTER rc=$RC"
[ "$AFTER" = "WRITTEN-BY-CEREMONY" ] && echo "PASS: ceremony wrote through the uchg lock" || echo "FAIL"
echo "=== control-path denial (expect deny, no touch) ==="; printf 'x' | "$BIN" write /var/ccfido/allowed_signers
echo "=== unenrolled-path denial (expect deny) ==="; printf 'x' | "$BIN" write /tmp/not-enrolled
echo "=== audit tail ==="; sudo tail -3 /var/ccfido/audit.log
echo "=== target re-locked ==="; sudo ls -lO "$TARGET"
```

- [ ] **Step 23: `[USER-RUN]` Run the e2e** — `! bash tests/userrun/task1_e2e.sh`
Expected: dialog → Approve → touch → `PASS`; `allowed_signers` and `/tmp/not-enrolled` writes **denied without a touch prompt** (C-3); audit shows `write_ok` + two `deny_target`; target `uchg` again. Negative control: `echo x > "$TARGET"` → `Operation not permitted`.

- [ ] **Step 24: Commit** — `git add tests/userrun/bootstrap.sh tests/userrun/task1_e2e.sh && git commit -m "test(broker): e2e ceremony + allowlist/control-path denial harness (USER-RUN)"`

---

## Task 2: Canonicalization & softened WYSIWYS rendering

Add the **injective** `humanRendering` (design §"three artifacts"). Round-1 fix: `escapeConfusables` also escapes `<` (0x3C) so the literal string `<U+200B>` cannot collide with an escaped real U+200B; digest mode shows the **full** sha256. Fully `[SW]`.

**Files:** Modify `Sources/CCFidoCore/Canonical.swift`, `Sources/CCFidoCore/Broker.swift`; Test `Tests/CCFidoCoreTests/WysiwysTests.swift`

**Interfaces produced:** `humanRendering(_ doc: SignedDocument, content: Data) -> String`; `INLINE_MAX = 4096`.

- [ ] **Step 1: `[SW]` Failing tests**

```swift
// Tests/CCFidoCoreTests/WysiwysTests.swift
import XCTest
@testable import CCFidoCore

final class WysiwysTests: XCTestCase {
    private func doc(_ path: String, _ content: Data) -> SignedDocument {
        buildSignedDocument(op: "execute-write", path: path, contentSha256: sha256Hex(content),
                            cwd: "/tmp", nonceHex: "00", callerUid: 501)
    }
    func testHomoglyphPathsRenderDistinctly() {
        let a = humanRendering(doc("/Users/sean/.zshrc", Data("x".utf8)), content: Data("x".utf8))
        let b = humanRendering(doc("/Users/s\u{0435}an/.zshrc", Data("x".utf8)), content: Data("x".utf8))
        XCTAssertNotEqual(a, b)
    }
    func testZeroWidthEscaped() {
        let r = humanRendering(doc("/tmp/a\u{200B}b", Data("x".utf8)), content: Data("x".utf8))
        XCTAssertFalse(r.contains("\u{200B}")); XCTAssertTrue(r.contains("U+200B"))
    }
    func testEscapeIsInjective_literalAngleBracketDiffersFromRealZWS() {
        // real U+200B vs the literal characters "<U+200B>" must NOT render identically
        let real = humanRendering(doc("/tmp/a\u{200B}b", Data("x".utf8)), content: Data("x".utf8))
        let literal = humanRendering(doc("/tmp/a<U+200B>b", Data("x".utf8)), content: Data("x".utf8))
        XCTAssertNotEqual(real, literal)
    }
    func testTrailingWhitespaceSurfaced() {
        XCTAssertNotEqual(humanRendering(doc("/tmp/x", Data("cmd".utf8)), content: Data("cmd".utf8)),
                          humanRendering(doc("/tmp/x", Data("cmd ".utf8)), content: Data("cmd ".utf8)))
    }
    func testDigestModeFullHashNoContent() {
        let big = Data(repeating: 0x41, count: INLINE_MAX + 1)
        let r = humanRendering(doc("/tmp/big", big), content: big)
        XCTAssertTrue(r.contains(sha256Hex(big)))            // FULL 64-hex digest
        XCTAssertTrue(r.contains("\(big.count) bytes"))
        XCTAssertFalse(r.contains(String(repeating: "A", count: 50)))
    }
}
```

- [ ] **Step 2: `[SW]` Run — expect FAIL**. Run: `swift test --filter WysiwysTests`

- [ ] **Step 3: Implement `humanRendering` + escaping**

```swift
// add to Sources/CCFidoCore/Canonical.swift
public let INLINE_MAX = 4096

func escapeConfusables(_ s: String) -> String {
    var out = ""
    for scalar in s.unicodeScalars {
        let v = scalar.value
        let cat = scalar.properties.generalCategory
        let dangerous = v < 0x20 || v == 0x7f || v > 0x7e
            || cat == .format || cat == .lineSeparator || cat == .paragraphSeparator
            || (0x200b...0x200f).contains(v) || (0x202a...0x202e).contains(v)
        // Escape '<' too so the escape token "<U+XXXX>" cannot collide with literal input. (injectivity)
        if dangerous || v == 0x3c { out += String(format: "<U+%04X>", v) }
        else { out += String(scalar) }
    }
    return out
}
public func humanRendering(_ doc: SignedDocument, content: Data) -> String {
    let path = escapeConfusables(doc.path)
    let header = "\(doc.op.uppercased()) \(path)\ncwd: \(escapeConfusables(doc.cwd))"
    let tail = "\n\(content.count) bytes  sha256:\(doc.contentSha256)"   // FULL digest
    if content.count > INLINE_MAX { return "\(header)\n[digest mode — content not shown]\(tail)" }
    let body = String(data: content, encoding: .utf8).map(escapeConfusables) ?? "[binary, \(content.count) bytes]"
    return "\(header)\n---\n\(body)\n---\(tail)"
}
```

- [ ] **Step 4: `[SW]` Run — expect PASS** (5 passed)

- [ ] **Step 5: Wire the renderer into `Broker.handle`** — replace the inline `human_rendering` string with `humanRendering(doc, content: content)`; set `contentMode: content.count > INLINE_MAX ? "digest" : "inline"` in `buildSignedDocument`.

- [ ] **Step 6: `[SW]` Build + test — expect PASS**. Run: `swift build && swift test`

- [ ] **Step 7: Commit** — `git add Sources/CCFidoCore/Canonical.swift Sources/CCFidoCore/Broker.swift Tests/CCFidoCoreTests/WysiwysTests.swift && git commit -m "feat(canonical): injective WYSIWYS rendering (escapes '<', full digest)"`

---

## Task 3: Broker daemon hardening

Add the **`approve`** operation (best-effort verdict, no write) with a **compiling** canonicalization (C-2 fix via `canonicalJSON`), `verifyChain` for the audit log, and confirm the Task-1 threading (per-connection thread, **real watchdog-thread wall-clock cap** — not `SO_RCVTIMEO`, which is per-recv — and the `flock` that both serializes and protects the audit read-modify-write). Verify logic `[SW]`; socket + `uchg` behavior `[USER-RUN]`.

**Files:** Modify `Sources/CCFidoCore/{Broker,Audit,Client}.swift`; Test `Tests/CCFidoCoreTests/{Audit,BrokerLogic}Tests.swift`; Test (USER-RUN) `tests/userrun/task3_daemon.sh`

**Interfaces produced:** `Broker.decideApprove(_ req: [String:Any], caller: Int) throws -> (challengeB64: String, human: String)`; `auditVerifyChain(path:) -> Bool`; `runApprove(tool:toolInput:cwd:sockPath:) -> Bool`.

- [ ] **Step 1: `[SW]` Failing audit chain test**

```swift
// Tests/CCFidoCoreTests/AuditTests.swift
import XCTest
@testable import CCFidoCore

final class AuditTests: XCTestCase {
    private func tmp() -> String { NSTemporaryDirectory() + "audit-\(UUID().uuidString).log" }
    func testChainVerifiesFromFirstLine() throws {
        let p = tmp(); try auditAppend(["event": "a"], path: p); try auditAppend(["event": "b"], path: p)
        XCTAssertTrue(auditVerifyChain(path: p))   // no unchained prefix — chained from line 0
    }
    func testTamperBreaksChain() throws {
        let p = tmp(); try auditAppend(["event": "a"], path: p); try auditAppend(["event": "b"], path: p)
        var lines = try String(contentsOfFile: p, encoding: .utf8).split(separator: "\n").map(String.init)
        lines[0] = lines[0].replacingOccurrences(of: "\"a\"", with: "\"HACKED\"")
        try (lines.joined(separator: "\n") + "\n").write(toFile: p, atomically: true, encoding: .utf8)
        XCTAssertFalse(auditVerifyChain(path: p))
    }
}
```

- [ ] **Step 2: `[SW]` Run — expect FAIL** (`cannot find 'auditVerifyChain'`)

- [ ] **Step 3: Add `auditVerifyChain` to `Audit.swift`**

```swift
// add to Sources/CCFidoCore/Audit.swift
public func auditVerifyChain(path: String = Paths.audit) -> Bool {
    var prev = String(repeating: "0", count: 64)
    for (i, line) in auditLines(path).enumerated() {
        guard let obj = (try? JSONSerialization.jsonObject(with: Data(line.utf8))) as? [String: Any],
              obj["seq"] as? Int == i, obj["prev_hash"] as? String == prev else { return false }
        prev = sha256Hex(Data(line.utf8))
    }
    return true
}
```

- [ ] **Step 4: `[SW]` Run — expect PASS** (2 passed)

- [ ] **Step 5: `[SW]` Failing approve-logic test (compile guard for C-2)**

```swift
// Tests/CCFidoCoreTests/BrokerLogicTests.swift
import XCTest
@testable import CCFidoCore

final class BrokerLogicTests: XCTestCase {
    func testDecideApproveCompilesAndBindsInput() throws {
        let b = Broker()
        let d = try b.decideApprove(["op": "approve", "tool": "Bash",
                                     "input": ["command": "git push --force"], "cwd": "/tmp"], caller: 501)
        XCTAssertTrue(d.human.contains("git push --force"))
        XCTAssertFalse(d.challengeB64.isEmpty)
    }
    func testApproveChallengeIsDeterministicForSameInput() throws {
        // canonicalJSON sorts nested keys, so payload hash is stable regardless of dict order
        let a = try canonicalJSON(["tool": "Bash", "input": ["command": "x"], "cwd": "/"])
        let b = try canonicalJSON(["cwd": "/", "input": ["command": "x"], "tool": "Bash"])
        XCTAssertEqual(a, b)
    }
}
```

- [ ] **Step 6: `[SW]` Run — expect FAIL**

- [ ] **Step 7: Implement `decideApprove` + the `approve` branch in `Broker.handle`** (uses `canonicalJSON`, no `AnyHashable`)

```swift
// add to Broker (Sources/CCFidoCore/Broker.swift)
extension Broker {
    public func decideApprove(_ req: [String: Any], caller: Int) throws -> (challengeB64: String, human: String) {
        guard let tool = req["tool"] as? String else { throw WireError.badBody }
        let payload = try canonicalJSON(["tool": tool, "input": req["input"] ?? [:],
                                         "cwd": req["cwd"] as? String ?? ""])
        let doc = buildSignedDocument(op: "approve", path: tool, contentSha256: sha256Hex(payload),
                                      cwd: req["cwd"] as? String ?? "",
                                      nonceHex: (0..<16).map { _ in String(format:"%02x", UInt8.random(in:0...255)) }.joined(),
                                      callerUid: caller)
        // humanRendering already prints "APPROVE <tool>" (doc.op/doc.path) — don't double it (round-2 cosmetic).
        let human = humanRendering(doc, content: payload)
        return (try canonicalBytes(doc).base64EncodedString(), human)
    }
}
```

In `handle`, branch on `req["op"]`: for `"approve"`, call `decideApprove`, send the challenge, `recvMsg` the signature, `verify` against the SAME `challengeB64` (decoded), and on success `auditAppend(["event":"approve_ok",...])` + `{"status":"ok"}`; on failure deny. **No `uchgWrite`.** `execute-write` keeps the Task-1 allowlisted path. Unknown op → deny.

- [ ] **Step 8: Add `runApprove` to `Client.swift`**

```swift
// add to Sources/CCFidoCore/Client.swift
public func runApprove(tool: String, toolInput: [String: Any], cwd: String, sockPath: String = Paths.sock) -> Bool {
    let fd = connectSock(sockPath); guard fd >= 0 else { return false }
    defer { close(fd) }
    do {
        try sendMsg(fd, ["op": "approve", "tool": tool, "input": toolInput, "cwd": cwd])
        let msg = try recvMsg(fd)
        guard let human = msg["human_rendering"] as? String, let chB64 = msg["challenge_b64"] as? String,
              let challenge = Data(base64Encoded: chB64) else { return false }
        if !dialog(human) { try sendMsg(fd, ["phase": "abort", "reason": "cancelled"]); return false }
        let sig: Data
        do { sig = try sign(challenge: challenge, handlePath: Paths.handle, namespace: Paths.namespace) }
        catch { try sendMsg(fd, ["phase": "abort", "reason": "sign failed"]); return false }
        try sendMsg(fd, ["phase": "signature", "signature_b64": sig.base64EncodedString()])
        return (try recvMsg(fd))["status"] as? String == "ok"
    } catch { return false }
}
```

- [ ] **Step 9: `[SW]` Build + full suite — expect PASS**. Run: `swift build && swift test`

- [ ] **Step 10: `[USER-RUN]` Hardened-daemon test** (cancel→deny, approve op, DoS-resistance sanity, chain)

```bash
# tests/userrun/task3_daemon.sh
#!/bin/bash
set -u
REPO="$(cd "$(dirname "$0")/../.." && pwd)"; TARGET=/Users/Shared/ccfido-target.txt
swift build -c release --package-path "$REPO"; BIN="$REPO/.build/release/cc-fido"
sudo -u _ccfido "$BIN" daemon & DPID=$!; sleep 1
echo "=== cancel -> deny, target unchanged ==="; BEFORE=$(sudo cat "$TARGET")
echo ">>> CANCEL the dialog (do NOT touch) <<<"; printf 'NOPE' | "$BIN" write "$TARGET"; echo "rc=$?"
[ "$(sudo cat "$TARGET")" = "$BEFORE" ] && echo "PASS: cancel wrote nothing" || echo "FAIL"
echo "=== accept still serves after a slow client (DoS: per-conn thread) ==="
( sleep 30 | nc -U /var/ccfido-run/gate.sock ) &   # slow-loris one connection
sleep 1; echo ">>> APPROVE + TOUCH to prove a second client is NOT starved <<<"
printf 'WRITTEN-2' | "$BIN" write "$TARGET"; [ "$(sudo cat "$TARGET")" = "WRITTEN-2" ] && echo "PASS: not starved" || echo "FAIL"
sudo kill "$DPID" 2>/dev/null
echo "=== audit chain ==="; sudo -u _ccfido "$BIN" _verify-audit 2>/dev/null || echo "(add _verify-audit or check manually)"
```

Run (user): `! bash tests/userrun/task3_daemon.sh` — Expect `PASS: cancel wrote nothing`, `PASS: not starved`.

- [ ] **Step 11: Commit** — `git add Sources/CCFidoCore Tests/CCFidoCoreTests/AuditTests.swift Tests/CCFidoCoreTests/BrokerLogicTests.swift tests/userrun/task3_daemon.sh && git commit -m "feat(broker): approve op (canonicalJSON), verifyChain, per-conn thread + watchdog wall-clock cap"`

---

## Task 4: File & directory custody + the enrolled-target registry

The hard-guarantee enrollment surface (spec §2) **and the C-3 anchor**: `enroll-file`/`enroll-dir` write the `_ccfido`-owned `custody.json` the broker consults. `checkAncestors` now checks **writability** (mode bits) and uses `lstat` (no symlink follow), and **WARNS rather than refuses** on agent-owned ancestors (spec §2 concedes the parent-swap residual). Registry + plan logic `[SW]`; enforcement `[USER-RUN]`.

**Files:** Create `Sources/CCFidoCore/Custody.swift`; Test `Tests/CCFidoCoreTests/CustodyTests.swift`; Test (USER-RUN) `tests/userrun/task4_custody.sh`

**Interfaces produced:**
- `planEnrollFile(_ path: String, mode: Int) -> [[String]]`, `planEnrollDir(_ path: String) -> [[String]]`
- `checkAncestors(_ path: String, safeOwners: Set<Int>) -> [String]` (agent-writable ancestors; warn list)
- `CustodyRegistry.add(file: String?, dir: String?, path: String = Paths.custody) throws` — reads+updates the JSON registry
- `CustodyRegistry.load(path: String = Paths.custody) -> (files: [String], dirs: [String])`

- [ ] **Step 1: `[SW]` Failing tests**

```swift
// Tests/CCFidoCoreTests/CustodyTests.swift
import XCTest
import Foundation
@testable import CCFidoCore

final class CustodyTests: XCTestCase {
    func testPlanEnrollFile() {
        XCTAssertEqual(planEnrollFile("/tmp/x/.env", mode: 0o600), [
            ["/usr/sbin/chown", "_ccfido", "/tmp/x/.env"],
            ["/bin/chmod", "600", "/tmp/x/.env"],
            ["/usr/bin/chflags", "uchg", "/tmp/x/.env"]])
    }
    func testPlanEnrollDir() {
        XCTAssertEqual(planEnrollDir("/tmp/LA"), [
            ["/usr/sbin/chown", "_ccfido", "/tmp/LA"], ["/bin/chmod", "755", "/tmp/LA"]])
    }
    func testWritableAncestorDetected() throws {
        let base = NSTemporaryDirectory() + "cust-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: base + "/sub", withIntermediateDirectories: true)
        let target = base + "/sub/secret"; FileManager.default.createFile(atPath: target, contents: Data("x".utf8))
        XCTAssertTrue(checkAncestors(target, safeOwners: [0]).contains(base))
    }
    func testRegistryRoundTrip() throws {
        let p = NSTemporaryDirectory() + "custody-\(UUID().uuidString).json"
        try CustodyRegistry.add(file: "/a/b", dir: nil, path: p)
        try CustodyRegistry.add(file: nil, dir: "/c", path: p)
        let (files, dirs) = CustodyRegistry.load(path: p)
        XCTAssertEqual(files, ["/a/b"]); XCTAssertEqual(dirs, ["/c"])
    }
}
```

- [ ] **Step 2: `[SW]` Run — expect FAIL**

- [ ] **Step 3: Implement `Custody.swift`**

```swift
// Sources/CCFidoCore/Custody.swift
import Foundation
import Darwin

public func planEnrollFile(_ path: String, mode: Int) -> [[String]] {
    [["/usr/sbin/chown", "_ccfido", path], ["/bin/chmod", String(mode, radix: 8), path],
     ["/usr/bin/chflags", "uchg", path]]
}
public func planEnrollDir(_ path: String) -> [[String]] {
    [["/usr/sbin/chown", "_ccfido", path], ["/bin/chmod", "755", path]]
}
/// Ancestors NOT owned by a safe principal OR group/other-writable (agent could swap them). lstat: no follow.
public func checkAncestors(_ path: String, safeOwners: Set<Int>) -> [String] {
    var bad: [String] = []
    var cur = (path as NSString).deletingLastPathComponent
    while true {
        var st = stat()
        if lstat(cur, &st) == 0 {
            let unsafeOwner = !safeOwners.contains(Int(st.st_uid))
            let groupOtherWritable = (st.st_mode & (S_IWGRP | S_IWOTH)) != 0
            if unsafeOwner || groupOtherWritable { bad.append(cur) }
        } // Note: does not inspect ACLs — a documented residual (spec §2 parent-swap).
        if cur == "/" { break }
        let parent = (cur as NSString).deletingLastPathComponent
        if parent == cur { break }
        cur = parent
    }
    return bad
}
public enum CustodyRegistry {
    public static func load(path: String = Paths.custody) -> (files: [String], dirs: [String]) {
        guard let d = try? Data(contentsOf: URL(fileURLWithPath: path)),
              let o = (try? JSONSerialization.jsonObject(with: d)) as? [String: Any] else { return ([], []) }
        return (o["files"] as? [String] ?? [], o["dirs"] as? [String] ?? [])
    }
    public static func add(file: String?, dir: String?, path: String = Paths.custody) throws {
        var (files, dirs) = load(path: path)
        if let f = (file as NSString?)?.standardizingPath, !files.contains(f) { files.append(f) }
        if let d = (dir as NSString?)?.standardizingPath, !dirs.contains(d) { dirs.append(d) }
        let data = try JSONSerialization.data(withJSONObject: ["files": files, "dirs": dirs],
                                              options: [.sortedKeys])
        try data.write(to: URL(fileURLWithPath: path))
    }
}
```

*(Broker C-3 note: `loadRegistry()` in Task 1 returns `CustodyRegistry.load().files`; `execute-write` on a dir-custody target creates a file inside an enrolled dir — a Task-4 follow-on branch, out of the skeleton.)*

- [ ] **Step 4: `[SW]` Run — expect PASS** (4 passed)

- [ ] **Step 5: `[USER-RUN]` Enforcement test** (mirrors probe-q3; file + dir lock + owner-unlock)

```bash
# tests/userrun/task4_custody.sh
#!/bin/bash
set -u
D=$(mktemp -d); chmod 755 "$D"; FAILED=0     # 755 so sudo -u _ccfido can traverse (test-only)
pass(){ echo "  PASS: $1"; }; fail(){ echo "  FAIL: $1"; FAILED=1; }
echo original > "$D/secret"; sudo chown _ccfido "$D/secret"; sudo chflags uchg "$D/secret"
echo hostile > "$D/secret" 2>/dev/null && fail "wrote locked" || pass "write denied"
rm -f "$D/secret" 2>/dev/null && fail "deleted" || pass "unlink denied"
mv "$D/secret" "$D/s2" 2>/dev/null && fail "renamed" || pass "rename denied"
chflags nouchg "$D/secret" 2>/dev/null && fail "cleared uchg" || pass "nouchg denied"
sudo mkdir "$D/dir"; sudo chown _ccfido "$D/dir"; sudo chmod 755 "$D/dir"
touch "$D/dir/new" 2>/dev/null && fail "created in locked dir" || pass "create denied"
sudo -u _ccfido chflags nouchg "$D/secret" && pass "owner cleared uchg" || fail "owner blocked"
sudo chflags nouchg "$D/secret" 2>/dev/null; sudo rm -rf "$D"
[ "$FAILED" = 0 ] && echo "RESULT: GREEN" || echo "RESULT: RED"
```

Run (user): `! bash tests/userrun/task4_custody.sh` — Expect `RESULT: GREEN`.

- [ ] **Step 6: Commit** — `git add Sources/CCFidoCore/Custody.swift Tests/CCFidoCoreTests/CustodyTests.swift tests/userrun/task4_custody.sh && git commit -m "feat(custody): enrolled-target registry (C-3 anchor) + writability-aware ancestor check + enforcement test"`

---

## Task 5: Policy & gating tiers

The best-effort decision engine (spec §3). Round-1 fixes: **fail-closed parsing** (no `as!`, invalid regex → throw, not silent-drop), and `matchPath`/locked paths **realpath-normalized** so `/var`→`/private/var` can't downgrade a deny-nudge. Policy lives at the root-owned `POLICY = /opt/cc-fido-gate/policy.json` (hook-readable). Fully `[SW]`.

**Files:** Create `Sources/CCFidoCore/Policy.swift`, `install/policy.json`; Test `Tests/CCFidoCoreTests/PolicyTests.swift`

**Interfaces produced:** `Policy.Verdict {pass, gate, denyNudge}`; `Policy(sensitiveGlobs:allowTier:lockedPaths:bashAdvisory:mcpAllow:)`; `Policy.fromFile(_:) throws -> Policy`; `Policy.decide(tool:toolInput:cwd:) -> Verdict`; `matchPath(_:cwd:) -> String`.

- [ ] **Step 1: `[SW]` Failing tests** (same battery as before, plus a fail-closed load test)

```swift
// Tests/CCFidoCoreTests/PolicyTests.swift
import XCTest
@testable import CCFidoCore

final class PolicyTests: XCTestCase {
    let p = Policy(sensitiveGlobs: ["**/.env*", "**/.ssh/*", "**/id_*"], allowTier: ["/Users/sean/proj/**"],
                   lockedPaths: ["/var/ccfido/target.txt"], bashAdvisory: [#"git push .*(--force|-f)\b"#],
                   mcpAllow: [["gh", "list_prs"]])
    func testAllowTierPasses() { XCTAssertEqual(p.decide(tool: "Write", toolInput: ["file_path": "/Users/sean/proj/a.py"], cwd: "/Users/sean/proj"), .pass) }
    func testSensitiveWins() { XCTAssertEqual(p.decide(tool: "Write", toolInput: ["file_path": "/Users/sean/proj/.env"], cwd: "/Users/sean/proj"), .gate) }
    func testLockedDenyNudge() { XCTAssertEqual(p.decide(tool: "Write", toolInput: ["file_path": "/var/ccfido/target.txt"], cwd: "/"), .denyNudge) }
    func testOutsideGates() { XCTAssertEqual(p.decide(tool: "Edit", toolInput: ["file_path": "/etc/hosts"], cwd: "/"), .gate) }
    func testForcePushGates() { XCTAssertEqual(p.decide(tool: "Bash", toolInput: ["command": "git push --force"], cwd: "/"), .gate) }
    func testBenignBashPasses() { XCTAssertEqual(p.decide(tool: "Bash", toolInput: ["command": "ls -la"], cwd: "/"), .pass) }
    func testMcpAllowlisted() { XCTAssertEqual(p.decide(tool: "mcp__gh__list_prs", toolInput: [:], cwd: "/"), .pass) }
    func testMcpNotAllowlisted() { XCTAssertEqual(p.decide(tool: "mcp__gh__merge_pr", toolInput: [:], cwd: "/"), .gate) }
    func testHyphenatedServer() {
        let q = Policy(sensitiveGlobs: [], allowTier: [], lockedPaths: [], bashAdvisory: [], mcpAllow: [["my-server", "read_thing"]])
        XCTAssertEqual(q.decide(tool: "mcp__my-server__read_thing", toolInput: [:], cwd: "/"), .pass)
        XCTAssertEqual(q.decide(tool: "mcp__my-server__write_thing", toolInput: [:], cwd: "/"), .gate)
    }
    func testUnknownToolGates() { XCTAssertEqual(p.decide(tool: "NotebookEdit", toolInput: [:], cwd: "/"), .gate) }
    func testMissingBashCommandGatesNotPasses() { XCTAssertEqual(p.decide(tool: "Bash", toolInput: [:], cwd: "/"), .gate) }
    func testInvalidRegexInPolicyThrows() {
        XCTAssertThrowsError(try Policy.fromDict(["bash_advisory": ["("], "sensitive_globs": [], "allow_tier": [], "locked_paths": [], "mcp_allow": []]))
    }
}
```

- [ ] **Step 2: `[SW]` Run — expect FAIL**

- [ ] **Step 3: Implement `Policy.swift`** (fail-closed load; Bash missing-command → `.gate`)

```swift
// Sources/CCFidoCore/Policy.swift
import Foundation
import Darwin

public enum PolicyError: Error { case badRegex(String), badFile }

public func matchPath(_ path: String, cwd: String) -> String {
    let abs = (path as NSString).isAbsolutePath ? path : (cwd as NSString).appendingPathComponent(path)
    // realpath the existing ancestor so /var vs /private/var can't fork the match; append the lexical suffix.
    // (realpath already resolves symlinks in `dir`; do NOT pre-resolve with destinationOfSymbolicLink —
    // that returns a possibly-relative target and would be re-resolved against CWD. Round-2 fix.)
    let ns = (abs as NSString).standardizingPath
    var dir = (ns as NSString).deletingLastPathComponent
    let leaf = (ns as NSString).lastPathComponent
    var resolved = [Int8](repeating: 0, count: Int(PATH_MAX))
    if realpath(dir, &resolved) != nil { dir = String(cString: resolved) }
    return (dir as NSString).appendingPathComponent(leaf)
}
func globMatch(_ pattern: String, _ path: String) -> Bool { fnmatch(pattern, path, 0) == 0 }

public struct Policy {
    public enum Verdict { case pass, gate, denyNudge }
    let sensitiveGlobs, allowTier: [String]
    let lockedPaths: Set<String>
    let bashAdvisory: [NSRegularExpression]
    let mcpAllow: Set<[String]>
    public init(sensitiveGlobs: [String], allowTier: [String], lockedPaths: [String],
                bashAdvisory: [NSRegularExpression], mcpAllow: [[String]]) {
        self.sensitiveGlobs = sensitiveGlobs; self.allowTier = allowTier
        self.lockedPaths = Set(lockedPaths.map { matchPath($0, cwd: "/") })
        self.bashAdvisory = bashAdvisory; self.mcpAllow = Set(mcpAllow)
    }
    public init(sensitiveGlobs: [String], allowTier: [String], lockedPaths: [String],
                bashAdvisory: [String], mcpAllow: [[String]]) throws {
        let compiled = try bashAdvisory.map { s -> NSRegularExpression in
            do { return try NSRegularExpression(pattern: s) } catch { throw PolicyError.badRegex(s) } }
        self.init(sensitiveGlobs: sensitiveGlobs, allowTier: allowTier, lockedPaths: lockedPaths,
                  bashAdvisory: compiled, mcpAllow: mcpAllow)
    }
    public static func fromDict(_ d: [String: Any]) throws -> Policy {
        guard let sg = d["sensitive_globs"] as? [String], let at = d["allow_tier"] as? [String],
              let lp = d["locked_paths"] as? [String], let ba = d["bash_advisory"] as? [String],
              let ma = d["mcp_allow"] as? [[String]] else { throw PolicyError.badFile }
        return try Policy(sensitiveGlobs: sg, allowTier: at, lockedPaths: lp, bashAdvisory: ba, mcpAllow: ma)
    }
    public static func fromFile(_ path: String) throws -> Policy {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
              let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else { throw PolicyError.badFile }
        return try fromDict(obj)
    }
    func decideWrite(_ path: String, _ cwd: String) -> Verdict {
        let p = matchPath(path, cwd: cwd)
        if lockedPaths.contains(p) { return .denyNudge }
        if sensitiveGlobs.contains(where: { globMatch($0, p) }) { return .gate }
        if allowTier.contains(where: { globMatch($0, p) }) { return .pass }
        return .gate
    }
    func decideMcp(_ tool: String) -> Verdict {
        let parts = tool.components(separatedBy: "__")
        guard parts.count >= 3 else { return .gate }
        return mcpAllow.contains([parts[1], parts[2...].joined(separator: "__")]) ? .pass : .gate
    }
    public func decide(tool: String, toolInput: [String: Any], cwd: String) -> Verdict {
        switch tool {
        case "Write", "Edit": return decideWrite(toolInput["file_path"] as? String ?? "", cwd)
        case "Bash":
            guard let cmd = toolInput["command"] as? String else { return .gate }  // missing -> gate, not pass
            let r = NSRange(cmd.startIndex..., in: cmd)
            return bashAdvisory.contains { $0.firstMatch(in: cmd, range: r) != nil } ? .gate : .pass
        default: return tool.hasPrefix("mcp__") ? decideMcp(tool) : .gate
        }
    }
}
```

- [ ] **Step 4: `[SW]` Run — expect PASS**

- [ ] **Step 5: Write `install/policy.json`** (unchanged default set: `**/.env*`, `**/.ssh/id_*`, `**/.ssh/authorized_keys`, `**/*.pem`, `**/credentials*`; allow_tier `/Users/sean/proj/**`, `/Users/sean/sites/**`; bash force-push/`rm -rf`/deploy/kubectl-delete; `mcp_allow` `[["gh","list_prs"],["gh","get_issue"]]`; `locked_paths: []`).

- [ ] **Step 6: Commit** — `git add Sources/CCFidoCore/Policy.swift install/policy.json Tests/CCFidoCoreTests/PolicyTests.swift && git commit -m "feat(policy): fail-closed parse, realpath-normalized paths, gating tiers"`

---

## Task 6: Best-effort hook

The `PreToolUse` thin client (spec §3). Round-1 fix: `scrubEnv` is now the single source consumed by every child spawn (via `scrubbedEnv()` in `Crypto`/`Client`), and the hook loads policy from the **hook-readable** `/opt/cc-fido-gate/policy.json`. `.pass`→passthrough; `.denyNudge`→exit 2 nudge; `.gate`→`approve` ceremony; any error→exit 2. Logic `[SW]`; live-CC firing `[USER-RUN]`.

**Files:** Create `Sources/CCFidoCore/HookLogic.swift`; Modify `Sources/cc-fido/main.swift`; Test `Tests/CCFidoCoreTests/HookTests.swift`; Test (USER-RUN) `tests/userrun/task6_hook.sh`

**Interfaces produced:** `scrubEnv(_ env: [String:String]) -> [String:String]`; `decideAndEmit(event:policy:out:err:approve:) -> Int32`; `hookMain() -> Never`.

- [ ] **Step 1: `[SW]` Failing tests** (passthrough/deny-nudge/gate-allow/gate-deny/broker-error/scrub)

```swift
// Tests/CCFidoCoreTests/HookTests.swift
import XCTest
import Foundation
@testable import CCFidoCore

final class HookTests: XCTestCase {
    let pol = try! Policy(sensitiveGlobs: ["**/.env*"], allowTier: ["/Users/sean/proj/**"],
                          lockedPaths: ["/var/ccfido/target.txt"], bashAdvisory: [#"git push .*-f\b"#], mcpAllow: [])
    private func run(_ e: [String: Any], _ approve: @escaping (String, [String: Any], String) -> Bool)
        -> (Int32, String, String) {
        let o = Pipe(), er = Pipe()
        let c = decideAndEmit(event: e, policy: pol, out: o.fileHandleForWriting, err: er.fileHandleForWriting, approve: approve)
        try? o.fileHandleForWriting.close(); try? er.fileHandleForWriting.close()
        return (c, String(data: o.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? "",
                String(data: er.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? "")
    }
    private func ev(_ t: String, _ i: [String: Any], _ cwd: String = "/Users/sean/proj") -> [String: Any] {
        ["tool_name": t, "tool_input": i, "cwd": cwd]
    }
    func testPassthrough() { let r = run(ev("Write", ["file_path": "/Users/sean/proj/a.py"]), { _,_,_ in true }); XCTAssertEqual(r.0, 0); XCTAssertEqual(r.1, "") }
    func testDenyNudge() { let r = run(ev("Write", ["file_path": "/var/ccfido/target.txt"], "/"), { _,_,_ in true }); XCTAssertEqual(r.0, 2); XCTAssertTrue(r.2.contains("cc-fido write")) }
    func testGateAllows() { let r = run(ev("Write", ["file_path": "/Users/sean/proj/.env"]), { _,_,_ in true }); XCTAssertEqual(r.0, 0); XCTAssertTrue(r.1.contains("\"permissionDecision\":\"allow\"")) }
    func testGateDenies() { XCTAssertEqual(run(ev("Write", ["file_path": "/Users/sean/proj/.env"]), { _,_,_ in false }).0, 2) }
    func testBrokerErrorFailsClosed() { XCTAssertEqual(run(ev("Bash", ["command": "git push -f"], "/"), { _,_,_ in false }).0, 2) }
    func testScrubDrops() {
        let c = scrubEnv(["NODE_OPTIONS": "x", "DYLD_INSERT_LIBRARIES": "y", "SSH_SK_HELPER": "z", "BASH_ENV": "e", "PATH": "/evil", "HOME": "/Users/sean"])
        XCTAssertNil(c["NODE_OPTIONS"]); XCTAssertNil(c["DYLD_INSERT_LIBRARIES"]); XCTAssertNil(c["SSH_SK_HELPER"]); XCTAssertNil(c["BASH_ENV"])
        XCTAssertEqual(c["PATH"], "/usr/bin:/bin:/usr/sbin:/sbin"); XCTAssertEqual(c["HOME"], "/Users/sean")
    }
}
```

- [ ] **Step 2: `[SW]` Run — expect FAIL**

- [ ] **Step 3: Implement `HookLogic.swift`** (`scrubEnv` is the shared allowlist; `hookMain` uses it — see note)

```swift
// Sources/CCFidoCore/HookLogic.swift
import Foundation

let denyNudgeMsg = "cc-fido: this path is FIDO-locked. Use `cc-fido write <path>` (content on stdin) to change it — a physical touch is required."
let allowJSON = #"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","permissionDecisionReason":"cc-fido: touch verified"}}"#

/// Pure allowlist filter (unit-tested). The RUNTIME application is `scrubbedEnv()` in Crypto.swift,
/// which every child spawn (sign/verify/dialog) already sets as `Process.environment`. This function
/// is the same policy expressed over an arbitrary env dict, used where an explicit env must be built.
public func scrubEnv(_ env: [String: String]) -> [String: String] {
    var keep: [String: String] = [:]
    for k in ["HOME", "USER", "LANG", "__CF_USER_TEXT_ENCODING"] { if let v = env[k] { keep[k] = v } }
    keep["PATH"] = "/usr/bin:/bin:/usr/sbin:/sbin"
    return keep
}
public func decideAndEmit(event: [String: Any], policy: Policy, out: FileHandle, err: FileHandle,
                          approve: (String, [String: Any], String) -> Bool) -> Int32 {
    let tool = event["tool_name"] as? String ?? ""
    let input = event["tool_input"] as? [String: Any] ?? [:]
    let cwd = event["cwd"] as? String ?? ""
    switch policy.decide(tool: tool, toolInput: input, cwd: cwd) {
    case .pass: return 0
    case .denyNudge: err.write(Data((denyNudgeMsg + "\n").utf8)); return 2
    case .gate:
        if approve(tool, input, cwd) { out.write(Data((allowJSON + "\n").utf8)); return 0 }
        err.write(Data("cc-fido: touch not provided — denied\n".utf8)); return 2
    }
}
public func hookMain() -> Never {
    let data = FileHandle.standardInput.readDataToEndOfFile()
    guard let event = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else {
        FileHandle.standardError.write(Data("cc-fido: unreadable payload — failing closed\n".utf8)); exit(2)
    }
    guard let policy = try? Policy.fromFile(Paths.policy) else {
        FileHandle.standardError.write(Data("cc-fido: no policy — failing closed\n".utf8)); exit(2)
    }
    exit(decideAndEmit(event: event, policy: policy, out: FileHandle.standardOutput,
                       err: FileHandle.standardError) { t, i, c in runApprove(tool: t, toolInput: i, cwd: c) })
}
```

Add to `main.swift`: `case "hook": hookMain()`.

- [ ] **Step 4: `[SW]` Run — expect PASS** (6 passed)

- [ ] **Step 5: `[USER-RUN]` Live-hook test** (real CC, real touch; hook reads `/opt/cc-fido-gate/policy.json`)

```bash
# tests/userrun/task6_hook.sh
#!/bin/bash
set -u
REPO="$(cd "$(dirname "$0")/../.." && pwd)"; CLAUDE_BIN="${CLAUDE_BIN:-/Users/sean/.local/bin/claude}"
swift build -c release --package-path "$REPO"; BIN="$REPO/.build/release/cc-fido"
sudo mkdir -p /opt/cc-fido-gate; sudo cp "$REPO/install/policy.json" /opt/cc-fido-gate/policy.json
sudo chown root:wheel /opt/cc-fido-gate/policy.json; sudo chmod 644 /opt/cc-fido-gate/policy.json
mkdir -p /tmp/claude/ccfg-task6; D=$(mktemp -d /tmp/claude/ccfg-task6/run.XXXXXX)
cat > "$D/settings.json" <<JSON
{ "hooks": { "PreToolUse": [ { "matcher": "Write", "hooks": [ { "type": "command", "command": "$BIN hook", "timeout": 90 } ] } ] } }
JSON
sudo -u _ccfido "$BIN" daemon & DPID=$!; sleep 1
echo ">>> APPROVE + TOUCH when the dialog appears <<<"
"$CLAUDE_BIN" -p "Using the Write tool, create /tmp/claude/ccfg-task6/.env with contents FOO=bar, then stop." \
  --model claude-haiku-4-5-20251001 --settings "$D/settings.json" --dangerously-skip-permissions --allowedTools Write < /dev/null
[ -f /tmp/claude/ccfg-task6/.env ] && echo "PASS: gated write completed after touch" || echo "note: denied (expected if touch withheld)"
sudo kill "$DPID" 2>/dev/null
```

Run (user, sandbox OFF): `! bash tests/userrun/task6_hook.sh` — Expect dialog on the `.env` Write → touch → `PASS`.

- [ ] **Step 6: Commit** — `git add Sources/CCFidoCore/HookLogic.swift Sources/cc-fido/main.swift Tests/CCFidoCoreTests/HookTests.swift tests/userrun/task6_hook.sh && git commit -m "feat(hook): env scrub applied to all children, hook-readable policy, fail-closed"`

---

## Task 7: Install & enroll CLIs

The privileged one-time surface (spec §4). Round-1 fixes: `install`/`enroll`/`enroll-file`/`enroll-dir`/`_render-plist`/`_render-managed`/`_blink-test` now have **concrete dispatch cases**; `runPrivileged` **checks `terminationStatus`** and stops at first failure; `negativeBlinkTest` **terminates the leaked signer** before the positive control; CLI args are **bounds-checked**; `enroll-file` writes the custody registry; the acceptance example uses `~/Library/LaunchAgents` dir-custody (not a live ssh key). Helpers `[SW]`; installs `[USER-RUN]`.

**Files:** Create `Sources/CCFidoCore/CLIHelpers.swift`; Modify `Sources/cc-fido/main.swift`; Test `Tests/CCFidoCoreTests/CLIHelperTests.swift`; Test (USER-RUN) `tests/userrun/task7_install.sh`, `tests/userrun/task7_enroll.sh`

**Interfaces produced:** `renderPlist(binary:) -> String`; `renderManagedSettings(hookCmd:) -> String`; `ccVersion(_:) -> String`; `negativeBlinkTest(handle:namespace:window:) -> Bool`; `runPrivileged(_ argv: [String]) -> Bool`.

- [ ] **Step 1: `[SW]` Failing helper tests**

```swift
// Tests/CCFidoCoreTests/CLIHelperTests.swift
import XCTest
import Foundation
@testable import CCFidoCore

final class CLIHelperTests: XCTestCase {
    func testRenderPlist() {
        let xml = renderPlist(binary: "/opt/cc-fido-gate/cc-fido")
        XCTAssertTrue(xml.contains("<string>_ccfido</string>"))
        XCTAssertTrue(xml.contains("/opt/cc-fido-gate/cc-fido"))
        XCTAssertTrue(xml.contains("<string>daemon</string>"))
        XCTAssertTrue(xml.contains("com.cc-fido-gate.brokerd"))
    }
    func testRenderManaged() throws {
        let s = try JSONSerialization.jsonObject(with: Data(renderManagedSettings(hookCmd: "/opt/cc-fido-gate/cc-fido hook").utf8)) as! [String: Any]
        XCTAssertEqual(s["allowManagedHooksOnly"] as? Bool, true)
    }
}
```

- [ ] **Step 2: `[SW]` Run — expect FAIL**

- [ ] **Step 3: Implement `CLIHelpers.swift`**

```swift
// Sources/CCFidoCore/CLIHelpers.swift
import Foundation
import Darwin

public func renderPlist(binary: String = Paths.code + "/cc-fido") -> String {
    """
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0"><dict>
      <key>Label</key><string>com.cc-fido-gate.brokerd</string>
      <key>UserName</key><string>_ccfido</string>
      <key>ProgramArguments</key><array><string>\(binary)</string><string>daemon</string></array>
      <key>KeepAlive</key><true/>
      <key>RunAtLoad</key><true/>
      <key>StandardErrorPath</key><string>/var/ccfido/brokerd.err</string>
    </dict></plist>
    """
}
public func renderManagedSettings(hookCmd: String) -> String {
    let obj: [String: Any] = ["allowManagedHooksOnly": true,
        "hooks": ["PreToolUse": [["matcher": "Write|Edit|Bash|mcp__.*",
                                  "hooks": [["type": "command", "command": hookCmd, "timeout": 90]]]]]]
    return String(data: try! JSONSerialization.data(withJSONObject: obj, options: [.prettyPrinted, .sortedKeys]), encoding: .utf8)!
}
public func ccVersion(_ claudeBin: String) -> String {
    let p = Process(); p.executableURL = URL(fileURLWithPath: claudeBin); p.arguments = ["--version"]
    p.environment = scrubbedEnv()   // consistency: every spawned child is env-scrubbed
    let out = Pipe(); p.standardOutput = out; p.standardError = FileHandle.nullDevice
    do { try p.run() } catch { return "unknown" }
    let s = String(data: out.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""; p.waitUntilExit()
    if let m = s.range(of: #"\d+\.\d+\.\d+"#, options: .regularExpression) { return String(s[m]) }
    return "unknown"
}
@discardableResult
public func runPrivileged(_ argv: [String]) -> Bool {
    let p = Process(); p.executableURL = URL(fileURLWithPath: "/usr/bin/sudo"); p.arguments = argv
    do { try p.run() } catch { return false }
    p.waitUntilExit(); return p.terminationStatus == 0
}
/// Arm+withhold must NOT sign within `window`s; positive control (touch) must sign. Terminates the
/// leaked negative signer before the positive control so they don't contend for the device. USER-RUN.
public func negativeBlinkTest(handle: String, namespace: String, window: Int = 8) -> Bool {
    FileHandle.standardError.write(Data(">>> Do NOT touch the key for a few seconds <<<\n".utf8))
    let neg = Process(); neg.executableURL = URL(fileURLWithPath: Paths.signKeygen)
    neg.arguments = ["-Y", "sign", "-f", handle, "-n", namespace]; neg.environment = scrubbedEnv()
    let inP = Pipe(); neg.standardInput = inP
    neg.standardOutput = FileHandle.nullDevice; neg.standardError = FileHandle.nullDevice
    do { try neg.run() } catch { return false }
    inP.fileHandleForWriting.write(Data("negative-blink".utf8)); try? inP.fileHandleForWriting.close()
    let deadline = Date().addingTimeInterval(Double(window))
    while neg.isRunning && Date() < deadline { Thread.sleep(forTimeInterval: 0.2) }
    let signedWithoutTouch = !neg.isRunning && neg.terminationStatus == 0
    if neg.isRunning { neg.terminate() }; neg.waitUntilExit()   // reap the leaked signer
    if signedWithoutTouch { return false }                       // signed with NO touch -> not touch-required
    FileHandle.standardError.write(Data(">>> Now TOUCH the key (positive control) <<<\n".utf8))
    return (try? sign(challenge: Data("positive-control".utf8), handlePath: handle, namespace: namespace, retries: 1)) != nil
}
```

- [ ] **Step 4: `[SW]` Run — expect PASS** (2 passed)

- [ ] **Step 5: Add all dispatch cases to `main.swift`**

```swift
// Sources/cc-fido/main.swift — these three helpers go at FILE SCOPE (above the switch);
// the `case` blocks below are added to the existing switch.
func ccfidoUIDOr(_ fallback: Int) -> Int { getpwnam("_ccfido").map { Int($0.pointee.pw_uid) } ?? fallback }
func warnAncestors(_ path: String) {
    let w = checkAncestors(path, safeOwners: [0, ccfidoUIDOr(-1)])
    if !w.isEmpty { FileHandle.standardError.write(Data("cc-fido: WARNING agent-writable ancestors (parent-swap residual, spec §2): \(w)\n".utf8)) }
}
func enrollSteps(_ plan: [[String]]) {
    for a in plan where !runPrivileged(a) {
        FileHandle.standardError.write(Data("cc-fido: privileged step failed: \(a)\n".utf8)); exit(1)
    }
}
case "hook": hookMain()
case "_render-plist": print(renderPlist()); exit(0)
case "_render-managed": print(renderManagedSettings(hookCmd: Paths.code + "/cc-fido hook")); exit(0)
case "_blink-test":
    guard args.count >= 2 else { usage() }
    exit(negativeBlinkTest(handle: args[1], namespace: Paths.namespace) ? 0 : 1)
// runs AS _ccfido (via `sudo -u _ccfido`) so it can write the 0600 _ccfido-owned custody.json:
case "_registry-add":
    guard args.count >= 3, args[1] == "file" || args[1] == "dir" else { usage() }
    do {
        try CustodyRegistry.add(file: args[1] == "file" ? args[2] : nil,
                                dir: args[1] == "dir" ? args[2] : nil)
        exit(0)
    } catch {
        FileHandle.standardError.write(Data("cc-fido: registry add failed: \(error)\n".utf8)); exit(1)
    }
// on registry-add failure, undo the lock so the file returns to its pre-enroll (usable) state.
// Restores the CAPTURED original uid (not an assumed one), and reports whether every step succeeded.
func rollbackFileLock(_ path: String, toUID uid: UInt32) {
    let unlocked = runPrivileged(["/usr/bin/chflags", "nouchg", path])
    let chowned = runPrivileged(["/usr/sbin/chown", String(uid), path])
    if unlocked && chowned {
        FileHandle.standardError.write(Data("cc-fido: rolled back lock on \(path)\n".utf8))
    } else {
        FileHandle.standardError.write(Data("cc-fido: ROLLBACK INCOMPLETE on \(path) (nouchg=\(unlocked) chown=\(chowned)) — the file may still be _ccfido-owned/locked; fix manually\n".utf8))
    }
}
case "enroll-file":
    guard args.count >= 2 else { usage() }
    let path = (args[1] as NSString).standardizingPath
    let mode = args.count > 2 ? (Int(args[2], radix: 8) ?? 0o600) : 0o600
    warnAncestors(path)
    var pre = stat(); let origUID = (lstat(path, &pre) == 0) ? pre.st_uid : getuid()  // capture owner BEFORE enroll
    // Lock FIRST, then register. This ordering fails SAFE: a registry failure leaves the file
    // locked-but-unregistered (over-protected, `cc-fido write` won't touch it) — never
    // registered-but-writable (which would advertise protection it doesn't have). We roll the lock back.
    enrollSteps(planEnrollFile(path, mode: mode))
    if !runPrivileged(["-u", "_ccfido", Paths.code + "/cc-fido", "_registry-add", "file", path]) {
        rollbackFileLock(path, toUID: origUID)
        FileHandle.standardError.write(Data("cc-fido: registry add failed for \(path)\n".utf8)); exit(1)
    }
    print("cc-fido: enrolled + registered file \(path)"); exit(0)
case "enroll-dir":
    guard args.count >= 2 else { usage() }
    let path = (args[1] as NSString).standardizingPath
    warnAncestors(path)
    enrollSteps(planEnrollDir(path))
    if !runPrivileged(["-u", "_ccfido", Paths.code + "/cc-fido", "_registry-add", "dir", path]) {
        FileHandle.standardError.write(Data("cc-fido: registry add failed for \(path); dir remains _ccfido-owned — re-run enroll-dir to register\n".utf8)); exit(1)
    }
    print("cc-fido: enrolled + registered dir \(path)"); exit(0)
```

*(`_registry-add` runs as `_ccfido` — `runPrivileged` shells `sudo -u _ccfido <binary> _registry-add …`, and `CustodyRegistry.add` (Task 4) reads+updates the `0600` `custody.json`. Lock-first-then-register fails safe (over-protect, never under-protect); a file registry failure rolls the lock back. `install`/`enroll` remain USER-RUN orchestration scripts, Task 7 Steps 7–8.)*

- [ ] **Step 6: `[SW]` Build + full suite, commit code** — `swift build && swift test` (all green), then `git add Sources Tests/CCFidoCoreTests/CLIHelperTests.swift && git commit -m "feat(cli): install/enroll/render/blink-test dispatch, checked runPrivileged, reaped blink signer"`

- [ ] **Step 7: `[USER-RUN]` Install script** (codesign, managed-settings, root-owned policy, canary, ≥1-key gate)

```bash
# tests/userrun/task7_install.sh — full privileged install + canary. Requires sudo.
#!/bin/bash
set -eu -o pipefail
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
swift build -c release --package-path "$REPO"; BIN="$REPO/.build/release/cc-fido"
sudo bash "$REPO/task0-broker/probes/account-setup.sh"
sudo mkdir -p /opt/cc-fido-gate /var/ccfido /var/ccfido-run "/Library/Application Support/ClaudeCode"
sudo cp "$BIN" /opt/cc-fido-gate/cc-fido
sudo codesign --force --options runtime --sign - /opt/cc-fido-gate/cc-fido
sudo cp "$REPO/install/policy.json" /opt/cc-fido-gate/policy.json
sudo chown -R root:wheel /opt/cc-fido-gate; sudo chmod 755 /opt/cc-fido-gate; sudo chmod 644 /opt/cc-fido-gate/policy.json
sudo chown _ccfido /var/ccfido /var/ccfido-run; sudo chmod 700 /var/ccfido; sudo chmod 755 /var/ccfido-run
# Prereqs are now installed. Break the install<->enroll circularity: if no key is enrolled yet, STOP here
# with instructions (exit 0, not a hard refusal) — enroll needs the account+dirs we just created; the
# daemon is only activated on a re-run once a key exists.
/opt/cc-fido-gate/cc-fido _render-plist | sudo tee /Library/LaunchDaemons/com.cc-fido-gate.brokerd.plist >/dev/null
/opt/cc-fido-gate/cc-fido _render-managed | sudo tee "/Library/Application Support/ClaudeCode/managed-settings.json" >/dev/null
/opt/cc-fido-gate/cc-fido --version 2>/dev/null | sudo tee /var/ccfido/cc-version >/dev/null || true
if ! sudo test -s /var/ccfido/allowed_signers; then
  echo "Prereqs installed. Next: run  bash tests/userrun/task7_enroll.sh  to enroll a key, then re-run THIS script to activate the daemon."
  exit 0
fi
sudo launchctl bootstrap system /Library/LaunchDaemons/com.cc-fido-gate.brokerd.plist
sleep 1
echo "=== CANARY: the BROKER must deny an execute-write to a control path (NON-destructive) ==="
# Drives the broker as the agent uid; the daemon denies control paths BEFORE any dialog/write.
# Capture separately so pipefail can't misread cc-fido's (correct) non-zero deny exit as a canary failure.
CANARY_OUT=$(printf 'x' | /opt/cc-fido-gate/cc-fido write /var/ccfido/allowed_signers 2>&1 || true)
echo "$CANARY_OUT" | grep -qi 'deny\|not an enrolled' \
  && echo "PASS: broker denied control-path write" \
  || { echo "FAIL: broker did not deny control path — ABORTING"; echo "$CANARY_OUT"; exit 1; }
sudo test -s /var/ccfido/allowed_signers \
  && echo "PASS: allowed_signers intact" \
  || { echo "FAIL: trust store damaged — ABORTING"; exit 1; }
echo "=== install complete ==="
```

*(`set -o pipefail` guards the `_render-*` pipelines. The canary is **non-destructive** (no `sudo tee` over the trust store — the round-2 CRITICAL) and now captures the write's output separately so `pipefail` can't turn `cc-fido write`'s correct non-zero deny into a false canary FAIL (round-3 codex HIGH); a real failure `exit 1`s the install. The `exit 0` prereqs-only path breaks the install↔enroll circularity: run install → enroll → re-run install to activate.)*

Run (user): `! bash tests/userrun/task7_install.sh` — Expect refusal until a key is enrolled, then codesigned binary + daemon booted.

- [ ] **Step 8: `[USER-RUN]` Enroll script** (2 dedicated keys, negative blink-test)

```bash
# tests/userrun/task7_enroll.sh
#!/bin/bash
set -eu
REPO="$(cd "$(dirname "$0")/../.." && pwd)"; SIGN=/opt/homebrew/opt/openssh/bin/ssh-keygen
swift build -c release --package-path "$REPO"; BIN="$REPO/.build/release/cc-fido"
mkdir -p "$HOME/.ccfido"; chmod 700 "$HOME/.ccfido"
for n in 1 2; do
  echo ">>> TOUCH to enroll key #$n <<<"
  "$SIGN" -t ed25519-sk -O application=ssh:cc-fido-gate -N '' -C "cc-fido-key$n" -f "$HOME/.ccfido/gate_sk$n"
  chmod 600 "$HOME/.ccfido/gate_sk$n"
  sudo sh -c "printf 'gate-principal %s\n' \"\$(cat '$HOME/.ccfido/gate_sk$n.pub')\" >> /var/ccfido/allowed_signers"
done
ln -sf "$HOME/.ccfido/gate_sk1" "$HOME/.ccfido/gate_sk"
sudo chown _ccfido /var/ccfido/allowed_signers; sudo chmod 600 /var/ccfido/allowed_signers
echo "=== negative blink-test (key #1) ==="
"$BIN" _blink-test "$HOME/.ccfido/gate_sk1" && echo "PASS: touch-required verified" || echo "FAIL"
```

Run (user): `! bash tests/userrun/task7_enroll.sh` — Expect 2 touches; withhold→no sig, touch→signs → `PASS`.

- [ ] **Step 9: Commit** — `git add tests/userrun/task7_install.sh tests/userrun/task7_enroll.sh && git commit -m "feat(cli): USER-RUN install (pipefail, key-gated, codesigned) + enroll (blink-test) scripts"`

- [ ] **Step 10: `[USER-RUN]` Full-system acceptance + teardown**

End-to-end once: install → enroll → `cc-fido enroll-dir ~/Library/LaunchAgents` (dir-custody of the design's named primary adversary path; **not** a live ssh key — those are credential-custody, out of scope) → confirm the agent-uid **cannot create** a new plist there (`touch ~/Library/LaunchAgents/x.plist` → `Operation not permitted`) → enroll a benign protected file and prove `cc-fido write` succeeds after a touch while a direct write gives `EACCES` → prove `cc-fido write /var/ccfido/allowed_signers` is **denied with no touch prompt** (C-3). Then teardown (`task0-broker/probes/account-teardown.sh` + remove `/var/ccfido*`, `/opt/cc-fido-gate`, plist, managed-settings). Record in `task7/REPORT.md`; confirm `auditVerifyChain` passes.

```bash
git add task7/REPORT.md && git commit -m "docs(v2): full-system acceptance report + teardown"
```

---

## Self-Review

**Spec coverage:** partner 1 (hard file lock + registry) → Tasks 1, 4; partner 2 (hook) → Tasks 5, 6; softened dialog/WYSIWYS → Tasks 1(argv dialog), 2; §1 ceremony (client sign / daemon verify, two ops, serialization, per-conn watchdog, LOCAL_PEERCRED, device-busy retry, hardened runtime) → Tasks 1, 3, 7; §2 file/dir custody + registry + ancestor warn + legit-writer caveat → Task 4, Global Constraints; §3 managed-settings, env scrub applied, tiers, deny-nudge → Tasks 5, 6, 7; §4 install (pipefail canary, ≥1-key gate, version record) + enroll (blink-test, 2 keys) → Task 7; §5 threat model incl. **C-3 target allowlist + control-file denylist** and O_NOFOLLOW → Tasks 1, 4; injective rendering → Task 2.

**Round-1 findings resolved:** verify() keydir-temp (C-1); decideApprove/canonicalJSON (C-2); execute-write allowlist + control denylist (C-3); scrubEnv applied to all children (M); O_NOFOLLOW + fstat in uchgWrite (M); hook policy relocated (M); uchgWrite full error handling + guaranteed relock (M); install/enroll/render/blink dispatch (M); per-conn thread + SIGPIPE ignore + checked socket (M); audit chained from line 0 (M); peerUID −1 sentinel; checkAncestors writability/lstat + warn-not-refuse + enroll-dir; injective renderer escapes `<` + full digest; osascript argv form; removed probe-"0.6" claim; fail-closed policy parse; loadUnaligned + EINTR; realpath-normalized paths; CLI bounds checks; reaped blink signer; checked runPrivileged; acceptance example → LaunchAgents dir-custody.

**Round-2 findings resolved:** removed the destructive install "canary" (CRITICAL); real watchdog-thread wall-clock cap replacing the false "absolute" `SO_RCVTIMEO` claim + `flock`/audit-serialization note (MAJOR); concrete `_registry-add` subcommand (HIGH); `uchgWrite` checks the relock return + `st_nlink==1`/owner guard (HIGH); `verify()` `EINTR`/`close` (MEDIUM); bootstrap/e2e target unified (MEDIUM); `ccVersion` scrubbed; `matchPath` relative-symlink step removed; approve rendering de-duplicated.

**Round-3 findings resolved (the write primitive, cross-confirmed by codex + pentester + fable):**
- **`uchgWrite` no longer `O_TRUNC`s before validating** — it opens `O_WRONLY|O_CREAT|O_NOFOLLOW` (no `O_TRUNC`), runs the full `fstat`+`F_GETPATH` guard, and only then `ftruncate`s. A redirect can no longer truncate the target before the check (codex CRITICAL).
- **`F_GETPATH` post-open re-check** re-runs `isControlPath`/`isEnrolledTarget` on the *actually-opened* (fully symlink-resolved) path → closes the **intermediate-directory-symlink redirect** onto a keydir control file that `O_NOFOLLOW` (final-component only) and `st_uid`/`st_nlink` could not (pentester HIGH — the `audit.log`/`allowed_signers` basename-collision → C-1-restore vector). The "chflags follows symlinks is a mere nuisance" claim was **wrong** and is retracted.
- **`canonPath` regression reverted** → `normPath` (standardize + strip the `/private` firmlink prefix), applied consistently to `isControlPath`, `isEnrolledTarget`, and `norm`, with an `[SW]` test that folds `/private/var`. Fixes the silent over-deny of enrolled targets under `/var`/`/tmp`/`/etc` and restores the denylist in production (fable + codex HIGH).
- **owner check is fail-closed** (refuse if `getpwnam("_ccfido")` fails, was fail-open); **install canary `pipefail` bug fixed** (output captured separately; a real failure `exit 1`s) (codex HIGH); **install↔enroll circularity broken** (install installs prereqs and exits 0 with instructions if no key; re-run activates) (codex HIGH); **enroll-file rolls the lock back** on registry-add failure (lock-first-then-register fails safe) (codex HIGH).

**Verification-pass fixes (post-round-3):** `normPath` now folds **only** the real firmlinked roots (`/var`,`/etc`,`/tmp`), not every `/private/*` (codex-verify HIGH — `/private/foo`↛`/foo`); `rollbackFileLock` captures the pre-enrollment owner and reports incomplete rollback instead of always claiming success (codex-verify MEDIUM). Write primitive, canary, and install/enroll sequencing verified correct by codex-verify + fable-verify (fable ran `normPath` under swiftc, 21/21).

**Known-minor deferred:** on the success path, if the final `relock()` fails *after* the bytes landed, the daemon reports `deny`/`write_error` even though the write committed (the file is left unlocked with new content — relock failure by the owner is near-impossible; consider a distinct `write_ok_unlocked` audit event) (fable-verify). `auditVerifyChain` returns true for an empty log (valid empty chain) — Task-7 acceptance must *also* assert a `write_ok` event is present. Watchdog fd-reuse boundary race (fable MINOR): if `handle()` finishes in the sub-ms instant around T0+90, the watchdog could `shutdown` a reused fd → aborts one unrelated ceremony (fails closed); narrow, noted for the implementer. **Acknowledged availability residual (pentester-verify):** on the escape-abort path, `chflags(norm,0)`/relock follow an intermediate symlink and can leave a redirected `_ccfido`-owned control file (e.g. `/var/ccfido/audit.log`) `UF_IMMUTABLE` — a **persistent availability DoS** (subsequent `auditAppend` `open O_APPEND` → `EPERM`, bricking write ceremonies until a manual `sudo chflags nouchg`). It has **zero integrity/C-1 impact** (toggles the flag, never writes content) and needs a coaxed touch (NEW-2 territory). Clean mitigation (`open O_RDONLY` → `F_GETPATH`-validate → `fchflags(fd,0)` on the validated inode) is available but not warranted for a touch-gated availability-only residual; noted for the implementer. The `real == norm` post-open guard now also closes the enrolled→enrolled basename-collision redirect that was the conceded NEW-1 ancestor-swap TOCTOU (spec §2), so a coaxed touch can no longer even land a legit write on the wrong enrolled file.

**Deferred (spec-declared out of scope):** credential-custody, MCP-proxy custody, setuid-root signer, CC-version auto-re-probe daemon, dir-custody `execute-write` create-branch (registry supports it; skeleton writes files), ACL inspection in `checkAncestors` (documented residual).

**Placeholder scan:** each code step shows complete Swift; each test step complete assertions. The `install`/`enroll`/`_registry-add` orchestration is expressed as concrete dispatch cases + the USER-RUN scripts that drive them.

**Type consistency:** `Policy.Verdict/decide/fromFile/fromDict`, `Broker.{normPath,decideApprove,handle,serve,uchgWrite(path,content,registry),isControlPath,isEnrolledTarget,loadRegistry}`, `sign/verify` (keydir param), `SignedDocument/buildSignedDocument/canonicalBytes/canonicalJSON/humanRendering`, `auditAppend/auditVerifyChain`, `CustodyRegistry.{add,load}/planEnroll*/checkAncestors`, `runWrite/runApprove`, `scrubEnv/decideAndEmit/hookMain`, `renderPlist/renderManagedSettings/ccVersion/negativeBlinkTest/runPrivileged` — signatures match across producing and consuming tasks.

---

## Execution Handoff

1. **Subagent-Driven (recommended)** — fresh subagent per task, two-stage review between tasks. Subagents run `[SW]` steps (`swift test`) only; every `[USER-RUN]` step (sudo/hardware) is handed to the user to run un-sandboxed (`! bash …`) and pasted back before the task is marked done.
2. **Inline Execution** — batch tasks with checkpoints.
