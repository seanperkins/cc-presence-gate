# Configurable Install Policy — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the cc-fido-gate hook policy admin-configurable and portable at install time — no hardcoded machine paths, a safe default that still gates code-exec/persistence paths, and a fail-closed validate/render path — without weakening the touch-gate.

**Architecture:** Add two thin `cc-fido` subcommands over `CCFidoCore` — `_validate-policy <path>` (read-only check: summary + lint) and `_render-policy <src> <home>` (JSON-safe `__HOME__` substitution + `$HOME` guard + validate + lint, emit on success only). The install scripts pipe `_render-policy`'s output into a **root-owned** candidate and `sudo mv` it atomically into place. `Policy` gains a `public summary()`/`lint()` API, stricter `mcp_allow` validation, and named parse errors.

**Tech Stack:** Swift (SwiftPM: `swift build`, `swift test`), Foundation `JSONSerialization`, POSIX `realpath`/`fnmatch`, bash install scripts.

**Spec:** `docs/superpowers/specs/2026-07-17-configurable-install-policy-design.md`

## Global Constraints

- The installed policy `/opt/cc-fido-gate/policy.json` is a **security control** — every change is fail-closed: on any error, gate/deny, never pass, and never clobber a good installed policy.
- The final installed policy stays **root-owned, 0644**, and is on the broker `controlDenylist` (`Sources/CCFidoCore/Paths.swift:19`) — unchanged.
- No new third-party dependencies.
- Conventional commits, committed directly to `main` (repo pattern). Commit per task.
- Run `swift test` (full suite) before every commit; it must stay green (currently 50 tests).
- `Policy` verdict order is load-bearing and unchanged: `locked_paths`→deny, `sensitive_globs`→gate, `allow_tier`→pass, else→gate (`Policy.swift:52-58`); `sensitive_globs` is checked before `allow_tier`.

---

### Task 1: `Policy` — `summary()`, `lint()`, stricter `mcp_allow`, named parse errors

**Files:**
- Modify: `Sources/CCFidoCore/Policy.swift`
- Test: `Tests/CCFidoCoreTests/PolicyTests.swift`

**Interfaces:**
- Consumes: existing `Policy.init`, `Policy.fromDict`, `Policy.decideWrite`.
- Produces:
  - `public func summary() -> String`
  - `public func lint() -> (fatal: [String], warnings: [String])`
  - `PolicyError.badFile(String)` (was `badFile` with no payload)
  - `Policy.fromDict` now throws on `mcp_allow` entries whose element count ≠ 2.

- [ ] **Step 1: Write failing tests**

Add to `Tests/CCFidoCoreTests/PolicyTests.swift` (inside the class):
```swift
    // --- widened-default gating verdicts (the feature's core behavior) ---
    let d = Policy(sensitiveGlobs: ["**/.env*", "**/.ssh/*", "**/.zshrc",
                                    "**/Library/LaunchAgents/*", "**/.git/hooks/*", "**/.gitconfig"],
                   allowTier: ["/Users/x/**"], lockedPaths: [], bashAdvisory: [], mcpAllow: [])
    func testHomeWritePasses() { XCTAssertEqual(d.decide(tool: "Write", toolInput: ["file_path": "/Users/x/proj/a.swift"], cwd: "/Users/x"), .pass) }
    func testOutsideHomeGates() { XCTAssertEqual(d.decide(tool: "Write", toolInput: ["file_path": "/etc/hosts"], cwd: "/"), .gate) }
    func testEnvInHomeGates() { XCTAssertEqual(d.decide(tool: "Write", toolInput: ["file_path": "/Users/x/proj/.env"], cwd: "/Users/x"), .gate) }
    func testZshrcGates() { XCTAssertEqual(d.decide(tool: "Edit", toolInput: ["file_path": "/Users/x/.zshrc"], cwd: "/Users/x"), .gate) }
    func testLaunchAgentGates() { XCTAssertEqual(d.decide(tool: "Write", toolInput: ["file_path": "/Users/x/Library/LaunchAgents/e.plist"], cwd: "/Users/x"), .gate) }
    func testGitHookGates() { XCTAssertEqual(d.decide(tool: "Write", toolInput: ["file_path": "/Users/x/proj/.git/hooks/pre-commit"], cwd: "/Users/x"), .gate) }

    // --- summary ---
    func testSummaryCounts() {
        XCTAssertEqual(p.summary(), "policy OK: 3 sensitive, 1 allow, 1 locked, 1 bash, 1 mcp")
    }

    // --- lint: fatal blanket grants (exact match) ---
    func testLintBlanketFatal() {
        for g in ["**", "/**", "*", "/*"] {
            let q = Policy(sensitiveGlobs: [], allowTier: [g], lockedPaths: [], bashAdvisory: [], mcpAllow: [])
            XCTAssertFalse(q.lint().fatal.isEmpty, "expected \(g) to be fatal")
        }
    }
    func testLintDefaultShapeNotFatalNoWarn() {   // MAJOR-3 anti-regression: /Users/x/** must NOT trip the blanket lint
        let q = Policy(sensitiveGlobs: ["**/.env*", "**/.ssh/*", "**/.zshrc"], allowTier: ["/Users/x/**"],
                       lockedPaths: [], bashAdvisory: [], mcpAllow: [])
        XCTAssertTrue(q.lint().fatal.isEmpty)
    }

    // --- stricter mcp_allow arity ---
    func testBadMcpTupleThrows() {
        XCTAssertThrowsError(try Policy.fromDict(["mcp_allow": [["only-one"]], "sensitive_globs": [], "allow_tier": [], "locked_paths": [], "bash_advisory": []]))
        XCTAssertThrowsError(try Policy.fromDict(["mcp_allow": [["a", "b", "c"]], "sensitive_globs": [], "allow_tier": [], "locked_paths": [], "bash_advisory": []]))
    }

    // --- named parse errors ---
    func testMissingKeyErrorNamesIt() {
        do { _ = try Policy.fromDict(["sensitive_globs": [], "allow_tier": [], "locked_paths": [], "mcp_allow": []]) ; XCTFail("expected throw") }
        catch PolicyError.badFile(let why) { XCTAssertTrue(why.contains("bash_advisory")) }
        catch { XCTFail("wrong error: \(error)") }
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `swift test --filter PolicyTests 2>&1 | tail -20`
Expected: FAIL — `summary`/`lint` not members of `Policy`; `badFile` has no associated value; mcp-arity and missing-key tests fail.

- [ ] **Step 3: Implement in `Policy.swift`**

Change the error enum (line 4):
```swift
public enum PolicyError: Error { case badRegex(String), badFile(String) }
```

Replace `fromDict` (lines 37-46) with per-key checks + mcp arity:
```swift
    public static func fromDict(_ d: [String: Any]) throws -> Policy {
        guard let sg = d["sensitive_globs"] as? [String] else { throw PolicyError.badFile("'sensitive_globs' missing or not a string array") }
        guard let at = d["allow_tier"] as? [String] else { throw PolicyError.badFile("'allow_tier' missing or not a string array") }
        guard let lp = d["locked_paths"] as? [String] else { throw PolicyError.badFile("'locked_paths' missing or not a string array") }
        guard let ba = d["bash_advisory"] as? [String] else { throw PolicyError.badFile("'bash_advisory' missing or not a string array") }
        guard let ma = d["mcp_allow"] as? [[String]] else { throw PolicyError.badFile("'mcp_allow' missing or not an array of string arrays") }
        for entry in ma where entry.count != 2 { throw PolicyError.badFile("mcp_allow entry \(entry) must be exactly [server, tool]") }
        for s in ba {   // fail-closed: validate every regex before construction
            do { _ = try NSRegularExpression(pattern: s) } catch { throw PolicyError.badRegex(s) }
        }
        return Policy(sensitiveGlobs: sg, allowTier: at, lockedPaths: lp, bashAdvisory: ba, mcpAllow: ma)
    }
```

Replace `fromFile` (lines 47-51) with error-carrying reads:
```swift
    public static func fromFile(_ path: String) throws -> Policy {
        let data: Data
        do { data = try Data(contentsOf: URL(fileURLWithPath: path)) }
        catch { throw PolicyError.badFile("cannot read \(path): \(error.localizedDescription)") }
        let obj: Any
        do { obj = try JSONSerialization.jsonObject(with: data) }
        catch { throw PolicyError.badFile("invalid JSON in \(path): \(error.localizedDescription)") }
        guard let dict = obj as? [String: Any] else { throw PolicyError.badFile("\(path): top-level JSON must be an object") }
        return try fromDict(dict)
    }
```

Add `summary()` + `lint()` + a private `staticPrefix` inside the `Policy` struct (after `decide`, before the closing brace):
```swift
    public func summary() -> String {
        "policy OK: \(sensitiveGlobs.count) sensitive, \(allowTier.count) allow, \(lockedPaths.count) locked, \(bashAdvisory.count) bash, \(mcpAllow.count) mcp"
    }
    /// Static analysis of allow_tier for install-time review. fatal ⇒ refuse to install.
    public func lint() -> (fatal: [String], warnings: [String]) {
        var fatal: [String] = [], warnings: [String] = []
        let blanket: Set<String> = ["**", "/**", "*", "/*"]   // exact-match only — must NOT flag "/Users/x/**"
        for g in allowTier {
            if blanket.contains(g) {
                fatal.append("allow_tier contains blanket grant \"\(g)\" — trusts the entire filesystem un-gated")
                continue
            }
            let prefix = Policy.staticPrefix(g)
            if prefix.isEmpty { continue }
            var buf = [Int8](repeating: 0, count: Int(PATH_MAX))
            if realpath(prefix, &buf) != nil {
                let real = String(cString: buf)
                if real != prefix {
                    warnings.append("allow_tier \"\(g)\": prefix \(prefix) resolves to \(real) — writes arrive symlink-resolved and won't match; write \(real) instead")
                }
            } else {
                warnings.append("allow_tier \"\(g)\": prefix \(prefix) does not exist — this entry can never match")
            }
        }
        if allowTier.contains(where: { $0.hasSuffix("/**") }) && sensitiveGlobs.count < 3 {
            warnings.append("allow_tier grants a broad subtree while sensitive_globs is short (\(sensitiveGlobs.count)) — most writes will pass un-gated")
        }
        return (fatal, warnings)
    }
    /// The literal directory prefix of a glob, up to the segment containing the first metacharacter.
    static func staticPrefix(_ glob: String) -> String {
        guard let i = glob.firstIndex(where: { "*?[".contains($0) }) else { return glob }
        return (String(glob[..<i]) as NSString).deletingLastPathComponent
    }
```

- [ ] **Step 4: Run to verify pass**

Run: `swift test --filter PolicyTests 2>&1 | tail -6`
Expected: PASS (all PolicyTests). Then `swift test 2>&1 | grep -E "Executed [0-9]+ tests"` → 0 failures.

- [ ] **Step 5: Commit**

```bash
git add Sources/CCFidoCore/Policy.swift Tests/CCFidoCoreTests/PolicyTests.swift
git commit -m "feat(policy): public summary()/lint(), strict mcp_allow arity, named parse errors"
```

---

### Task 2: `renderPolicy` — JSON-safe `__HOME__` substitution + `$HOME` guard

**Files:**
- Modify: `Sources/CCFidoCore/CLIHelpers.swift` (alongside `renderPlist`/`renderManagedSettings`)
- Test: `Tests/CCFidoCoreTests/CLIHelperTests.swift`

**Interfaces:**
- Consumes: nothing from Task 1 (uses `JSONSerialization`).
- Produces:
  - `public enum RenderError: Error { case badHome(String), badSource(String) }`
  - `public func renderPolicy(srcPath: String, home: String) throws -> Data` — reads `srcPath`, guards `home`, substitutes `__HOME__`→`home` in every JSON string value, returns pretty-printed sorted-keys JSON `Data`. (Does NOT validate policy semantics — the caller runs `Policy.fromDict` for that.)

- [ ] **Step 1: Write failing tests**

Add to `Tests/CCFidoCoreTests/CLIHelperTests.swift` (inside the class):
```swift
    private func tmpJSON(_ s: String) -> String {
        let p = NSTemporaryDirectory() + "pol-\(UUID().uuidString).json"
        try! s.write(toFile: p, atomically: true, encoding: .utf8); return p
    }
    func testRenderSubstitutesHome() throws {
        let src = tmpJSON(#"{"allow_tier":["__HOME__/**"],"sensitive_globs":[],"locked_paths":[],"bash_advisory":[],"mcp_allow":[]}"#)
        let out = try renderPolicy(srcPath: src, home: "/Users/alice")
        let obj = try JSONSerialization.jsonObject(with: out) as! [String: Any]
        XCTAssertEqual(obj["allow_tier"] as? [String], ["/Users/alice/**"])
        XCTAssertFalse(String(data: out, encoding: .utf8)!.contains("__HOME__"))
    }
    func testRenderHomeWithMetacharsStaysValidJSON() throws {   // the sed-bug regression
        let src = tmpJSON(#"{"allow_tier":["__HOME__/**"],"sensitive_globs":[],"locked_paths":[],"bash_advisory":[],"mcp_allow":[]}"#)
        let out = try renderPolicy(srcPath: src, home: #"/Users/a"b\c"#)
        let obj = try JSONSerialization.jsonObject(with: out) as! [String: Any]   // must not throw
        XCTAssertEqual(obj["allow_tier"] as? [String], [#"/Users/a"b\c/**"#])
    }
    func testRenderRejectsBadHome() {
        let src = tmpJSON(#"{"allow_tier":["__HOME__/**"],"sensitive_globs":[],"locked_paths":[],"bash_advisory":[],"mcp_allow":[]}"#)
        for h in ["", "/", "/var/root", "/root"] {
            XCTAssertThrowsError(try renderPolicy(srcPath: src, home: h), "expected reject for HOME=\(h)")
        }
    }
    func testRenderRejectsMissingSource() {
        XCTAssertThrowsError(try renderPolicy(srcPath: "/no/such/file.json", home: "/Users/alice"))
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `swift test --filter CLIHelperTests 2>&1 | tail -20`
Expected: FAIL — `renderPolicy`/`RenderError` undefined.

- [ ] **Step 3: Implement in `CLIHelpers.swift`**

Append to `Sources/CCFidoCore/CLIHelpers.swift`:
```swift
public enum RenderError: Error { case badHome(String), badSource(String) }

/// Reads a policy template, guards `home`, substitutes `__HOME__`→`home` in every JSON string value
/// (parse → walk → re-serialize, so a home with `"`/`\`/`&` can never corrupt the JSON), and returns
/// pretty JSON. Does NOT check policy semantics — the caller runs `Policy.fromDict` + `lint()`.
public func renderPolicy(srcPath: String, home: String) throws -> Data {
    let banned: Set<String> = ["", "/", "/var/root", "/root"]
    guard !banned.contains(home), (home as NSString).isAbsolutePath else {
        throw RenderError.badHome("refusing HOME='\(home)' — run as the login user, not root")
    }
    guard let data = try? Data(contentsOf: URL(fileURLWithPath: srcPath)) else {
        throw RenderError.badSource("cannot read \(srcPath)")
    }
    guard let obj = try? JSONSerialization.jsonObject(with: data) else {
        throw RenderError.badSource("invalid JSON in \(srcPath)")
    }
    let substituted = substituteHome(obj, home)
    return try JSONSerialization.data(withJSONObject: substituted, options: [.prettyPrinted, .sortedKeys])
}
private func substituteHome(_ v: Any, _ home: String) -> Any {
    if let s = v as? String { return s.replacingOccurrences(of: "__HOME__", with: home) }
    if let a = v as? [Any] { return a.map { substituteHome($0, home) } }
    if let d = v as? [String: Any] { return d.mapValues { substituteHome($0, home) } }
    return v
}
```

- [ ] **Step 4: Run to verify pass**

Run: `swift test --filter CLIHelperTests 2>&1 | tail -6`
Expected: PASS. Then `swift test 2>&1 | grep -E "Executed [0-9]+ tests"` → 0 failures.

- [ ] **Step 5: Commit**

```bash
git add Sources/CCFidoCore/CLIHelpers.swift Tests/CCFidoCoreTests/CLIHelperTests.swift
git commit -m "feat(cli): renderPolicy — JSON-safe __HOME__ substitution + \$HOME guard"
```

---

### Task 3: `_validate-policy` + `_render-policy` subcommands

**Files:**
- Modify: `Sources/cc-fido/main.swift` (dispatch switch at `:34-91`, usage at `:5-8`)

**Interfaces:**
- Consumes: `Policy.fromFile`, `Policy.summary()`, `Policy.lint()` (Task 1); `renderPolicy` (Task 2); `Policy.fromDict`.
- Produces: two CLI subcommands (behavior, not a Swift symbol) — verified by Task 6 integration.

- [ ] **Step 1: Add the dispatch cases**

In `Sources/cc-fido/main.swift`, add these cases inside the `switch cmd` (e.g. after the `_blink-test` / `_verify-audit` cases):
```swift
case "_validate-policy":   // read-only: parse + summary + lint. exactly one path.
    guard args.count == 2 else { usage() }
    do {
        let policy = try Policy.fromFile(args[1])
        let (fatal, warnings) = policy.lint()
        for w in warnings { FileHandle.standardError.write(Data("cc-fido: WARNING \(w)\n".utf8)) }
        guard fatal.isEmpty else {
            for f in fatal { FileHandle.standardError.write(Data("cc-fido: FATAL \(f)\n".utf8)) }
            exit(1)
        }
        print(policy.summary()); exit(0)
    } catch {
        FileHandle.standardError.write(Data("cc-fido: invalid policy: \(error)\n".utf8)); exit(1)
    }
case "_render-policy":   // substitute __HOME__, guard home, validate + lint, emit JSON on success ONLY.
    guard args.count == 3 else { usage() }
    do {
        let rendered = try renderPolicy(srcPath: args[1], home: args[2])
        guard let obj = try JSONSerialization.jsonObject(with: rendered) as? [String: Any] else {
            throw PolicyError.badFile("rendered policy is not a JSON object")
        }
        let policy = try Policy.fromDict(obj)
        let (fatal, warnings) = policy.lint()
        for w in warnings { FileHandle.standardError.write(Data("cc-fido: WARNING \(w)\n".utf8)) }
        guard fatal.isEmpty else {
            for f in fatal { FileHandle.standardError.write(Data("cc-fido: FATAL \(f)\n".utf8)) }
            exit(1)   // NO stdout — a downstream `tee` writes nothing, live policy untouched
        }
        FileHandle.standardOutput.write(rendered); exit(0)   // emit only when valid
    } catch {
        FileHandle.standardError.write(Data("cc-fido: render failed: \(error)\n".utf8)); exit(1)
    }
```

Update `usage()` (`:6`) to list the new subcommands:
```swift
    FileHandle.standardError.write(Data("usage: cc-fido {daemon|hook|write <path>|enroll|install|enroll-file <path> [mode]|enroll-dir <path>|_validate-policy <path>|_render-policy <src> <home>}\n".utf8))
```

- [ ] **Step 2: Build**

Run: `swift build 2>&1 | tail -4`
Expected: `Build complete!`

- [ ] **Step 3: Smoke-test the subcommands by hand**

Run:
```bash
B=$(swift build --show-bin-path)/cc-fido
printf '{"allow_tier":["__HOME__/**"],"sensitive_globs":["**/.env*"],"locked_paths":[],"bash_advisory":[],"mcp_allow":[]}' > /tmp/pol-ok.json
"$B" _render-policy /tmp/pol-ok.json /Users/alice | grep -q '/Users/alice/\*\*' && echo "RENDER OK"
printf '{"allow_tier":["/**"],"sensitive_globs":[],"locked_paths":[],"bash_advisory":[],"mcp_allow":[]}' > /tmp/pol-blanket.json
"$B" _render-policy /tmp/pol-blanket.json /Users/alice; echo "blanket rc=$? (expect 1, no stdout)"
"$B" _render-policy /tmp/pol-ok.json ""; echo "emptyhome rc=$? (expect 1)"
"$B" _validate-policy /tmp/pol-ok.json; echo "validate rc=$? (expect 0)"
```
Expected: `RENDER OK`; blanket `rc=1`; emptyhome `rc=1`; validate prints `policy OK: …` `rc=0`.

- [ ] **Step 4: Commit**

```bash
git add Sources/cc-fido/main.swift
git commit -m "feat(cli): _validate-policy + _render-policy subcommands (fail-closed, emit-on-valid-only)"
```

---

### Task 4: Portable default template + `POLICY.md`

**Files:**
- Modify: `install/policy.json`
- Create: `install/POLICY.md`

**Interfaces:** none (data + docs). The template must parse via `Policy.fromDict` after `__HOME__`→a real home.

- [ ] **Step 1: Rewrite `install/policy.json`** (widened `sensitive_globs`, `__HOME__/**` allow_tier)

```json
{
  "sensitive_globs": [
    "**/.env*",
    "**/*.pem",
    "**/credentials*",
    "**/.ssh/*",
    "**/.zshrc",
    "**/.zprofile",
    "**/.zshenv",
    "**/.bashrc",
    "**/.bash_profile",
    "**/.profile",
    "**/Library/LaunchAgents/*",
    "**/Library/LaunchDaemons/*",
    "**/.gitconfig",
    "**/.config/git/*",
    "**/.git/hooks/*",
    "**/.claude/settings*.json",
    "**/.claude/CLAUDE.md",
    "**/.claude/hooks/*"
  ],
  "allow_tier": [
    "__HOME__/**"
  ],
  "locked_paths": [],
  "bash_advisory": [
    "git push .*(--force|-f)\\b",
    "rm -rf .*",
    "deploy",
    "kubectl delete .*"
  ],
  "mcp_allow": [
    ["gh", "list_prs"],
    ["gh", "get_issue"]
  ]
}
```

- [ ] **Step 2: Verify it renders + validates**

Run:
```bash
B=$(swift build --show-bin-path)/cc-fido
"$B" _render-policy install/policy.json "$HOME" > /tmp/pol-rendered.json
"$B" _validate-policy /tmp/pol-rendered.json && echo "TEMPLATE OK"
```
Expected: `policy OK: 18 sensitive, 1 allow, 0 locked, 4 bash, 2 mcp` then `TEMPLATE OK`.

- [ ] **Step 3: Create `install/POLICY.md`**

```markdown
# cc-fido-gate policy reference

`/opt/cc-fido-gate/policy.json` is the **best-effort hook** policy: it decides which agent tool
calls require a physical FIDO touch. It is root-owned and the agent cannot edit it. (The *hard*
guarantee — `_ccfido`-owned + `uchg` custody — is separate and stronger; this policy is the broad,
honestly-defeatable tier.)

## How to configure

Edit `install/policy.json` before install, **or** point the installer at your own file:
`POLICY=/path/to/policy.json bash scripts/userrun/task7_install.sh`. Install substitutes `__HOME__`
with your home, validates, and installs atomically — a broken or blanket policy aborts the install and
leaves the previous one intact. Check a file yourself any time with
`/opt/cc-fido-gate/cc-fido _validate-policy <file>`.

## Verdict order (writes: Write/Edit/MultiEdit/NotebookEdit)
1. `locked_paths` → **deny** (hard, with a nudge)
2. `sensitive_globs` → **gate** (touch required)
3. `allow_tier` → **pass** (no touch)
4. anything else → **gate**

`sensitive_globs` is checked *before* `allow_tier`, so a broad `allow_tier` can never un-gate a
sensitive path. Bash: a command matching any `bash_advisory` regex → gate, else pass. MCP: a
`mcp__server__tool` call whose `[server, tool]` is in `mcp_allow` → pass, else gate.

## Fields
- **`sensitive_globs`** — globs that always gate. Defaults cover secrets (`.env*`, `*.pem`,
  `credentials*`, `.ssh/*`) and code-exec/persistence (`.zshrc`/`.bashrc`/`.profile`,
  `Library/LaunchAgents/*`, `.gitconfig`, `.git/hooks/*`, `.claude/settings*.json`/`hooks`).
- **`allow_tier`** — globs that pass without a touch. Default `__HOME__/**` (whole home, minus
  `sensitive_globs`). Narrow to specific project roots for a stricter posture.
- **`locked_paths`** — exact paths that are hard-denied.
- **`bash_advisory`** — regexes (NSRegularExpression); a matching Bash command gates.
- **`mcp_allow`** — exactly-two-element `[server, tool]` pairs that pass.

## Glob semantics — READ THIS
Patterns use `fnmatch(pattern, path, 0)` — **no `FNM_PATHNAME`**. Consequences:
- `*` and `**` both cross `/`. `~/x/*` allows **arbitrary depth**, not one level. This is NOT
  gitignore/shell-globstar behavior; misreading it produces an *over-permissive* policy.
- Paths are matched **symlink-resolved** (realpath'd). Write **resolved** prefixes: use
  `/private/tmp/**`, not `/tmp/**`; `/private/var/...`, not `/var/...`. `_validate-policy` warns when
  an `allow_tier` prefix resolves elsewhere or doesn't exist.

## Residual risk of the default `__HOME__/**`
Everything under your home that isn't a `sensitive_glob` passes un-gated (the hook is best-effort and
a same-uid `echo > file` already bypasses it — but the Write/Edit gate is the visibility this tier
adds). The default gates the common code-exec/persistence and secret classes; if you add tools or
config outside those globs that you want gated, add them to `sensitive_globs`, or narrow `allow_tier`.
A blanket `allow_tier` (`**`, `/**`, `*`, `/*`) is rejected at install.
```

- [ ] **Step 4: Commit**

```bash
git add install/policy.json install/POLICY.md
git commit -m "feat(policy): portable default template (widened sensitive_globs, __HOME__/**) + POLICY.md"
```

---

### Task 5: Wire the atomic render→validate→install into the install scripts

**Files:**
- Modify: `scripts/userrun/task7_install.sh` (the `cp` at `:10`)
- Modify: `scripts/userrun/task6_hook.sh` (the `cp` at `:5-6`, and its `set -u` at `:2`)

**Interfaces:** consumes the `_render-policy` subcommand (Task 3) and `install/policy.json` (Task 4).

- [ ] **Step 1: Replace the policy `cp` in `task7_install.sh`**

Replace line 10 (`sudo cp "$REPO/install/policy.json" /opt/cc-fido-gate/policy.json`) with:
```bash
# Render (substitute __HOME__, validate, lint) → root-owned candidate → atomic mv. Never stages a
# user-owned file (TOCTOU) and never truncates the live policy (atomic). Aborts (set -e/pipefail) on
# a bad or blanket policy, leaving any existing /opt/cc-fido-gate/policy.json intact.
POLICY_SRC="${POLICY:-$REPO/install/policy.json}"
POLICY_CAND=/opt/cc-fido-gate/policy.json.new
trap 'sudo rm -f "$POLICY_CAND"' EXIT
/opt/cc-fido-gate/cc-fido _render-policy "$POLICY_SRC" "$HOME" | sudo tee "$POLICY_CAND" >/dev/null
sudo test -s "$POLICY_CAND"          # non-empty ⇒ render succeeded (emit-on-valid-only)
sudo mv "$POLICY_CAND" /opt/cc-fido-gate/policy.json
```
Note: the existing `sudo chmod 644 /opt/cc-fido-gate/policy.json` at `:11` still applies to the moved-in file; `sudo mv` within `/opt/cc-fido-gate` preserves root ownership.

- [ ] **Step 2: Replace the policy `cp` in `task6_hook.sh` + harden the shell**

Change line 2 from `set -u` to:
```bash
set -eu -o pipefail
```
Replace line 5 (`sudo mkdir -p /opt/cc-fido-gate; sudo cp "$REPO/install/policy.json" /opt/cc-fido-gate/policy.json`) with (uses the freshly-built `$BIN`, since the installed binary may not exist in this pre-install test):
```bash
sudo mkdir -p /opt/cc-fido-gate
POLICY_CAND=/opt/cc-fido-gate/policy.json.new
trap 'sudo rm -f "$POLICY_CAND"' EXIT
"$BIN" _render-policy "$REPO/install/policy.json" "$HOME" | sudo tee "$POLICY_CAND" >/dev/null
sudo test -s "$POLICY_CAND"
sudo mv "$POLICY_CAND" /opt/cc-fido-gate/policy.json
```
(Line 6's `sudo chown root:wheel … ; sudo chmod 644 …` still applies.)

- [ ] **Step 3: Syntax-check both**

Run: `bash -n scripts/userrun/task7_install.sh && bash -n scripts/userrun/task6_hook.sh && echo OK`
Expected: `OK`

- [ ] **Step 4: Commit**

```bash
git add scripts/userrun/task7_install.sh scripts/userrun/task6_hook.sh
git commit -m "feat(install): atomic render→validate→root-candidate→mv for policy install; harden task6 shell"
```

---

### Task 6: Install-path integration assertions (USER-RUN)

**Files:**
- Modify: `scripts/userrun/task7_accept.sh` (add policy-layer assertions)

**Interfaces:** consumes the installed `/opt/cc-fido-gate/policy.json` and `cc-fido _validate-policy`.

**Note:** this task is `[USER-RUN]` — it needs the live install from `task7_install.sh`. Author it here; the user runs it (no touch needed for these specific asserts).

- [ ] **Step 1: Add assertions to `task7_accept.sh`**

Add a new section before the final `RESULT` line:
```bash
echo "=== 6. installed policy is portable + substituted (no placeholder, home present) ==="
sudo grep -q __HOME__ /opt/cc-fido-gate/policy.json && fail "installed policy still contains __HOME__" || pass "no __HOME__ placeholder survived"
sudo grep -q "\"$HOME/\*\*\"" /opt/cc-fido-gate/policy.json && pass "allow_tier substituted to \$HOME" || fail "allow_tier not substituted to \$HOME"
sudo /opt/cc-fido-gate/cc-fido _validate-policy /opt/cc-fido-gate/policy.json >/dev/null && pass "installed policy validates" || fail "installed policy does not validate"

echo "=== 7. a broken custom POLICY aborts install and leaves the good policy intact ==="
GOOD_SHA=$(sudo shasum -a 256 /opt/cc-fido-gate/policy.json | cut -d' ' -f1)
printf '{"allow_tier":["("],"sensitive_globs":[],"locked_paths":[],"bash_advisory":["("],"mcp_allow":[]}' > /tmp/pol-bad.json
POLICY=/tmp/pol-bad.json bash "$REPO/scripts/userrun/task7_install.sh" >/dev/null 2>&1 && fail "install accepted a broken policy" || pass "install rejected the broken policy"
[ "$(sudo shasum -a 256 /opt/cc-fido-gate/policy.json | cut -d' ' -f1)" = "$GOOD_SHA" ] && pass "good policy left byte-for-byte intact" || fail "good policy was clobbered by a failed install"
```

- [ ] **Step 2: Syntax-check**

Run: `bash -n scripts/userrun/task7_accept.sh && echo OK`
Expected: `OK`

- [ ] **Step 3: Commit**

```bash
git add scripts/userrun/task7_accept.sh
git commit -m "test(accept): assert installed policy is substituted, validates, and survives a bad POLICY"
```

- [ ] **Step 4 (USER-RUN, after install): run the full acceptance**

The user runs `bash scripts/userrun/task7_install.sh` then `bash scripts/userrun/task7_accept.sh` and confirms sections 6–7 are `PASS` (in addition to the existing custody/broker/audit sections). No touch required for the new asserts; the broker-write section still needs one.

---

## Notes for the implementer
- The full `swift test` suite (currently 50) must stay green after Tasks 1–3; run it before each commit, not just `--filter`.
- `$(swift build --show-bin-path)/cc-fido` locates the debug binary for hand smoke-tests.
- Do NOT change `Policy.decideWrite`'s order or `matchPath` — the widened defaults rely on existing sensitive-before-allow semantics.
- Task 6 step 4 is hardware/host-dependent (real install) and is the user's to run; everything else is `swift test` / `bash -n` verifiable in-session.
