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
    func testLintDefaultShapeNotFatalNoWarn() {   // legit non-blanket allow: not fatal AND no warning
        let q = Policy(sensitiveGlobs: ["**/.env*", "**/.ssh/*", "**/.zshrc"],
                       allowTier: [NSHomeDirectory() + "/**"],
                       lockedPaths: [], bashAdvisory: [], mcpAllow: [])
        XCTAssertTrue(q.lint().fatal.isEmpty)
        XCTAssertTrue(q.lint().warnings.isEmpty, "a legit existing dir/** must not warn: \(q.lint().warnings)")
    }
    func testStaticPrefixKeepsFullDir() {
        XCTAssertEqual(Policy.staticPrefix("/Users/x/**"), "/Users/x")
        XCTAssertEqual(Policy.staticPrefix("/Users/x/*"), "/Users/x")
        XCTAssertEqual(Policy.staticPrefix("/Users/x/y/**"), "/Users/x/y")
        XCTAssertEqual(Policy.staticPrefix("/Users/x/foo*bar"), "/Users/x")
    }
    func testLintWarnsOnNonexistentPrefix() {
        let q = Policy(sensitiveGlobs: ["a","b","c"], allowTier: ["/no-such-dir-zzz/**"], lockedPaths: [], bashAdvisory: [], mcpAllow: [])
        XCTAssertTrue(q.lint().fatal.isEmpty)
        XCTAssertTrue(q.lint().warnings.contains { $0.contains("/no-such-dir-zzz") }, "expected a warning naming the nonexistent prefix")
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
}
