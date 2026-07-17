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
