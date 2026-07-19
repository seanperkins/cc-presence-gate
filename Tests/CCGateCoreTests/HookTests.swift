import XCTest
import Foundation
@testable import CCGateCore

final class HookTests: XCTestCase {
    let pol = try! Policy(sensitiveGlobs: ["**/.env*"], allowTier: ["/Users/sean/proj/**"],
                          lockedPaths: ["/var/ccfido/target.txt"], bashAdvisory: [#"git push .*-f\b"#], mcpAllow: [])
    private func run(_ e: [String: Any], _ approve: @escaping (String, [String: Any], String) -> Bool)
        -> (Int32, String, String) {
        let o = Pipe(), er = Pipe()
        let c = decideAndEmit(event: e, policy: pol, profile: testProfile, out: o.fileHandleForWriting, err: er.fileHandleForWriting, approve: approve)
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
