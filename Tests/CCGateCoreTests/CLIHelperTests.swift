import XCTest
import Foundation
@testable import CCGateCore

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
    func testRenderKeepsSlashesUnescaped() throws {
        let src = tmpJSON(#"{"allow_tier":["__HOME__/**"],"sensitive_globs":["**/.env*"],"locked_paths":[],"bash_advisory":[],"mcp_allow":[]}"#)
        let s = String(data: try renderPolicy(srcPath: src, home: "/Users/alice"), encoding: .utf8)!
        XCTAssertTrue(s.contains("/Users/alice/**"), "expected unescaped slashes")
        XCTAssertTrue(s.contains("**/.env*"))
        XCTAssertFalse(s.contains(#"\/"#), "no slash should be escaped as \\/")
    }
    func testFlagValueReturnsTrailingArg() {
        XCTAssertEqual(flagValue("--keys", in: ["enroll", "--keys", "3"]), "3")
    }
    func testFlagValueNilWhenFlagAbsent() {
        XCTAssertNil(flagValue("--keys", in: ["enroll"]))
    }
    func testFlagValueNilWhenFlagIsLastArg() {
        // must not trap on out-of-bounds access when the flag has no trailing value
        XCTAssertNil(flagValue("--keys", in: ["enroll", "--keys"]))
    }
}
