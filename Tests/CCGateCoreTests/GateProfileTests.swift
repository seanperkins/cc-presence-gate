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
