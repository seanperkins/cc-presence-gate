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
