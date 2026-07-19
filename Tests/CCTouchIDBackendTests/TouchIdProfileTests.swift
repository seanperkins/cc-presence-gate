import XCTest
@testable import CCTouchIDBackend
@testable import CCGateCore
final class TouchIdProfileTests: XCTestCase {
    func testProfileIdentity() {
        let p = touchIdProfile
        XCTAssertEqual(p.serviceAccount, "_cctouchid")
        XCTAssertEqual(p.binaryName, "cc-touch-id")
        XCTAssertEqual(p.namespace, "cc-touch-id-gate/v1")
        XCTAssertEqual(p.sock, "/var/cctouchid-run/gate.sock")
        XCTAssertEqual(p.allowedSigners, "/var/cctouchid/allowed_signers")
        XCTAssertEqual(p.launchdLabel, "com.cc-touch-id-gate.brokerd")
    }
    func testContextComposesTouchIdSeams() {
        let ctx = makeTouchIdContext(home: "/tmp/h")
        XCTAssertTrue(ctx.ceremony is TouchIdCeremony)
        XCTAssertTrue(ctx.verifier is TouchIdVerifier)
        XCTAssertTrue(ctx.enroller is TouchIdEnroller)
    }
}
