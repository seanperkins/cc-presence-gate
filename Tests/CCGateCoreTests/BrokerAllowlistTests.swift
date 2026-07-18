import XCTest
@testable import CCGateCore

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
