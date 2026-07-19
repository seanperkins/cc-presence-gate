import XCTest
import Foundation
@testable import CCGateCore
@testable import CCFidoBackend

final class FidoBarrierTests: XCTestCase {
    let b = Broker(profile: fidoProfile, verifier: FidoVerifier(keygen: "/usr/bin/ssh-keygen",
        allowedSigners: fidoProfile.allowedSigners, principal: "gate-principal",
        namespace: fidoProfile.namespace, keydir: fidoProfile.keydir))

    /// Regression guard: catches silent drift in the FIDO control-path barrier if `fidoProfile`
    /// changes shape. Anchored on hardcoded literal paths, NOT values derived from fidoProfile.
    func testControlPathOutcomesMatchHardcodedFidoBarrier() {
        for p in ["/var/ccfido/allowed_signers", "/var/ccfido-run/gate.sock", "/var/ccfido/audit.log",
                  "/opt/cc-fido-gate/policy.json", "/opt/cc-fido-gate/cc-fido",
                  "/private/var/ccfido/allowed_signers", "/private/var/ccfido-run/gate.sock"] {
            XCTAssertTrue(b.isControlPath(p), "\(p) must be control")
        }
        XCTAssertFalse(b.isControlPath("/Users/x/project/.env"), "enrolled-style target must NOT be control")
    }

    /// One-sided-anchored sign→verify roundtrip: the allowed_signers line and the GOOD verifier's
    /// principal are both the hardcoded literal "gate-principal" (mirrors enroll). A verifier
    /// miswired to the service account principal must fail — that's the rename-regression guard.
    func testVerifierUsesSignPrincipal_oneSidedAnchor() throws {
        // temp topology; software ed25519 key; injected /usr/bin/ssh-keygen (no touch → [SW])
        let tmp = NSTemporaryDirectory() + "ccfido-test-\(getpid())"
        try? FileManager.default.createDirectory(atPath: tmp, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: tmp) }
        // 1. software key
        let p = Process(); p.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-keygen")
        p.arguments = ["-t", "ed25519", "-N", "", "-f", tmp + "/k"]
        p.standardOutput = FileHandle.nullDevice; p.standardError = FileHandle.nullDevice
        try p.run(); p.waitUntilExit()
        let pub = try String(contentsOfFile: tmp + "/k.pub", encoding: .utf8)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        // 2. allowed_signers anchored on the HARDCODED literal "gate-principal" (mirrors enroll)
        try "gate-principal \(pub)\n".write(toFile: tmp + "/allowed", atomically: true, encoding: .utf8)
        let challenge = Data("hello".utf8)
        let sig = try fidoSign(challenge: challenge, handlePath: tmp + "/k",
                               namespace: fidoProfile.namespace, keygen: "/usr/bin/ssh-keygen")
        // 3. verifier driven from the PROFILE/constructor principal — must equal the literal for verify to pass
        let good = FidoVerifier(keygen: "/usr/bin/ssh-keygen", allowedSigners: tmp + "/allowed",
                                principal: "gate-principal", namespace: fidoProfile.namespace, keydir: tmp)
        XCTAssertTrue(good.verify(challenge: challenge, signature: sig))
        // a miswire to the service account fails (this is the rename-regression guard)
        let bad = FidoVerifier(keygen: "/usr/bin/ssh-keygen", allowedSigners: tmp + "/allowed",
                               principal: "_ccfido", namespace: fidoProfile.namespace, keydir: tmp)
        XCTAssertFalse(bad.verify(challenge: challenge, signature: sig))
    }
}
