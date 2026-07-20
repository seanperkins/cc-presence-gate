import XCTest
import Foundation
@testable import CCGateCore

// Shared across CCGateCoreTests (internal, not private) — e.g. BrokerAllowlistTests also needs a Broker.
struct StubVerifier: Verifier {
    func verify(challenge: Data, signature: Data) -> Bool { false }
}

final class BrokerLogicTests: XCTestCase {
    // --- ns domain separator: defined on SignedDocument AND actually wired by the broker ---
    func testApproveChallengeCarriesTheProfileNamespace() throws {
        let b = Broker(profile: testProfile, verifier: StubVerifier())
        let (_, _, doc) = try b.decideApprove(["tool": "Bash", "input": ["command": "ls"], "cwd": "/tmp"], caller: 501)
        XCTAssertEqual(doc.ns, testProfile.namespace,
                       "broker must stamp the profile namespace into the signed document")
    }
    func testTwoProfilesProduceDifferentChallengeBytesForTheSameRequest() throws {
        // Domain separation: the same logical request under two products must not canonicalize to the
        // same bytes, so a signature over one can never be replayed as the other.
        let other = GateProfile(serviceAccount: "_svc2", accountRealName: "rn", namespace: "other-gate/v1",
            keydir: "/var/k2", runDir: "/var/r2", sock: "/var/r2/g.sock", daemonLogErr: "/var/k2/e.err",
            codeDir: "/opt/c2", policy: "/opt/c2/p.json", binaryName: "bin2", displayName: "d2",
            launchdLabel: "lbl2", plist: "/L/lbl2.plist", daemonMatchPattern: "bin2 daemon",
            claudeCodeDir: "/CC", managedSettings: "/CC/m.json")
        let req: [String: Any] = ["tool": "Bash", "input": ["command": "ls"], "cwd": "/tmp"]
        let a = try Broker(profile: testProfile, verifier: StubVerifier()).decideApprove(req, caller: 501).doc
        let c = try Broker(profile: other, verifier: StubVerifier()).decideApprove(req, caller: 501).doc
        XCTAssertNotEqual(a.ns, c.ns)
        // compare with the per-op nonce held equal, so only ns can account for the difference
        let aFixed = buildSignedDocument(op: a.op, path: a.path, contentSha256: a.contentSha256, cwd: a.cwd,
                                         nonceHex: "fixed", callerUid: a.callerUid, contentMode: a.contentMode, ns: a.ns)
        let cFixed = buildSignedDocument(op: c.op, path: c.path, contentSha256: c.contentSha256, cwd: c.cwd,
                                         nonceHex: "fixed", callerUid: c.callerUid, contentMode: c.contentMode, ns: c.ns)
        XCTAssertNotEqual(try canonicalBytes(aFixed), try canonicalBytes(cFixed),
                          "identical requests under different namespaces must not share challenge bytes")
    }

    // --- M1: a durable write must never be reported as a failure ---
    enum FakeAuditError: Error { case disk }
    func testWriteResultIsOkWhenAuditSucceeded() {
        let r = Broker.writeResult(auditError: nil)
        XCTAssertEqual(r["status"] as? String, "ok")
        XCTAssertNil(r["audit_error"], "no audit failure ⇒ no audit_error key")
    }
    func testWriteResultStaysOkButFlagsAuditFailure() {
        // The write is already durable at this point: an audit-append failure must NOT downgrade the
        // status to deny (the client would think nothing happened) — but it must not be silent either.
        let r = Broker.writeResult(auditError: FakeAuditError.disk)
        XCTAssertEqual(r["status"] as? String, "ok", "durable write must still report ok")
        XCTAssertTrue((r["audit_error"] as? String)?.contains("audit append failed") == true,
                      "audit gap must be surfaced, got: \(String(describing: r["audit_error"]))")
    }

    func testDecideApproveCompilesAndBindsInput() throws {
        let b = Broker(profile: testProfile, verifier: StubVerifier())
        let d = try b.decideApprove(["op": "approve", "tool": "Bash",
                                     "input": ["command": "git push --force"], "cwd": "/tmp"], caller: 501)
        XCTAssertTrue(d.human.contains("git push --force"))
        XCTAssertFalse(d.challengeB64.isEmpty)
    }
    func testApproveChallengeIsDeterministicForSameInput() throws {
        // canonicalJSON sorts nested keys, so payload hash is stable regardless of dict order
        let a = try canonicalJSON(["tool": "Bash", "input": ["command": "x"], "cwd": "/"])
        let b = try canonicalJSON(["cwd": "/", "input": ["command": "x"], "tool": "Bash"])
        XCTAssertEqual(a, b)
    }
}
