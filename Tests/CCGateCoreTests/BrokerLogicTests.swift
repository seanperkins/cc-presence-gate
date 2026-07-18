import XCTest
@testable import CCGateCore

final class BrokerLogicTests: XCTestCase {
    func testDecideApproveCompilesAndBindsInput() throws {
        let b = Broker()
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
