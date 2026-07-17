import XCTest
@testable import CCFidoCore

final class AuditTests: XCTestCase {
    private func tmp() -> String { NSTemporaryDirectory() + "audit-\(UUID().uuidString).log" }
    func testChainVerifiesFromFirstLine() throws {
        let p = tmp(); try auditAppend(["event": "a"], path: p); try auditAppend(["event": "b"], path: p)
        XCTAssertTrue(auditVerifyChain(path: p))   // no unchained prefix — chained from line 0
    }
    func testTamperBreaksChain() throws {
        let p = tmp(); try auditAppend(["event": "a"], path: p); try auditAppend(["event": "b"], path: p)
        var lines = try String(contentsOfFile: p, encoding: .utf8).split(separator: "\n").map(String.init)
        lines[0] = lines[0].replacingOccurrences(of: "\"a\"", with: "\"HACKED\"")
        try (lines.joined(separator: "\n") + "\n").write(toFile: p, atomically: true, encoding: .utf8)
        XCTAssertFalse(auditVerifyChain(path: p))
    }

    // Concurrent ceremonies append to the chain in parallel (the broker no longer holds a ceremony-wide
    // lock — task3 DoS fix). auditAppend must serialize its own read-modify-write so no two records land on
    // the same seq/prev_hash. Without the internal flock the seqs collide and the chain fails to verify.
    func testConcurrentAppendsKeepChainIntact() {
        let p = tmp(); let n = 100
        DispatchQueue.concurrentPerform(iterations: n) { i in
            try? auditAppend(["event": "e\(i)"], path: p)
        }
        XCTAssertEqual(auditLines(p).count, n)      // every append durably landed
        XCTAssertTrue(auditVerifyChain(path: p))    // seq/prev_hash chain intact despite concurrency
    }
}
