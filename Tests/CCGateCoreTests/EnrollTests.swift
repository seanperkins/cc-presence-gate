import XCTest
@testable import CCGateCore

final class EnrollTests: XCTestCase {
    func testEnrollPlanGeneratesKeygenPerKey() {
        let plan = enrollPlan(home: "/Users/x", keys: 2)
        XCTAssertEqual(plan.count, 2)
        // each entry is a ssh-keygen -t ed25519-sk invocation writing gate_sk<N>
        XCTAssertTrue(plan[0].contains("ed25519-sk"))
        XCTAssertTrue(plan[0].contains("/Users/x/.ccfido/gate_sk1"))
        XCTAssertTrue(plan[1].contains("/Users/x/.ccfido/gate_sk2"))
    }
    func testEnrollPlanArgvShape() {
        // full argv shape per key: empty passphrase (-N ""), the app namespace (-O application=...),
        // and a comment flag (-C) — not just the destination path.
        for argv in enrollPlan(home: "/Users/x", keys: 2) {
            guard let nIdx = argv.firstIndex(of: "-N") else { return XCTFail("missing -N flag: \(argv)") }
            XCTAssertEqual(argv[safe: nIdx + 1], "", "expected empty passphrase after -N: \(argv)")
            guard let oIdx = argv.firstIndex(of: "-O") else { return XCTFail("missing -O flag: \(argv)") }
            XCTAssertEqual(argv[safe: oIdx + 1], "application=ssh:cc-fido-gate", "expected app namespace after -O: \(argv)")
            XCTAssertTrue(argv.contains("-C"), "expected a -C comment flag: \(argv)")
        }
    }
}
private extension Array {
    subscript(safe i: Int) -> Element? { indices.contains(i) ? self[i] : nil }
}
