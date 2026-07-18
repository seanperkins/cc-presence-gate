import XCTest
@testable import CCFidoBackend

final class FidoEnrollerTests: XCTestCase {
    func testEnrollPlanGeneratesSkKeygenStep() {
        let plan = FidoEnroller().enrollPlan(home: "/Users/x", index: 2)
        XCTAssertEqual(plan.count, 1)
        XCTAssertTrue(plan[0].contains("ed25519-sk"))
        XCTAssertTrue(plan[0].contains("/Users/x/.ccfido/gate_sk2"))
    }
    func testEnrollPlanArgvShape() {
        // full argv shape: empty passphrase (-N ""), the app namespace (-O application=...),
        // and a comment flag (-C) — not just the destination path.
        let argv = FidoEnroller().enrollPlan(home: "/Users/x", index: 1)[0]
        guard let nIdx = argv.firstIndex(of: "-N") else { return XCTFail("missing -N flag: \(argv)") }
        XCTAssertEqual(argv[safe: nIdx + 1], "", "expected empty passphrase after -N: \(argv)")
        guard let oIdx = argv.firstIndex(of: "-O") else { return XCTFail("missing -O flag: \(argv)") }
        XCTAssertEqual(argv[safe: oIdx + 1], "application=ssh:cc-fido-gate", "expected app namespace after -O: \(argv)")
        XCTAssertTrue(argv.contains("-C"), "expected a -C comment flag: \(argv)")
    }
    func testIsEnrolledChecksKeyFile() throws {
        XCTAssertFalse(FidoEnroller().isEnrolled(home: "/nonexistent-xyz"))
        let home = "/tmp/cc-fido-enroller-test-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: home + "/.ccfido", withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: home) }
        XCTAssertFalse(FidoEnroller().isEnrolled(home: home))
        FileManager.default.createFile(atPath: home + "/.ccfido/gate_sk", contents: Data("stub".utf8))
        XCTAssertTrue(FidoEnroller().isEnrolled(home: home))
    }
    func testRemoveKeyMaterialDeletesKeyFiles() throws {
        let home = "/tmp/cc-fido-enroller-test-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: home + "/.ccfido", withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: home) }
        for f in ["gate_sk", "gate_sk.pub", "gate_sk1", "gate_sk1.pub", "gate_sk2", "gate_sk2.pub"] {
            FileManager.default.createFile(atPath: "\(home)/.ccfido/\(f)", contents: Data())
        }
        FidoEnroller().removeKeyMaterial(home: home)
        for f in ["gate_sk", "gate_sk.pub", "gate_sk1", "gate_sk1.pub", "gate_sk2", "gate_sk2.pub"] {
            XCTAssertFalse(FileManager.default.fileExists(atPath: "\(home)/.ccfido/\(f)"))
        }
    }
}
private extension Array {
    subscript(safe i: Int) -> Element? { indices.contains(i) ? self[i] : nil }
}
