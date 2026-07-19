import XCTest
final class GrepGateTests: XCTestCase {
    func testCoreCarriesNoFidoIdentity() throws {
        let root = URL(fileURLWithPath: #filePath)  // .../Tests/CCGateCoreTests/GrepGateTests.swift
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Sources/CCGateCore")
        let tokens = ["_ccfido", ".ccfido", "gate_sk", "gate-principal", "cc-fido",
                      "ccfido", "/var/ccfido", "cc-fido-gate@", "com.cc-fido-gate", "brokerd"]
        let fm = FileManager.default
        let files = fm.enumerator(at: root, includingPropertiesForKeys: nil)!
            .compactMap { $0 as? URL }.filter { $0.pathExtension == "swift" }
            // Enroll.swift's FIDO enroll-ceremony literals (.ccfido, gate_sk, gate-principal) are a
            // documented, user-approved SP2 residual: de-FIDO-ing runEnroll is deferred past SP1.
            .filter { $0.lastPathComponent != "Enroll.swift" }
        var hits: [String] = []
        for f in files {
            let txt = try String(contentsOf: f, encoding: .utf8)
            for t in tokens where txt.contains(t) { hits.append("\(f.lastPathComponent): \(t)") }
        }
        XCTAssertTrue(hits.isEmpty, "CCGateCore carries FIDO identity: \(hits)")
    }
}
