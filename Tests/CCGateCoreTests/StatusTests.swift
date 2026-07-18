import XCTest
@testable import CCGateCore

final class StatusTests: XCTestCase {
    func testRollupClean() {
        let s = StatusReport(account: false, dirs: false, binary: false, policyValid: false,
                             keyEnrolled: false, daemonRunning: false, managedSettings: false)
        XCTAssertEqual(s.rollup, "clean")
    }
    func testRollupPrereqsOnly() {
        let s = StatusReport(account: true, dirs: true, binary: true, policyValid: true,
                             keyEnrolled: false, daemonRunning: false, managedSettings: true)
        XCTAssertEqual(s.rollup, "prereqs-only")
    }
    func testRollupEnrolled() {
        let s = StatusReport(account: true, dirs: true, binary: true, policyValid: true,
                             keyEnrolled: true, daemonRunning: false, managedSettings: true)
        XCTAssertEqual(s.rollup, "enrolled")
    }
    func testRollupActive() {
        let s = StatusReport(account: true, dirs: true, binary: true, policyValid: true,
                             keyEnrolled: true, daemonRunning: true, managedSettings: true)
        XCTAssertEqual(s.rollup, "active")
    }
    func testRollupDegraded() {   // daemon running but a prereq is missing ⇒ degraded
        let s = StatusReport(account: true, dirs: true, binary: true, policyValid: false,
                             keyEnrolled: true, daemonRunning: true, managedSettings: true)
        XCTAssertEqual(s.rollup, "degraded")
    }
    func testJSONEncodes() throws {
        let s = StatusReport(account: true, dirs: true, binary: true, policyValid: true,
                             keyEnrolled: true, daemonRunning: true, managedSettings: true)
        let data = try JSONEncoder().encode(s)
        let obj = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        XCTAssertEqual(obj["rollup"] as? String, "active")
        XCTAssertEqual(obj["daemon_running"] as? Bool, true)
    }
    // gatherStatus must probe the login user's OWN enrollment handle (readable without privilege),
    // not allowed_signers (root/_ccfido-owned, unreadable to `status` running as the login user).
    func testGatherStatusKeyEnrolledWhenHandlePresent() throws {
        let home = "/tmp/cc-fido-status-test-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: home + "/.ccfido", withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: home) }
        FileManager.default.createFile(atPath: home + "/.ccfido/gate_sk", contents: Data("stub".utf8))
        let report = gatherStatus(platform: MockPlatform(), home: home)
        XCTAssertTrue(report.keyEnrolled)
    }
    func testGatherStatusKeyNotEnrolledWhenHandleAbsent() throws {
        let home = "/tmp/cc-fido-status-test-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: home, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: home) }
        let report = gatherStatus(platform: MockPlatform(), home: home)
        XCTAssertFalse(report.keyEnrolled)
    }
}
