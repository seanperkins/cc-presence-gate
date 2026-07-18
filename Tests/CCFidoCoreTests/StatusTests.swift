import XCTest
@testable import CCFidoCore

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
}
