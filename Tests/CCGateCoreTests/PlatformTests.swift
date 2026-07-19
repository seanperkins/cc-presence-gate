import XCTest
@testable import CCGateCore

// A Platform double that records the OS ops the orchestration requests, so install/activate/uninstall
// logic can be unit-tested without touching the real system.
final class MockPlatform: Platform {
    var calls: [String] = []
    var accountExists = false
    var daemon: (loaded: Bool, running: Bool, pid: Int?) = (false, false, nil)
    func createServiceAccount(name: String) throws { calls.append("createAccount(\(name))"); accountExists = true }
    func deleteServiceAccount(name: String) throws { calls.append("deleteAccount(\(name))"); accountExists = false }
    func serviceAccountExists(name: String) -> Bool { accountExists }
    func installDaemonPlist(_ xml: String) throws { calls.append("installPlist") }
    func activateDaemon() throws { calls.append("activateDaemon"); daemon = (true, true, 1234) }
    func bootoutDaemon() throws { calls.append("bootoutDaemon"); daemon = (false, false, nil) }
    func daemonState() -> (loaded: Bool, running: Bool, pid: Int?) { daemon }
    func writeManagedSettings(_ json: String) throws { calls.append("writeManaged") }
    func removeManagedSettings() throws { calls.append("removeManaged") }
    func makeImmutable(_ path: String) throws { calls.append("uchg(\(path))") }
    func clearImmutable(_ path: String) throws { calls.append("nouchg(\(path))") }
}

// An Enroller double: backend-agnostic stand-in so core tests (gatherStatus/uninstall/runEnroll)
// don't need CCFidoBackend, which CCGateCoreTests doesn't depend on.
final class MockEnroller: Enroller {
    var enrolled = false
    var removedHome: String?
    func enroll(home: String, keys: Int, profile: GateProfile) throws {}
    func positiveControl(home: String, profile: GateProfile) -> Bool { true }
    func isEnrolled(home: String) -> Bool { enrolled }
    func removeKeyMaterial(home: String) { removedHome = home }
}

final class PlatformTests: XCTestCase {
    func testMockRecordsAccountLifecycle() throws {
        let p = MockPlatform()
        XCTAssertFalse(p.serviceAccountExists(name: "_ccfido"))
        try p.createServiceAccount(name: "_ccfido")
        XCTAssertTrue(p.serviceAccountExists(name: "_ccfido"))
        XCTAssertEqual(p.calls, ["createAccount(_ccfido)"])
    }
}
