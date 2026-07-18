import XCTest
@testable import CCFidoCore

final class InstallTests: XCTestCase {
    func testInstallRequestsPlatformOpsAndIsIdempotent() throws {
        let p = MockPlatform()
        // installPrereqs must: create account (once), install the plist, write managed-settings.
        try installOrchestration(platform: p)          // pure part under test (see impl note)
        try installOrchestration(platform: p)          // re-run: account already exists ⇒ not re-created
        XCTAssertEqual(p.calls.filter { $0.hasPrefix("createAccount") }.count, 1)
        XCTAssertTrue(p.calls.contains("installPlist"))
        XCTAssertTrue(p.calls.contains("writeManaged"))
        XCTAssertFalse(p.calls.contains("activateDaemon"))   // install never starts the daemon
    }
}
