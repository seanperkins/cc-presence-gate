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

    func testActivateRefusesWithoutKey_thenActivates() throws {
        // activate must refuse if allowed_signers is absent; with a key present, it calls activateDaemon.
        let p = MockPlatform()
        XCTAssertThrowsError(try activate(platform: p, keyEnrolled: false))
        XCTAssertFalse(p.calls.contains("activateDaemon"))
        try activate(platform: p, keyEnrolled: true)
        XCTAssertTrue(p.calls.contains("activateDaemon"))
    }
}
