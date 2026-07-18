import XCTest
@testable import CCGateCore

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

    func testUninstallUnlocksTargetsThenTearsDown() throws {
        let p = MockPlatform(); p.accountExists = true; p.daemon = (true, true, 9)
        let enroller = MockEnroller()
        try uninstall(platform: p, enrolledTargets: ["/Users/Shared/x.txt"], home: "/Users/x", enroller: enroller)
        XCTAssertTrue(p.calls.contains("nouchg(/Users/Shared/x.txt)"))  // unlocked before deletion
        XCTAssertTrue(p.calls.contains("bootoutDaemon"))
        XCTAssertTrue(p.calls.contains("removeManaged"))
        XCTAssertTrue(p.calls.contains("deleteAccount(_ccfido)"))
        // unlock must precede account deletion
        XCTAssertLessThan(p.calls.firstIndex(of: "nouchg(/Users/Shared/x.txt)")!, p.calls.firstIndex(of: "deleteAccount(_ccfido)")!)
        // key material cleanup delegated to the Enroller seam
        XCTAssertEqual(enroller.removedHome, "/Users/x")
    }
}
