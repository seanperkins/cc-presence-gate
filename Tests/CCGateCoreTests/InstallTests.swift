import XCTest
@testable import CCGateCore

final class InstallTests: XCTestCase {
    func testInstallRequestsPlatformOpsAndIsIdempotent() throws {
        let p = MockPlatform()
        // installPrereqs must: create account (once), install the plist, write managed-settings.
        try installOrchestration(platform: p, profile: testProfile)          // pure part under test (see impl note)
        try installOrchestration(platform: p, profile: testProfile)          // re-run: account already exists ⇒ not re-created
        XCTAssertEqual(p.calls.filter { $0.hasPrefix("createAccount") }.count, 1)
        XCTAssertTrue(p.calls.contains("installPlist"))
        XCTAssertTrue(p.calls.contains("writeManaged"))
        XCTAssertFalse(p.calls.contains("activateDaemon"))   // install never starts the daemon
    }

    func testActivateRefusesWithoutKey_thenActivates() throws {
        // activate must refuse if allowed_signers is absent; with a key present, it calls activateDaemon.
        let p = MockPlatform()
        XCTAssertThrowsError(try activate(platform: p, keyEnrolled: false, profile: testProfile))
        XCTAssertFalse(p.calls.contains("activateDaemon"))
        try activate(platform: p, keyEnrolled: true, profile: testProfile)
        XCTAssertTrue(p.calls.contains("activateDaemon"))
    }

    func testLoginOwnerFallsBackForNonexistentUser() {
        // A user that definitely doesn't exist → must fall back to :staff
        XCTAssertEqual(loginOwner(home: "/Users/no-such-user-xyzzy-99999"), "no-such-user-xyzzy-99999:staff")
    }
    func testLoginOwnerUsesRealPrimaryGroup() {
        // The current user exists — verify the returned group is non-empty and matches getpwnam.
        let home = NSHomeDirectory()
        let user = (home as NSString).lastPathComponent
        let result = loginOwner(home: home)
        // Format: "user:group"
        XCTAssertTrue(result.hasPrefix("\(user):"), "expected '\(user):…' but got '\(result)'")
        let group = String(result.dropFirst("\(user):".count))
        XCTAssertFalse(group.isEmpty, "group name must not be empty")
        // Cross-check: group must match what getpwnam → getgrgid gives
        if let pw = getpwnam(user), let gr = getgrgid(pw.pointee.pw_gid),
           let expectedGroup = String(validatingUTF8: gr.pointee.gr_name) {
            XCTAssertEqual(group, expectedGroup, "loginOwner returned '\(group)' but getgrgid gives '\(expectedGroup)'")
        }
    }
    func testUninstallUnlocksTargetsThenTearsDown() throws {
        let p = MockPlatform(); p.accountExists = true; p.daemon = (true, true, 9)
        let enroller = MockEnroller()
        try uninstall(platform: p, enrolledTargets: ["/Users/Shared/x.txt"], home: "/Users/x", enroller: enroller, profile: testProfile)
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
