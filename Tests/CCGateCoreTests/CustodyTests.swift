import XCTest
import Foundation
@testable import CCGateCore

final class CustodyTests: XCTestCase {
    func testPlanEnrollFile() {
        XCTAssertEqual(planEnrollFile("/tmp/x/.env", mode: 0o600, profile: testProfile), [
            ["/usr/sbin/chown", "_ccfido", "/tmp/x/.env"],
            ["/bin/chmod", "600", "/tmp/x/.env"],
            ["/usr/bin/chflags", "uchg", "/tmp/x/.env"]])
    }
    func testPlanEnrollDir() {
        XCTAssertEqual(planEnrollDir("/tmp/LA", profile: testProfile), [
            ["/usr/sbin/chown", "_ccfido", "/tmp/LA"], ["/bin/chmod", "755", "/tmp/LA"]])
    }
    func testWritableAncestorDetected() throws {
        let base = NSTemporaryDirectory() + "cust-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: base + "/sub", withIntermediateDirectories: true)
        let target = base + "/sub/secret"; FileManager.default.createFile(atPath: target, contents: Data("x".utf8))
        XCTAssertTrue(checkAncestors(target, safeOwners: [0]).contains(base))
    }
    func testIsSymlinkDistinguishesLinkFromTargetAndMissing() throws {
        let base = NSTemporaryDirectory() + "sym-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: base, withIntermediateDirectories: true)
        let real = base + "/real.txt", link = base + "/link.txt", dir = base + "/d", dlink = base + "/dlink"
        FileManager.default.createFile(atPath: real, contents: Data("x".utf8))
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: real)
        try FileManager.default.createSymbolicLink(atPath: dlink, withDestinationPath: dir)
        XCTAssertTrue(isSymlink(link), "a symlink to a file must be detected")
        XCTAssertTrue(isSymlink(dlink), "a symlink to a directory must be detected")
        XCTAssertFalse(isSymlink(real), "a regular file is not a symlink")
        XCTAssertFalse(isSymlink(dir), "a directory is not a symlink")
        XCTAssertFalse(isSymlink(base + "/nope"), "a missing path is not a symlink")
    }
    func testIsSymlinkDetectsDanglingLink() throws {
        // The inducement case: the link resolves to nothing (or to a file the operator can't see),
        // so a stat()-based check would miss it while chown/chmod would still follow.
        let base = NSTemporaryDirectory() + "sym2-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: base, withIntermediateDirectories: true)
        let dangling = base + "/dangling"
        try FileManager.default.createSymbolicLink(atPath: dangling, withDestinationPath: base + "/does-not-exist")
        XCTAssertTrue(isSymlink(dangling))
        var st = stat()
        XCTAssertNotEqual(stat(dangling, &st), 0, "stat() follows and fails — only lstat sees the link")
    }
    func testRegistryRoundTrip() throws {
        let p = NSTemporaryDirectory() + "custody-\(UUID().uuidString).json"
        try CustodyRegistry.add(file: "/a/b", dir: nil, path: p)
        try CustodyRegistry.add(file: nil, dir: "/c", path: p)
        let (files, dirs) = CustodyRegistry.load(path: p)
        XCTAssertEqual(files, ["/a/b"]); XCTAssertEqual(dirs, ["/c"])
    }
    func testRegistryDedupsAcrossFirmlinkAndRepeat() throws {
        let p = NSTemporaryDirectory() + "custody-\(UUID().uuidString).json"
        try CustodyRegistry.add(file: "/var/foo", dir: nil, path: p)
        try CustodyRegistry.add(file: "/private/var/foo", dir: nil, path: p)  // firmlink form of the same file
        try CustodyRegistry.add(file: "/var/foo", dir: nil, path: p)          // exact repeat
        XCTAssertEqual(CustodyRegistry.load(path: p).files, ["/var/foo"])     // one entry, normalized
    }
    func testRegistryConcurrentAddsPreservesAllEntries() throws {
        // Verifies the flock-serialized RMW: concurrent adds must not race and drop entries.
        let path = NSTemporaryDirectory() + "custody-concurrent-\(UUID().uuidString).json"
        let count = 20
        let group = DispatchGroup()
        for i in 0..<count {
            group.enter()
            DispatchQueue.global().async {
                try? CustodyRegistry.add(file: "/tmp/concurrent-file-\(i)", dir: nil, path: path)
                group.leave()
            }
        }
        group.wait()
        let (files, _) = CustodyRegistry.load(path: path)
        XCTAssertEqual(files.count, count, "expected \(count) entries but got \(files.count): \(files)")
    }
}
