import Foundation
import Darwin

public func planEnrollFile(_ path: String, mode: Int, profile: GateProfile) -> [[String]] {
    [["/usr/sbin/chown", profile.serviceAccount, path], ["/bin/chmod", String(mode, radix: 8), path],
     ["/usr/bin/chflags", "uchg", path]]
}
public func planEnrollDir(_ path: String, profile: GateProfile) -> [[String]] {
    [["/usr/sbin/chown", profile.serviceAccount, path], ["/bin/chmod", "755", path]]
}
/// True if `path` is itself a symlink (no follow). Enrollment must REFUSE these: the pre-enroll
/// `lstat` captures the LINK's uid+mode, but `chown`/`chmod`/`chflags` all follow to the target — so
/// enrolling a symlink re-owns and locks the target while a rollback would restore the link's
/// metadata instead, leaving the target service-account-owned. It is also an inducement vector: an
/// agent that can plant a symlink could get an admin to enroll (and hand custody of) an arbitrary
/// file. Callers fail closed and make the operator name the resolved path.
public func isSymlink(_ path: String) -> Bool {
    var st = stat()
    return lstat(path, &st) == 0 && (st.st_mode & S_IFMT) == S_IFLNK
}

/// Ancestors NOT owned by a safe principal OR group/other-writable (agent could swap them). lstat: no follow.
public func checkAncestors(_ path: String, safeOwners: Set<Int>) -> [String] {
    var bad: [String] = []
    var cur = (path as NSString).deletingLastPathComponent
    while true {
        var st = stat()
        if lstat(cur, &st) == 0 {
            let unsafeOwner = !safeOwners.contains(Int(st.st_uid))
            let groupOtherWritable = (st.st_mode & (S_IWGRP | S_IWOTH)) != 0
            if unsafeOwner || groupOtherWritable { bad.append(cur) }
        } // Note: does not inspect ACLs — a documented residual (spec §2 parent-swap).
        if cur == "/" { break }
        let parent = (cur as NSString).deletingLastPathComponent
        if parent == cur { break }
        cur = parent
    }
    return bad
}
public enum CustodyRegistry {
    public static func load(path: String) -> (files: [String], dirs: [String]) {
        guard let d = try? Data(contentsOf: URL(fileURLWithPath: path)),
              let o = (try? JSONSerialization.jsonObject(with: d)) as? [String: Any] else { return ([], []) }
        return (o["files"] as? [String] ?? [], o["dirs"] as? [String] ?? [])
    }
    public static func add(file: String?, dir: String?, path: String) throws {
        // Advisory flock(LOCK_EX) serializes concurrent enroll-* processes across the
        // read–modify–write so two racing adds cannot drop each other's entry (last-writer-wins).
        //
        // Lock a SIBLING `.lock` file, never `path` itself: the atomic write below replaces the
        // registry's inode (write-to-temp + rename), so a lock held on the data file would be
        // orphaned on a now-unlinked inode the moment anyone writes — subsequent callers would open
        // the NEW inode and flock something entirely different, and the mutual exclusion would
        // silently evaporate. Same pattern (and reasoning) as auditAppend. The sibling `.lock` under
        // keydir is control-denied for execute-write by the keydir-prefix rule.
        let lockFD = open(path + ".lock", O_CREAT | O_RDWR, 0o600)
        if lockFD >= 0 { flock(lockFD, LOCK_EX) }
        defer { if lockFD >= 0 { flock(lockFD, LOCK_UN); close(lockFD) } }
        var (files, dirs) = load(path: path)
        // Normalize via Broker.normPath (the SAME normalization the broker uses at comparison time) so
        // /private/var/foo and /var/foo dedup to one entry — idempotency contract (Task-4 review). NOT
        // standardizingPath, which doesn't fold the /private firmlinks.
        if let f = file.map({ Broker.normPath($0) }), !files.contains(f) { files.append(f) }
        if let d = dir.map({ Broker.normPath($0) }), !dirs.contains(d) { dirs.append(d) }
        let data = try JSONSerialization.data(withJSONObject: ["files": files, "dirs": dirs],
                                              options: [.sortedKeys])
        try data.write(to: URL(fileURLWithPath: path), options: [.atomic])
    }
}
