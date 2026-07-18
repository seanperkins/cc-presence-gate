import Foundation
import Darwin

public func planEnrollFile(_ path: String, mode: Int) -> [[String]] {
    [["/usr/sbin/chown", "_ccfido", path], ["/bin/chmod", String(mode, radix: 8), path],
     ["/usr/bin/chflags", "uchg", path]]
}
public func planEnrollDir(_ path: String) -> [[String]] {
    [["/usr/sbin/chown", "_ccfido", path], ["/bin/chmod", "755", path]]
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
    public static func load(path: String = Paths.custody) -> (files: [String], dirs: [String]) {
        guard let d = try? Data(contentsOf: URL(fileURLWithPath: path)),
              let o = (try? JSONSerialization.jsonObject(with: d)) as? [String: Any] else { return ([], []) }
        return (o["files"] as? [String] ?? [], o["dirs"] as? [String] ?? [])
    }
    public static func add(file: String?, dir: String?, path: String = Paths.custody) throws {
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
