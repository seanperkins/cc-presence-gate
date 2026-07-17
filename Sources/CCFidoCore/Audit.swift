import Foundation
import Darwin
import CryptoKit

public func sha256Hex(_ data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}
func auditLines(_ path: String) -> [String] {
    (try? String(contentsOfFile: path, encoding: .utf8))?.split(separator: "\n").map(String.init) ?? []
}
public func auditAppend(_ entry: [String: Any], path: String = Paths.audit) throws {
    let lines = auditLines(path)
    var rec = entry
    rec["seq"] = lines.count
    rec["prev_hash"] = lines.last.map { sha256Hex(Data($0.utf8)) } ?? String(repeating: "0", count: 64)
    rec["ts"] = Date().timeIntervalSince1970
    var line = String(data: try JSONSerialization.data(withJSONObject: rec, options: [.sortedKeys]),
                      encoding: .utf8)! + "\n"
    let fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0o600)
    guard fd >= 0 else { throw WireError.eof }
    defer { close(fd) }
    let ok = line.withUTF8 { p -> Bool in
        var off = 0
        while off < p.count { let w = write(fd, p.baseAddress!.advanced(by: off), p.count - off)
            if w <= 0 { return false }; off += w }
        return true
    }
    fsync(fd)
    if !ok { throw WireError.eof }
}
