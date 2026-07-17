import Foundation
import Darwin

public enum WireError: Error, Equatable { case eof, tooLarge, badBody }
public let MAX_MSG = 8 * 1024 * 1024

func recvRetry(_ fd: Int32, _ buf: UnsafeMutableRawPointer, _ n: Int) -> Int {
    while true { let r = recv(fd, buf, n, 0); if r < 0 && errno == EINTR { continue }; return r }
}
func sendRetry(_ fd: Int32, _ buf: UnsafeRawPointer, _ n: Int) -> Int {
    while true { let r = send(fd, buf, n, 0); if r < 0 && errno == EINTR { continue }; return r }
}

func readExactly(_ fd: Int32, _ n: Int) throws -> Data {
    var buf = Data(); buf.reserveCapacity(n)
    let chunk = 64 * 1024
    var tmp = [UInt8](repeating: 0, count: min(max(n, 1), chunk))
    while buf.count < n {
        let want = min(n - buf.count, tmp.count)
        let r = tmp.withUnsafeMutableBytes { recvRetry(fd, $0.baseAddress!, want) }
        if r <= 0 { throw WireError.eof }
        buf.append(contentsOf: tmp[0..<r])
    }
    return buf
}
func writeAll(_ fd: Int32, _ data: Data) throws {
    try data.withUnsafeBytes { raw in
        var off = 0
        while off < data.count {
            let w = sendRetry(fd, raw.baseAddress!.advanced(by: off), data.count - off)
            if w <= 0 { throw WireError.eof }
            off += w
        }
    }
}
public func sendMsg(_ fd: Int32, _ obj: [String: Any]) throws {
    guard let body = try? JSONSerialization.data(withJSONObject: obj) else { throw WireError.badBody }
    if body.count > MAX_MSG { throw WireError.tooLarge }
    var len = UInt32(body.count).bigEndian
    var frame = Data(bytes: &len, count: 4); frame.append(body)
    try writeAll(fd, frame)
}
public func recvMsg(_ fd: Int32) throws -> [String: Any] {
    let header = try readExactly(fd, 4)
    let length = Int(UInt32(bigEndian: header.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) }))
    if length > MAX_MSG { throw WireError.tooLarge }
    let body = try readExactly(fd, length)
    guard let obj = (try? JSONSerialization.jsonObject(with: body)) as? [String: Any] else {
        throw WireError.badBody
    }
    return obj
}
public func peerUID(_ fd: Int32) -> Int {
    var cred = xucred()
    var len = socklen_t(MemoryLayout<xucred>.size)
    let rc = getsockopt(fd, 0, LOCAL_PEERCRED, &cred, &len)
    return rc == 0 ? Int(cred.cr_uid) : -1   // fail-honest, never 0
}
