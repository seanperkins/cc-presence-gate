import XCTest
import Darwin
@testable import CCGateCore

final class WireTests: XCTestCase {
    private func pair() -> (Int32, Int32) {
        var fds: [Int32] = [0, 0]
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &fds), 0)
        return (fds[0], fds[1])
    }
    func testRoundtrip() throws {
        let (a, b) = pair(); defer { close(a); close(b) }
        try sendMsg(a, ["op": "execute-write", "path": "/x", "content_b64": "aGk="])
        let got = try recvMsg(b)
        XCTAssertEqual(got["op"] as? String, "execute-write")
        XCTAssertEqual(got["content_b64"] as? String, "aGk=")
    }
    func testRecvOnClosedPeerThrows() {
        let (a, b) = pair(); close(a)
        XCTAssertThrowsError(try recvMsg(b)) { _ in close(b) }
    }
    func testOversizeLengthRejected() {
        let (a, b) = pair(); defer { close(a); close(b) }
        var len = UInt32(0x7fffffff).bigEndian
        withUnsafeBytes(of: &len) { _ = send(a, $0.baseAddress, 4, 0) }
        XCTAssertThrowsError(try recvMsg(b))
    }
    func testInvalidJSONRaisesBadBody() throws {
        let (a, b) = pair(); defer { close(a); close(b) }
        let body = Data("{not json".utf8)
        var len = UInt32(body.count).bigEndian
        var frame = Data(bytes: &len, count: 4); frame.append(body)
        _ = frame.withUnsafeBytes { send(a, $0.baseAddress, frame.count, 0) }
        XCTAssertThrowsError(try recvMsg(b)) { XCTAssertEqual($0 as? WireError, .badBody) }
    }
    func testPeerUIDMatchesSelf() {
        let (a, b) = pair(); defer { close(a); close(b) }
        XCTAssertEqual(peerUID(a), Int(getuid()))
    }
}
