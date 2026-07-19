import XCTest
@testable import CCGateCore

final class CanonicalNsTests: XCTestCase {
    // Build a doc the way the current code does (fill with the real buildSignedDocument signature).
    func testNilNsProducesTodaysBytes() throws {
        let a = try canonicalBytes(buildSignedDocument(op: "execute-write", path: "/tmp/x", contentSha256: "ab",
                                                        cwd: "/tmp", nonceHex: "00", callerUid: 501, contentMode: "inline",
                                                        ns: nil))
        let b = try canonicalBytes(buildSignedDocument(op: "execute-write", path: "/tmp/x", contentSha256: "ab",
                                                        cwd: "/tmp", nonceHex: "00", callerUid: 501, contentMode: "inline"))
        XCTAssertEqual(a, b, "ns:nil must not change FIDO canonical bytes")
        XCTAssertFalse(String(data: a, encoding: .utf8)!.contains("\"ns\""))
    }
    func testSetNsIsIncludedAndDiffers() throws {
        let withNs = try canonicalBytes(buildSignedDocument(op: "execute-write", path: "/tmp/x", contentSha256: "ab",
                                                             cwd: "/tmp", nonceHex: "00", callerUid: 501, contentMode: "inline",
                                                             ns: "cc-touch-id-gate/v1"))
        let without = try canonicalBytes(buildSignedDocument(op: "execute-write", path: "/tmp/x", contentSha256: "ab",
                                                              cwd: "/tmp", nonceHex: "00", callerUid: 501, contentMode: "inline",
                                                              ns: nil))
        XCTAssertTrue(String(data: withNs, encoding: .utf8)!.contains("\"ns\":\"cc-touch-id-gate/v1\""))
        XCTAssertNotEqual(withNs, without)
    }
}
