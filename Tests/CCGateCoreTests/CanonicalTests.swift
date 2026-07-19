import XCTest
@testable import CCGateCore

final class CanonicalTests: XCTestCase {
    func testGoldenSignedDocumentBytes() throws {
        let doc = buildSignedDocument(op: "execute-write", path: "/tmp/x", contentSha256: "ab",
                                      cwd: "/tmp", nonceHex: "00", callerUid: 501, contentMode: "inline")
        let expected = #"{"caller_uid":501,"content_mode":"inline","content_sha256":"ab","cwd":"/tmp","nonce":"00","op":"execute-write","path":"/tmp/x","v":1}"#
        XCTAssertEqual(String(data: try canonicalBytes(doc), encoding: .utf8), expected)
    }
    func testCanonicalJSONSortsKeys() throws {
        let a = try canonicalJSON(["b": 1, "a": 2])
        XCTAssertEqual(String(data: a, encoding: .utf8), #"{"a":2,"b":1}"#)
    }
    func testCanonicalJSONNestedDeterministic() throws {
        let a = try canonicalJSON(["input": ["z": 1, "a": 2], "tool": "Bash"])
        let b = try canonicalJSON(["tool": "Bash", "input": ["a": 2, "z": 1]])
        XCTAssertEqual(a, b)
    }
}
