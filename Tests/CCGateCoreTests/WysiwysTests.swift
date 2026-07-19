import XCTest
@testable import CCGateCore

final class WysiwysTests: XCTestCase {
    private func doc(_ path: String, _ content: Data) -> SignedDocument {
        buildSignedDocument(op: "execute-write", path: path, contentSha256: sha256Hex(content),
                            cwd: "/tmp", nonceHex: "00", callerUid: 501)
    }
    func testHomoglyphPathsRenderDistinctly() {
        let a = humanRendering(doc("/Users/sean/.zshrc", Data("x".utf8)), content: Data("x".utf8))
        let b = humanRendering(doc("/Users/s\u{0435}an/.zshrc", Data("x".utf8)), content: Data("x".utf8))
        XCTAssertNotEqual(a, b)
    }
    func testZeroWidthEscaped() {
        let r = humanRendering(doc("/tmp/a\u{200B}b", Data("x".utf8)), content: Data("x".utf8))
        XCTAssertFalse(r.contains("\u{200B}")); XCTAssertTrue(r.contains("U+200B"))
    }
    func testEscapeIsInjective_literalAngleBracketDiffersFromRealZWS() {
        // real U+200B vs the literal characters "<U+200B>" must NOT render identically
        let real = humanRendering(doc("/tmp/a\u{200B}b", Data("x".utf8)), content: Data("x".utf8))
        let literal = humanRendering(doc("/tmp/a<U+200B>b", Data("x".utf8)), content: Data("x".utf8))
        XCTAssertNotEqual(real, literal)
    }
    func testTrailingWhitespaceSurfaced() {
        XCTAssertNotEqual(humanRendering(doc("/tmp/x", Data("cmd".utf8)), content: Data("cmd".utf8)),
                          humanRendering(doc("/tmp/x", Data("cmd ".utf8)), content: Data("cmd ".utf8)))
    }
    func testDigestModeFullHashNoContent() {
        let big = Data(repeating: 0x41, count: INLINE_MAX + 1)
        let r = humanRendering(doc("/tmp/big", big), content: big)
        XCTAssertTrue(r.contains(sha256Hex(big)))            // FULL 64-hex digest
        XCTAssertTrue(r.contains("\(big.count) bytes"))
        XCTAssertFalse(r.contains(String(repeating: "A", count: 50)))
    }
}
