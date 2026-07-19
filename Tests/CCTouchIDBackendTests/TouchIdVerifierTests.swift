import XCTest
import Security
@testable import CCTouchIDBackend

final class TouchIdVerifierTests: XCTestCase {
    private func softwareKeyAndPubHex() -> (SecKey, String) {
        var e: Unmanaged<CFError>?
        let priv = SecKeyCreateRandomKey([kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                                          kSecAttrKeySizeInBits as String: 256] as CFDictionary, &e)!
        let raw = SecKeyCopyExternalRepresentation(SecKeyCopyPublicKey(priv)!, &e)! as Data
        return (priv, hexEncode(raw))
    }
    private func sign(_ p: SecKey, _ m: Data) -> Data {
        var e: Unmanaged<CFError>?; return SecKeyCreateSignature(p, .ecdsaSignatureMessageX962SHA256, m as CFData, &e)! as Data
    }
    private func writeHex(_ hex: String) -> String {
        let path = NSTemporaryDirectory() + "tidpub-\(getpid())-\(hex.prefix(6))"
        try! hex.write(toFile: path, atomically: true, encoding: .utf8); return path
    }
    func testEnrolledKeyVerifies() {
        let (p, hex) = softwareKeyAndPubHex(); let c = Data("hi".utf8); let s = sign(p, c)
        XCTAssertTrue(TouchIdVerifier(allowedSigners: writeHex(hex)).verify(challenge: c, signature: s))
    }
    func testWrongKeyRejected() {
        let (p, _) = softwareKeyAndPubHex(); let (_, otherHex) = softwareKeyAndPubHex()
        let c = Data("hi".utf8); let s = sign(p, c)
        XCTAssertFalse(TouchIdVerifier(allowedSigners: writeHex(otherHex)).verify(challenge: c, signature: s))
    }
    func testTamperedChallengeRejected() {
        let (p, hex) = softwareKeyAndPubHex(); let s = sign(p, Data("hi".utf8))
        XCTAssertFalse(TouchIdVerifier(allowedSigners: writeHex(hex)).verify(challenge: Data("ho".utf8), signature: s))
    }
    func testMissingFileRejects() {
        XCTAssertFalse(TouchIdVerifier(allowedSigners: "/no/such").verify(challenge: Data("x".utf8), signature: Data([0])))
    }
}
