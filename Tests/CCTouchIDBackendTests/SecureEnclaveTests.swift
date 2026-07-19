import CryptoKit
import Foundation
import XCTest
@testable import CCTouchIDBackend

/// `seVerify` is format-only (agnostic to whether the private key was SE-backed), so software P-256
/// keys are a legitimate unit-test fixture — the daemon runs exactly this code path against real SE output.
final class SecureEnclaveTests: XCTestCase {
    func testVerifyAcceptsValidSignature() throws {
        let priv = P256.Signing.PrivateKey()
        let pub = priv.publicKey.x963Representation
        let msg = Data("hello".utf8)
        let sig = try priv.signature(for: msg).derRepresentation   // SHA256 hashed internally
        XCTAssertTrue(seVerify(message: msg, signatureDER: sig, publicKeyX963: pub))
    }
    func testVerifyRejectsTamperedMessage() throws {
        let priv = P256.Signing.PrivateKey()
        let sig = try priv.signature(for: Data("hello".utf8)).derRepresentation
        XCTAssertFalse(seVerify(message: Data("hell0".utf8), signatureDER: sig,
                                publicKeyX963: priv.publicKey.x963Representation))
    }
    func testVerifyRejectsWrongKey() throws {
        let priv = P256.Signing.PrivateKey(), other = P256.Signing.PrivateKey()
        let msg = Data("hello".utf8)
        let sig = try priv.signature(for: msg).derRepresentation
        XCTAssertFalse(seVerify(message: msg, signatureDER: sig,
                                publicKeyX963: other.publicKey.x963Representation))
    }
    func testVerifyRejectsGarbage() {
        XCTAssertFalse(seVerify(message: Data("x".utf8), signatureDER: Data([0, 1, 2]),
                                publicKeyX963: Data([4, 0, 0])))
    }
}
