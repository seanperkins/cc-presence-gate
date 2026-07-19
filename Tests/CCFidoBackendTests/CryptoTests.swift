import XCTest
import Foundation
@testable import CCFidoBackend

final class CryptoTests: XCTestCase {
    private func mkSoftwareKey() throws -> (key: String, allowed: String, keydir: String) {
        let dir = NSTemporaryDirectory() + "ccfg-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        let key = dir + "/id"
        let p = Process(); p.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-keygen")
        p.arguments = ["-t", "ed25519", "-N", "", "-C", "gate-principal", "-f", key]
        p.standardOutput = FileHandle.nullDevice; p.standardError = FileHandle.nullDevice
        try p.run(); p.waitUntilExit()
        let pub = try String(contentsOfFile: key + ".pub", encoding: .utf8)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let allowed = dir + "/allowed_signers"
        try "gate-principal \(pub)\n".write(toFile: allowed, atomically: true, encoding: .utf8)
        return (key, allowed, dir)
    }
    func testSignVerifyRoundtrip() throws {
        let (key, allowed, dir) = try mkSoftwareKey()
        let challenge = Data("canonical challenge bytes".utf8)
        let sig = try fidoSign(challenge: challenge, handlePath: key, namespace: "cc-fido-gate@example.test",
                           keygen: "/usr/bin/ssh-keygen")
        XCTAssertTrue(String(data: sig, encoding: .utf8)!.contains("BEGIN SSH SIGNATURE"))
        // verify() must use a real, readable sig path — the keydir temp file. Pass dir as the temp root.
        XCTAssertTrue(fidoVerify(challenge: challenge, signature: sig, allowedSigners: allowed,
                             principal: "gate-principal", namespace: "cc-fido-gate@example.test",
                             keygen: "/usr/bin/ssh-keygen", keydir: dir))
    }
    func testTamperRejected() throws {
        let (key, allowed, dir) = try mkSoftwareKey()
        let sig = try fidoSign(challenge: Data("original".utf8), handlePath: key,
                           namespace: "cc-fido-gate@example.test", keygen: "/usr/bin/ssh-keygen")
        XCTAssertFalse(fidoVerify(challenge: Data("tampered".utf8), signature: sig, allowedSigners: allowed,
                              principal: "gate-principal", namespace: "cc-fido-gate@example.test",
                              keygen: "/usr/bin/ssh-keygen", keydir: dir))
    }
    func testWrongNamespaceRejected() throws {
        let (key, allowed, dir) = try mkSoftwareKey()
        let sig = try fidoSign(challenge: Data("m".utf8), handlePath: key,
                           namespace: "cc-fido-gate@example.test", keygen: "/usr/bin/ssh-keygen")
        XCTAssertFalse(fidoVerify(challenge: Data("m".utf8), signature: sig, allowedSigners: allowed,
                              principal: "gate-principal", namespace: "other@example.test",
                              keygen: "/usr/bin/ssh-keygen", keydir: dir))
    }
}
