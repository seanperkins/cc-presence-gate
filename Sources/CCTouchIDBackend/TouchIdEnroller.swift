import Foundation
import CCGateCore
public struct TouchIdEnroller: Enroller {
    let priv: ([String]) -> Bool
    public init(priv: @escaping ([String]) -> Bool = { runPrivileged($0) }) { self.priv = priv }

    /// Overwrite the single enrolled hex-X9.63 pubkey ($1 positional — never interpolated).
    @discardableResult
    public func register(pubHex: String, profile: GateProfile) -> Bool {
        priv(["/bin/sh", "-c", "printf '%s\\n' \"$1\" > \(profile.allowedSigners)", "sh", pubHex])
    }
    public func enroll(home: String, keys: Int, profile: GateProfile) throws {
        seDeleteKey(tag: touchIdKeyTag)                                   // idempotent re-enroll
        FileHandle.standardError.write(Data(">>> Creating the cc-touch-id Secure Enclave key <<<\n".utf8))
        _ = try seCreateKey(tag: touchIdKeyTag)                           // needs the entitled binary
        let pubHex = hexEncode(try seExportPublicKey(tag: touchIdKeyTag))
        guard register(pubHex: pubHex, profile: profile) else { throw EnrollError.failed("register pubkey") }
        guard priv(["/usr/sbin/chown", profile.serviceAccount, profile.allowedSigners]) else {
            throw EnrollError.failed("chown allowed_signers")
        }
        guard priv(["/bin/chmod", "600", profile.allowedSigners]) else {
            throw EnrollError.failed("chmod allowed_signers")
        }
    }
    public func positiveControl(home: String, profile: GateProfile) -> Bool {
        // Verify against the SE key's OWN exported public key, NOT the on-disk registered file:
        // `enroll` has just chowned `allowedSigners` to the service account (mode 600), and this
        // self-test runs as the LOGIN user, which therefore cannot read it (EACCES). The registered
        // file IS `hexEncode(seExportPublicKey(tag))` — the same bytes — so verifying against the live
        // export is equivalent and avoids the permission cross. (The daemon, running AS the service
        // account, reads the file fine at runtime.)
        guard let pub = try? seExportPublicKey(tag: touchIdKeyTag) else { return false }
        let nonce = randomBytes(32)
        FileHandle.standardError.write(Data(">>> TOUCH to confirm enrollment <<<\n".utf8))
        guard let sig = try? seSign(message: nonce, tag: touchIdKeyTag, reason: "confirm cc-touch-id enrollment") else { return false }
        return seVerify(message: nonce, signatureDER: sig, publicKeyX963: pub)
    }
    public func isEnrolled(home: String) -> Bool { seKeyExists(tag: touchIdKeyTag) }
    public func removeKeyMaterial(home: String) { _ = seDeleteKey(tag: touchIdKeyTag) }
}
