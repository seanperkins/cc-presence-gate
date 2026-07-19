import Foundation
import CryptoKit
import LocalAuthentication
import Security

/// Daemon-side, biometrics-free. Verifies a DER ECDSA-P256-SHA256 signature (as produced by
/// `SecKeyCreateSignature(.ecdsaSignatureMessageX962SHA256)`) against an X9.63 public key
/// (`0x04 || X || Y`). Pure math — no Secure Enclave, no session, no subprocess. Replaces
/// `ssh-keygen -Y verify`. Presence is protected at signing time, not here (same as the FIDO design).
public func seVerify(message: Data, signatureDER: Data, publicKeyX963: Data) -> Bool {
    guard signatureDER.count > 0, signatureDER.count <= 150,        // DER P-256 sig is ~70-72 bytes
          let pub = try? P256.Signing.PublicKey(x963Representation: publicKeyX963),
          let sig = try? P256.Signing.ECDSASignature(derRepresentation: signatureDER)
    else { return false }
    return pub.isValidSignature(sig, for: message)                  // hashes message with SHA-256 internally
}

// MARK: - Client-side Secure Enclave signing (requires SE + a biometry-gated key; validated on-device)

public enum SEError: Error, CustomStringConvertible {
    case userCancelled
    case notFound(OSStatus)
    case accessControl(String)
    case keygen(String)
    case sign(Int, String)
    case noPublicKey
    case export(String)
    public var description: String {
        switch self {
        case .userCancelled:        return "denied (Touch ID cancelled)"
        case .notFound(let s):      return "SE key not found (OSStatus \(s))"
        case .accessControl(let m): return "access control: \(m)"
        case .keygen(let m):        return "SE keygen failed: \(m)"
        case .sign(let c, let m):   return "sign failed (code \(c)): \(m)"
        case .noPublicKey:          return "could not copy public key"
        case .export(let m):        return "public-key export failed: \(m)"
        }
    }
}

/// Cancels an in-flight `seSign` — a concurrent dialog's Cancel/give-up invalidates the `LAContext`
/// driving the Touch ID prompt, dismissing it. Thread-safe. Replaces the FIDO `SignCanceller` (which
/// terminated an ssh-keygen `Process`); here there is no subprocess, only the biometric context.
public final class TouchIDCanceller {
    private let lock = NSLock()
    private var ctx: LAContext?
    private var cancelled = false
    /// Adopt the context so a later cancel() can invalidate it. Returns false if already cancelled.
    func bind(_ c: LAContext) -> Bool { lock.lock(); defer { lock.unlock() }
        if cancelled { c.invalidate(); return false }; ctx = c; return true }
    public func cancel() { lock.lock(); defer { lock.unlock() }; cancelled = true; ctx?.invalidate() }
    public var isCancelled: Bool { lock.lock(); defer { lock.unlock() }; return cancelled }
    public init() {}
}

/// Fetch the enrolled key ref. Copying the ref does not prompt; only a private-key *operation* does.
/// A non-nil `context` binds the biometric prompt (and its localizedReason) to the subsequent sign.
func seFetchKey(tag: String, context: LAContext?) throws -> SecKey {
    var q: [String: Any] = [
        kSecClass as String: kSecClassKey,
        kSecAttrApplicationTag as String: Data(tag.utf8),
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecReturnRef as String: true,
    ]
    if let c = context { q[kSecUseAuthenticationContext as String] = c }
    var item: CFTypeRef?
    let st = SecItemCopyMatching(q as CFDictionary, &item)
    guard st == errSecSuccess, let it = item else { throw SEError.notFound(st) }
    return (it as! SecKey)
}

/// Create a biometry-gated P-256 key in the Secure Enclave. Every future signature forces Touch ID
/// (`.biometryCurrentSet`); the private key is non-exportable. `accessGroup == nil` uses the signer's
/// default (application-identifier) keychain group. Requires an entitled, provisioned binary.
public func seCreateKey(tag: String, accessGroup: String? = nil) throws -> SecKey {
    var acErr: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        [.privateKeyUsage, .biometryCurrentSet], &acErr) else {
        throw SEError.accessControl("\(acErr!.takeRetainedValue())")
    }
    var priv: [String: Any] = [
        kSecAttrIsPermanent as String: true,
        kSecAttrApplicationTag as String: Data(tag.utf8),
        kSecAttrAccessControl as String: access,
    ]
    if let g = accessGroup { priv[kSecAttrAccessGroup as String] = g }
    let attrs: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits as String: 256,
        kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
        kSecPrivateKeyAttrs as String: priv,
    ]
    var err: Unmanaged<CFError>?
    guard let key = SecKeyCreateRandomKey(attrs as CFDictionary, &err) else {
        throw SEError.keygen("\(err!.takeRetainedValue())")
    }
    return key
}

public func seKeyExists(tag: String) -> Bool { (try? seFetchKey(tag: tag, context: nil)) != nil }

/// Export the enrolled key's public half as X9.63 bytes (for the daemon's `enrolled_pubkey` custody).
/// Public-key access needs no biometrics.
public func seExportPublicKey(tag: String) throws -> Data {
    guard let pub = SecKeyCopyPublicKey(try seFetchKey(tag: tag, context: nil)) else { throw SEError.noPublicKey }
    var e: Unmanaged<CFError>?
    guard let ext = SecKeyCopyExternalRepresentation(pub, &e) as Data? else {
        throw SEError.export("\(e!.takeRetainedValue())")
    }
    return ext
}

/// Sign `message` with the enrolled SE key — TRIGGERS a Touch ID prompt (`reason` shown to the user).
/// Returns a DER ECDSA-P256-SHA256 signature that `seVerify` accepts. An agent can call this but has no
/// finger, so it cannot satisfy the prompt: the whole inversion. Requires the biometry-gated key + a GUI session.
public func seSign(message: Data, tag: String = touchIdKeyTag, reason: String,
                   canceller: TouchIDCanceller? = nil) throws -> Data {
    if canceller?.isCancelled == true { throw SEError.userCancelled }
    let ctx = LAContext()
    ctx.localizedReason = reason                                    // modern prompt path (kSecUseOperationPrompt is deprecated)
    ctx.touchIDAuthenticationAllowableReuseDuration = 0            // TID-3: re-prompt every signature, no reuse
    if let c = canceller, !c.bind(ctx) { throw SEError.userCancelled }
    let key = try seFetchKey(tag: tag, context: ctx)
    var err: Unmanaged<CFError>?
    guard let sig = SecKeyCreateSignature(key, .ecdsaSignatureMessageX962SHA256, message as CFData, &err) as Data? else {
        let e = err!.takeRetainedValue() as Error
        let code = (e as NSError).code
        if code == errSecUserCanceled { throw SEError.userCancelled }
        throw SEError.sign(code, "\(e)")
    }
    return sig
}

@discardableResult
public func seDeleteKey(tag: String) -> OSStatus {
    SecItemDelete([kSecClass as String: kSecClassKey, kSecAttrApplicationTag as String: Data(tag.utf8)] as CFDictionary)
}

/// Cryptographically-random challenge bytes (nonce / presence-test challenge).
public func randomBytes(_ n: Int) -> Data {
    var d = Data(count: n)
    let ok = d.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, n, $0.baseAddress!) == errSecSuccess }
    precondition(ok, "SecRandomCopyBytes failed")
    return d
}

public func hexEncode(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }
public func hexDecode(_ s: String) -> Data? {
    let c = s.filter { !$0.isWhitespace }
    guard c.count % 2 == 0 else { return nil }
    var d = Data(); d.reserveCapacity(c.count / 2); var i = c.startIndex
    while i < c.endIndex { let j = c.index(i, offsetBy: 2)
        guard let b = UInt8(c[i..<j], radix: 16) else { return nil }; d.append(b); i = j }
    return d
}
