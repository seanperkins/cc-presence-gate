import Foundation
import CCGateCore
/// Broker-side. Reads the hex-encoded X9.63 enrolled pubkey and verifies via CryptoKit seVerify.
public struct TouchIdVerifier: Verifier {
    let allowedSigners: String
    public init(allowedSigners: String) { self.allowedSigners = allowedSigners }
    public func verify(challenge: Data, signature: Data) -> Bool {
        guard let hex = try? String(contentsOfFile: allowedSigners, encoding: .utf8),
              let pub = hexDecode(hex.trimmingCharacters(in: .whitespacesAndNewlines)), !pub.isEmpty
        else { return false }
        return seVerify(message: challenge, signatureDER: signature, publicKeyX963: pub)
    }
}
