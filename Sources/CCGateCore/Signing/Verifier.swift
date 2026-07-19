import Foundation
public protocol Verifier {
    /// Broker-side. Returns true iff `signature` is a valid signature over `challenge` from an enrolled key.
    func verify(challenge: Data, signature: Data) -> Bool
}
