import Foundation
public protocol Signer {
    /// A fresh cancellation handle, one per ceremony. `confirmAndSign` mints one and threads it into `sign`.
    func makeCanceller() -> CeremonyCanceller
    /// Non-optional: every ceremony must pass a handle so the nil-canceller hang is unrepresentable.
    func sign(challenge: Data, canceller: CeremonyCanceller) throws -> Data
}
