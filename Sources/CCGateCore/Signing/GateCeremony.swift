import Foundation
/// Client-side presence ceremony: method-specific UI that shows what is being signed and returns a
/// challenge-bound signature on approval, nil on deny/cancel/timeout. FIDO = osascript + armed key;
/// Touch ID = native biometric sheet. Lives in core; impls live in backends.
public protocol GateCeremony {
    func confirmAndSign(rendering: String, challenge: Data, displayName: String) -> Data?
}
