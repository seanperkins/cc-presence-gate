import Foundation
public protocol Enroller {
    /// Run the full, method-specific enroll ceremony (key generation + touch + registration).
    /// Backend-specific end to end — core no longer knows the shape of the ceremony.
    func enroll(home: String, keys: Int, profile: GateProfile) throws
    /// Verify touch-required presence AFTER enroll (e.g. FIDO's negative-blink test).
    func positiveControl(home: String, profile: GateProfile) -> Bool
    /// Is a gate key present for this user? FIDO = key file on disk; SE = keychain query.
    func isEnrolled(home: String) -> Bool
    /// Delete this method's key material (uninstall). FIDO = rm key files; SE = keychain delete.
    func removeKeyMaterial(home: String)
}
