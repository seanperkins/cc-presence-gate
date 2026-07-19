import Foundation
public protocol Enroller {
    /// Ordered privileged steps to create + register key #index (1-based). Backend-specific.
    func enrollPlan(home: String, index: Int) -> [[String]]
    /// Is a gate key present for this user? FIDO = key file on disk; SE = keychain query.
    func isEnrolled(home: String) -> Bool
    /// Delete this method's key material (uninstall). FIDO = rm key files; SE = keychain delete.
    func removeKeyMaterial(home: String)
}
