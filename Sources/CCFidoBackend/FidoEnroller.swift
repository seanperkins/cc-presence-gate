import Foundation
import CCGateCore

/// FIDO-specific `Enroller`: sk-keygen argv, on-disk handle probe, and key-file cleanup. Core's
/// `runEnroll`/`gatherStatus`/`uninstall` are backend-agnostic and consume this through the
/// `Enroller` protocol so a future Secure-Enclave backend can supply its own without touching core.
public struct FidoEnroller: Enroller {
    public init() {}
    /// The `ssh-keygen -t ed25519-sk` argv for key #index (1-based). Touch required. Same shape as
    /// the former core `enrollPlan(home:keys:)` — one step, no behavior change, just relocated.
    public func enrollPlan(home: String, index: Int) -> [[String]] {
        [["-t", "ed25519-sk", "-O", "application=ssh:cc-fido-gate", "-N", "", "-C", "cc-fido-key\(index)",
          "-f", "\(home)/.ccfido/gate_sk\(index)"]]
    }
    /// Privilege-independent probe: is the enroll handle present in the login user's own home?
    public func isEnrolled(home: String) -> Bool {
        FileManager.default.fileExists(atPath: home + "/.ccfido/gate_sk")
    }
    /// Uninstall: delete this user's FIDO key material (handle symlinks + the keys themselves).
    public func removeKeyMaterial(home: String) {
        for f in ["gate_sk", "gate_sk.pub", "gate_sk1", "gate_sk1.pub", "gate_sk2", "gate_sk2.pub"] {
            try? FileManager.default.removeItem(atPath: "\(home)/.ccfido/\(f)")
        }
    }
}
