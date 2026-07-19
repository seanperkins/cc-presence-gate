import Foundation

public enum EnrollError: Error { case failed(String) }

/// Thin, method-agnostic driver: run the backend's enroll ceremony, then its positive control.
/// All method-specific behavior (key generation, touch prompts, registration, blink-test) lives
/// behind the `Enroller` seam (Sources/CCFidoBackend/FidoEnroller.swift for FIDO) — core carries
/// no FIDO (or any other backend's) identity.
public func runEnroll(home: String, keys: Int, enroller: Enroller, profile: GateProfile) throws {
    try enroller.enroll(home: home, keys: max(1, keys), profile: profile)
    if !enroller.positiveControl(home: home, profile: profile) {
        throw EnrollError.failed("positive control failed — presence not verified")
    }
}
