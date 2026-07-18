import Foundation
public struct GateContext {
    public let profile: GateProfile
    public let signer: Signer
    public let verifier: Verifier
    public let enroller: Enroller
    public init(profile: GateProfile, signer: Signer, verifier: Verifier, enroller: Enroller) {
        self.profile = profile; self.signer = signer; self.verifier = verifier; self.enroller = enroller
    }
}
