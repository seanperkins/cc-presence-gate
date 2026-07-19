import Foundation
public struct GateContext {
    public let profile: GateProfile
    public let ceremony: GateCeremony
    public let verifier: Verifier
    public let enroller: Enroller
    public init(profile: GateProfile, ceremony: GateCeremony, verifier: Verifier, enroller: Enroller) {
        self.profile = profile; self.ceremony = ceremony; self.verifier = verifier; self.enroller = enroller
    }
}
