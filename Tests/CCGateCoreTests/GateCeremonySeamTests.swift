import XCTest
@testable import CCGateCore

final class GateCeremonySeamTests: XCTestCase {
    struct FakeCeremony: GateCeremony {
        let out: Data?
        func confirmAndSign(rendering: String, challenge: Data, displayName: String) -> Data? { out }
    }
    func testGateContextHoldsACeremony() {
        let ctx = GateContext(profile: testProfile, ceremony: FakeCeremony(out: Data([1,2,3])),
                              verifier: AlwaysVerifier(ok: true), enroller: NoopEnroller())
        XCTAssertEqual(ctx.ceremony.confirmAndSign(rendering: "r", challenge: Data(), displayName: "d"), Data([1,2,3]))
    }
    func testCeremonyDenyIsNil() {
        let c: GateCeremony = FakeCeremony(out: nil)
        XCTAssertNil(c.confirmAndSign(rendering: "r", challenge: Data(), displayName: "d"))
    }
}
struct AlwaysVerifier: Verifier { let ok: Bool; func verify(challenge: Data, signature: Data) -> Bool { ok } }
struct NoopEnroller: Enroller {
    func enroll(home: String, keys: Int, profile: GateProfile) throws {}
    func positiveControl(home: String, profile: GateProfile) -> Bool { true }
    func isEnrolled(home: String) -> Bool { false }
    func removeKeyMaterial(home: String) {}
}
