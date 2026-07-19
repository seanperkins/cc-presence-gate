import XCTest
@testable import CCTouchIDBackend

final class TouchIdCeremonyTests: XCTestCase {
    func testCancellerIdempotent() {
        let c = TouchIDCanceller(); c.cancel(); c.cancel(); XCTAssertTrue(c.isCancelled)
    }
    func testDeniesWhenNoKeyEnrolled() {
        seDeleteKey(tag: touchIdKeyTag)   // ensure clean
        // No enrolled key -> seSign throws notFound -> ceremony returns nil (deny).
        XCTAssertNil(TouchIdCeremony().confirmAndSign(rendering: "x", challenge: Data("x".utf8), displayName: "cc-touch-id"))
    }
}
