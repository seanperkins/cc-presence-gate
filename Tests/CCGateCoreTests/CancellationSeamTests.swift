import XCTest
@testable import CCGateCore
final class CancellationSeamTests: XCTestCase {
    final class FakeCanceller: CeremonyCanceller {
        let sem = DispatchSemaphore(value: 0)
        func cancel() { sem.signal() }
    }
    struct FakeSigner: Signer {
        let c = FakeCanceller()
        func makeCanceller() -> CeremonyCanceller { c }
        func sign(challenge: Data, canceller: CeremonyCanceller) throws -> Data {
            // block until THIS handle is cancelled
            (canceller as! FakeCanceller).sem.wait()
            throw SignError.failed("cancelled")
        }
    }
    func testCancelHandleAbortsBlockedSignPromptly() {
        let signer = FakeSigner()
        let handle = signer.makeCanceller()
        let started = expectation(description: "sign returned")
        DispatchQueue.global().async {
            _ = try? signer.sign(challenge: Data(), canceller: handle)
            started.fulfill()
        }
        handle.cancel()
        wait(for: [started], timeout: 2.0)   // promptly, not the 90s backstop
    }
}
