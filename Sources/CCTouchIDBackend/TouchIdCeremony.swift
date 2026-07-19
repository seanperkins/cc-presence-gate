import Foundation
import CCGateCore
/// Client-side. The native Touch ID sheet IS the presence ceremony (no osascript). reason = rendering
/// (verb-phrase; large writes already digest-mode in the shared humanRendering). Fail-closed → nil.
///
/// The native sheet has NO give-up of its own: an explicit Cancel/Escape denies (seSign throws
/// userCancelled → nil), but a walked-away sheet stays open indefinitely. So we run seSign on a
/// background thread and, if the user neither touches nor cancels within `giveUp`, invalidate the
/// LAContext to dismiss the sheet and deny — the analog of FIDO's osascript "giving up after 60".
public final class TouchIdCeremony: GateCeremony {
    /// Walk-away give-up. Kept under the broker's 90s `ceremonyDeadline` so the client returns a clean
    /// deny before the daemon times out on the socket.
    static let giveUp: TimeInterval = 60

    public init() {}
    public func confirmAndSign(rendering: String, challenge: Data, displayName: String) -> Data? {
        let canceller = TouchIDCanceller()
        let sem = DispatchSemaphore(value: 0)
        let lock = NSLock()
        var result: Data? = nil
        DispatchQueue.global().async {
            let s = try? seSign(message: challenge, tag: touchIdKeyTag, reason: rendering, canceller: canceller)
            lock.lock(); result = s; lock.unlock()
            sem.signal()
        }
        if sem.wait(timeout: .now() + TouchIdCeremony.giveUp) == .timedOut {
            canceller.cancel()   // LAContext.invalidate() → dismiss the sheet; seSign throws → result stays nil
            sem.wait()           // let the sign thread unwind before returning
        }
        lock.lock(); let out = result; lock.unlock()
        return out
    }
}
