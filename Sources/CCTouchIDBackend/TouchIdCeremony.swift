import Foundation
import CCGateCore
/// Client-side. The native Touch ID sheet IS the presence ceremony (no osascript). reason = rendering
/// (verb-phrase; large writes already digest-mode in the shared humanRendering). Fail-closed → nil.
public final class TouchIdCeremony: GateCeremony {
    public init() {}
    public func confirmAndSign(rendering: String, challenge: Data, displayName: String) -> Data? {
        let canceller = TouchIDCanceller()
        return try? seSign(message: challenge, tag: touchIdKeyTag, reason: rendering, canceller: canceller)
    }
}
