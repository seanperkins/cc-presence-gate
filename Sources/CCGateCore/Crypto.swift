import Foundation
import Darwin

public enum SignError: Error { case failed(String) }
public let MAX_SIG = 64 * 1024   // sk signatures are < 1 KiB; cap defensively

// The runtime child-spawn env (sign/verify/dialog/blink). Single source of truth = scrubEnv (HookLogic):
// one literal allowlist, so hardening it in one place can't desync hook-context vs child-spawn scrubbing
// (Task-6 review Important).
public func scrubbedEnv() -> [String: String] {
    return scrubEnv(ProcessInfo.processInfo.environment)
}
