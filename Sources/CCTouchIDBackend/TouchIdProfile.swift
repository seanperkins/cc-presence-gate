import Foundation
import CCGateCore
public let touchIdProfile = GateProfile(
    serviceAccount: "_cctouchid", accountRealName: "cc-touch-id broker",
    namespace: "cc-touch-id-gate/v1",
    keydir: "/var/cctouchid", runDir: "/var/cctouchid-run", sock: "/var/cctouchid-run/gate.sock",
    daemonLogErr: "/var/cctouchid/brokerd.err",
    codeDir: "/opt/cc-touch-id-gate", policy: "/opt/cc-touch-id-gate/policy.json",
    binaryName: "cc-touch-id", displayName: "cc-touch-id",
    launchdLabel: "com.cc-touch-id-gate.brokerd",
    plist: "/Library/LaunchDaemons/com.cc-touch-id-gate.brokerd.plist",
    daemonMatchPattern: "cc-touch-id daemon",
    claudeCodeDir: "/Library/Application Support/ClaudeCode",
    managedSettings: "/Library/Application Support/ClaudeCode/managed-settings.json")

public func makeTouchIdContext(home: String) -> GateContext {
    GateContext(profile: touchIdProfile, ceremony: TouchIdCeremony(),
                verifier: TouchIdVerifier(allowedSigners: touchIdProfile.allowedSigners),
                enroller: TouchIdEnroller())
}
