import Foundation
import CCGateCore
public let fidoProfile = GateProfile(
    serviceAccount: "_ccfido", accountRealName: "cc-fido broker",
    namespace: "cc-fido-gate@example.test",
    keydir: "/var/ccfido", runDir: "/var/ccfido-run", sock: "/var/ccfido-run/gate.sock",
    daemonLogErr: "/var/ccfido/brokerd.err",
    codeDir: "/opt/cc-fido-gate", policy: "/opt/cc-fido-gate/policy.json",
    binaryName: "cc-fido", displayName: "cc-fido-gate",
    launchdLabel: "com.cc-fido-gate.brokerd",
    plist: "/Library/LaunchDaemons/com.cc-fido-gate.brokerd.plist",
    daemonMatchPattern: "cc-fido daemon",
    claudeCodeDir: "/Library/Application Support/ClaudeCode",
    managedSettings: "/Library/Application Support/ClaudeCode/managed-settings.json")

// FIDO key handle is HOME-relative — composed here, NEVER a literal "~".
public func fidoKeyHandle(home: String) -> String { home + "/.ccfido/gate_sk" }
public let fidoSignKeygen = "/opt/homebrew/opt/openssh/bin/ssh-keygen"   // TODO Task 8 preflight: arch-aware
public let fidoVerifyKeygen = "/usr/bin/ssh-keygen"

public func makeFidoContext(home: String) -> GateContext {
    let signer = FidoSigner(keygen: fidoSignKeygen, handlePath: fidoKeyHandle(home: home), namespace: fidoProfile.namespace)
    return GateContext(
        profile: fidoProfile,
        ceremony: FidoCeremony(signer: signer),
        verifier: FidoVerifier(keygen: fidoVerifyKeygen, allowedSigners: fidoProfile.allowedSigners,
                               principal: "gate-principal", namespace: fidoProfile.namespace, keydir: fidoProfile.keydir),
        enroller: FidoEnroller())
}
