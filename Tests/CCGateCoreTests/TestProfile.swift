import Foundation
@testable import CCGateCore

// Shared GateProfile fixture for core tests. CCGateCoreTests cannot import CCFidoBackend (Package.swift
// dependency graph), so this mirrors `fidoProfile` (Sources/CCFidoBackend/FidoProfile.swift) field-for-field
// — the exact values today's Paths constants had. FIDO literals here are fine: the Task-9 core grep gate
// scans Sources/CCGateCore only, never Tests/.
let testProfile = GateProfile(
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
