import Foundation

public enum Paths {
    public static let keydir = "/var/ccfido"
    public static let runDir = "/var/ccfido-run"
    public static let sock = "/var/ccfido-run/gate.sock"
    public static let allowedSigners = "/var/ccfido/allowed_signers"
    public static let audit = "/var/ccfido/audit.log"
    public static let custody = "/var/ccfido/custody.json"
    public static let ceremonyLock = "/var/ccfido/ceremony.lock"
    public static let policy = "/opt/cc-fido-gate/policy.json"
    public static let code = "/opt/cc-fido-gate"
    public static let handle = (NSHomeDirectory() as NSString).appendingPathComponent(".ccfido/gate_sk")
    public static let namespace = "cc-fido-gate@example.test"
    public static let principal = "gate-principal"
    public static let signKeygen = "/opt/homebrew/opt/openssh/bin/ssh-keygen"
    public static let verifyKeygen = "/usr/bin/ssh-keygen"
    // execute-write is UNCONDITIONALLY denied to these + anything under keydir/code:
    public static let controlDenylist = [allowedSigners, audit, custody, ceremonyLock, sock, policy]
    public static let launchdLabel = "com.cc-fido-gate.brokerd"
    public static let plist = "/Library/LaunchDaemons/com.cc-fido-gate.brokerd.plist"
    public static let claudeCodeDir = "/Library/Application Support/ClaudeCode"
    public static let managedSettings = "/Library/Application Support/ClaudeCode/managed-settings.json"
}
