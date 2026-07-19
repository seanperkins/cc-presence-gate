import Foundation
/// All per-product filesystem topology + identity. Replaces the old `Paths` constant bag.
/// Crypto-primitive details (keygen paths, key handle, ssh signing principal) do NOT live here —
/// they are backend constructor args.
public struct GateProfile {
    public let serviceAccount: String      // e.g. "_gatesvc"
    public let accountRealName: String     // e.g. "gate broker"
    public let namespace: String           // signing-domain separator, e.g. "gate@example.test"
    public let keydir: String              // e.g. "/var/mygate"
    public let runDir: String              // e.g. "/var/mygate-run"
    public let sock: String                // e.g. "/var/mygate-run/gate.sock"
    public let daemonLogErr: String        // e.g. "/var/mygate/daemon.err"
    public let codeDir: String             // e.g. "/opt/mygate"
    public let policy: String              // e.g. "/opt/mygate/policy.json"
    public let binaryName: String          // e.g. "mygate"
    public let displayName: String         // dialog title, e.g. "mygate"
    public let launchdLabel: String        // e.g. "com.example.gated"
    public let plist: String               // e.g. "/Library/LaunchDaemons/com.example.gated.plist"
    public let daemonMatchPattern: String  // pkill -f arg, e.g. "mygate daemon"
    public let claudeCodeDir: String       // "/Library/Application Support/ClaudeCode"
    public let managedSettings: String     // claudeCodeDir + "/managed-settings.json"

    public init(serviceAccount: String, accountRealName: String, namespace: String,
                keydir: String, runDir: String, sock: String, daemonLogErr: String,
                codeDir: String, policy: String, binaryName: String, displayName: String,
                launchdLabel: String, plist: String, daemonMatchPattern: String,
                claudeCodeDir: String, managedSettings: String) {
        self.serviceAccount = serviceAccount; self.accountRealName = accountRealName
        self.namespace = namespace; self.keydir = keydir; self.runDir = runDir; self.sock = sock
        self.daemonLogErr = daemonLogErr; self.codeDir = codeDir; self.policy = policy
        self.binaryName = binaryName; self.displayName = displayName; self.launchdLabel = launchdLabel
        self.plist = plist; self.daemonMatchPattern = daemonMatchPattern
        self.claudeCodeDir = claudeCodeDir; self.managedSettings = managedSettings
    }

    // Control files are DERIVED from roots so the deny logic lives in one place.
    public var allowedSigners: String { keydir + "/allowed_signers" }
    public var audit: String { keydir + "/audit.log" }
    public var custody: String { keydir + "/custody.json" }
    public var ceremonyLock: String { keydir + "/ceremony.lock" }
    /// Same six entries as today's Paths.controlDenylist, derived.
    public var controlDenylist: [String] { [allowedSigners, audit, custody, ceremonyLock, sock, policy] }
}
