import Foundation

public struct StatusReport: Codable {
    public let account, dirs, binary, policyValid, keyEnrolled, daemonRunning, managedSettings: Bool
    public init(account: Bool, dirs: Bool, binary: Bool, policyValid: Bool,
                keyEnrolled: Bool, daemonRunning: Bool, managedSettings: Bool) {
        self.account = account; self.dirs = dirs; self.binary = binary; self.policyValid = policyValid
        self.keyEnrolled = keyEnrolled; self.daemonRunning = daemonRunning; self.managedSettings = managedSettings
    }
    /// Overall lifecycle stage. `degraded` = the daemon is running but a prereq is missing/broken.
    public var rollup: String {
        let prereqs = account && dirs && binary && policyValid
        if daemonRunning && !prereqs { return "degraded" }
        if daemonRunning { return "active" }
        if prereqs && keyEnrolled { return "enrolled" }        // ready to activate
        if prereqs { return "prereqs-only" }
        if !account && !dirs && !binary { return "clean" }
        return "degraded"
    }
    enum CodingKeys: String, CodingKey {
        case account, dirs, binary
        case policyValid = "policy_valid", keyEnrolled = "key_enrolled"
        case daemonRunning = "daemon_running", managedSettings = "managed_settings", rollupKey = "rollup"
    }
    public func encode(to enc: Encoder) throws {
        var c = enc.container(keyedBy: CodingKeys.self)
        try c.encode(account, forKey: .account); try c.encode(dirs, forKey: .dirs); try c.encode(binary, forKey: .binary)
        try c.encode(policyValid, forKey: .policyValid); try c.encode(keyEnrolled, forKey: .keyEnrolled)
        try c.encode(daemonRunning, forKey: .daemonRunning); try c.encode(managedSettings, forKey: .managedSettings)
        try c.encode(rollup, forKey: .rollupKey)
    }
    // `rollup` is computed from the other 7 fields, so decoding ignores the `rollup` wire key.
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        account = try c.decode(Bool.self, forKey: .account)
        dirs = try c.decode(Bool.self, forKey: .dirs)
        binary = try c.decode(Bool.self, forKey: .binary)
        policyValid = try c.decode(Bool.self, forKey: .policyValid)
        keyEnrolled = try c.decode(Bool.self, forKey: .keyEnrolled)
        daemonRunning = try c.decode(Bool.self, forKey: .daemonRunning)
        managedSettings = try c.decode(Bool.self, forKey: .managedSettings)
    }
}

public func gatherStatus(platform: Platform) -> StatusReport {
    let fm = FileManager.default
    let account = platform.serviceAccountExists(name: "_ccfido")
    let dirs = fm.fileExists(atPath: Paths.keydir) && fm.fileExists(atPath: Paths.runDir)
    let binary = fm.fileExists(atPath: Paths.code + "/cc-fido")
    let policyValid = (try? Policy.fromFile(Paths.policy)) != nil
    let keyEnrolled = fm.fileExists(atPath: Paths.allowedSigners)
        && ((try? String(contentsOfFile: Paths.allowedSigners, encoding: .utf8))?.isEmpty == false)
    let daemonRunning = platform.daemonState().running
    let managed = fm.fileExists(atPath: Paths.managedSettings)
    return StatusReport(account: account, dirs: dirs, binary: binary, policyValid: policyValid,
                        keyEnrolled: keyEnrolled, daemonRunning: daemonRunning, managedSettings: managed)
}
