import Foundation

public enum InstallError: Error { case notRoot, failed(String) }

/// Platform-driven prereqs: account + daemon plist + managed-settings. Unit-tested against MockPlatform.
public func installOrchestration(platform: Platform) throws {
    if !platform.serviceAccountExists(name: "_ccfido") { try platform.createServiceAccount(name: "_ccfido") }
    try platform.installDaemonPlist(renderPlist())
    try platform.writeManagedSettings(renderManagedSettings(hookCmd: Paths.code + "/cc-fido hook"))
}

/// Full root-context install: dirs, binary, policy (render+validate+install), then installOrchestration.
/// `binarySource` is the just-built/-run binary to copy into /opt; `policySrc` is the template (or --policy).
public func installPrereqs(policySrc: String, home: String, binarySource: String, platform: Platform) throws {
    guard getuid() == 0 else { throw InstallError.notRoot }
    let fm = FileManager.default
    for d in [Paths.code, Paths.keydir, Paths.runDir] {
        try fm.createDirectory(atPath: d, withIntermediateDirectories: true)
    }
    // binary + codesign
    try? fm.removeItem(atPath: Paths.code + "/cc-fido")
    try fm.copyItem(atPath: binarySource, toPath: Paths.code + "/cc-fido")
    if run("/usr/bin/codesign", ["--force", "--options", "runtime", "--sign", "-", Paths.code + "/cc-fido"]).0 != 0 {
        throw InstallError.failed("codesign")
    }
    // policy: render (substitute+validate+lint) → validate dict → atomic write. Reuses renderPolicy.
    let rendered = try renderPolicy(srcPath: policySrc, home: home)
    guard let obj = try JSONSerialization.jsonObject(with: rendered) as? [String: Any] else { throw InstallError.failed("policy not an object") }
    let policy = try Policy.fromDict(obj)                 // throws on invalid
    let (fatal, _) = policy.lint(); if !fatal.isEmpty { throw InstallError.failed("policy: \(fatal.joined(separator: "; "))") }
    let cand = Paths.policy + ".new"
    try rendered.write(to: URL(fileURLWithPath: cand))
    try fm.moveItem(atPath: cand, toPath: Paths.policy)   // atomic
    // perms
    _ = run("/usr/sbin/chown", ["-R", "root:wheel", Paths.code]); _ = run("/bin/chmod", ["755", Paths.code])
    _ = run("/bin/chmod", ["644", Paths.policy])
    _ = run("/usr/sbin/chown", ["_ccfido", Paths.keydir]); _ = run("/usr/sbin/chown", ["_ccfido", Paths.runDir])
    _ = run("/bin/chmod", ["700", Paths.keydir]); _ = run("/bin/chmod", ["755", Paths.runDir])
    // account + plist + managed-settings
    try installOrchestration(platform: platform)
}
