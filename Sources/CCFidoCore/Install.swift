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
    // binary + codesign. Skip the remove+copy when binarySource already IS the destination (e.g.
    // a repair re-run invoked as the installed binary) — removing it first would delete the copy
    // source out from under itself and the copy would then fail.
    let dest = Paths.code + "/cc-fido"
    let sameFile = fm.fileExists(atPath: binarySource)
        && URL(fileURLWithPath: binarySource).resolvingSymlinksInPath().path
        == URL(fileURLWithPath: dest).resolvingSymlinksInPath().path
    if !sameFile {
        try? fm.removeItem(atPath: dest)
        try fm.copyItem(atPath: binarySource, toPath: dest)
    }
    if run("/usr/bin/codesign", ["--force", "--options", "runtime", "--sign", "-", dest]).0 != 0 {
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
    // perms (root-owned code + policy — root always exists, so best-effort is fine here)
    _ = run("/usr/sbin/chown", ["-R", "root:wheel", Paths.code]); _ = run("/bin/chmod", ["755", Paths.code])
    _ = run("/bin/chmod", ["644", Paths.policy])
    // account + plist + managed-settings — MUST run before the _ccfido chowns below: on a fresh
    // install the account doesn't exist yet, and chown to a nonexistent user fails.
    try installOrchestration(platform: platform)
    // _ccfido ownership is the real write barrier (see CLAUDE.md) — fail closed rather than
    // silently leaving keydir/runDir root-owned.
    if run("/usr/sbin/chown", ["_ccfido", Paths.keydir]).0 != 0 { throw InstallError.failed("chown _ccfido \(Paths.keydir)") }
    if run("/usr/sbin/chown", ["_ccfido", Paths.runDir]).0 != 0 { throw InstallError.failed("chown _ccfido \(Paths.runDir)") }
    _ = run("/bin/chmod", ["700", Paths.keydir]); _ = run("/bin/chmod", ["755", Paths.runDir])
}
