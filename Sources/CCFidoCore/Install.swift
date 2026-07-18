import Foundation

public enum InstallError: Error { case notRoot, failed(String) }

/// Boots the LaunchDaemon (fresh socket). Refuses if no key is enrolled (the daemon would deny everything).
/// `keyEnrolled` is injected so it's unit-testable; the subcommand passes the real allowed_signers check.
public func activate(platform: Platform, keyEnrolled: Bool) throws {
    guard keyEnrolled else { throw InstallError.failed("no key enrolled — run `cc-fido enroll` first") }
    try platform.activateDaemon()
}

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
    // binary + codesign. Stage to `dest + ".new"` then atomically rename over `dest` — never
    // remove the live binary before its replacement is fully copied. This also handles the
    // repair-re-run case (binarySource == dest) safely: the source is untouched until the copy
    // completes, so a bare/relative binarySource (or a same-file source) can never leave `dest`
    // deleted with no replacement.
    let dest = Paths.code + "/cc-fido"
    let stagedBinary = dest + ".new"
    try? fm.removeItem(atPath: stagedBinary)
    try fm.copyItem(atPath: binarySource, toPath: stagedBinary)
    // POSIX rename, not FileManager.moveItem: moveItem throws NSFileWriteFileExistsError when
    // `dest` already exists (the normal re-install/repair case), whereas rename(2) atomically
    // replaces an existing destination on the same filesystem — which staged and dest are.
    if rename(stagedBinary, dest) != 0 {
        let err = String(cString: strerror(errno))
        try? fm.removeItem(atPath: stagedBinary)           // don't leave an orphan .new on failure
        throw InstallError.failed("install binary: rename \(stagedBinary) -> \(dest): \(err)")
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
    // Same rename-not-moveItem reasoning as the binary above: rename(2) overwrites an existing
    // Paths.policy atomically; moveItem would throw on a re-install where the policy already exists.
    if rename(cand, Paths.policy) != 0 {
        let err = String(cString: strerror(errno))
        try? fm.removeItem(atPath: cand)                   // don't leave an orphan .new on failure
        throw InstallError.failed("install policy: rename \(cand) -> \(Paths.policy): \(err)")
    }
    // Ship the (unsubstituted) template next to the binary so re-installs have a default source.
    // Skip the remove+copy when policySrc already IS the staging destination (a --policy-less
    // re-install defaults policySrc to this same path via installRepoPolicyDefault()) — same
    // same-file guard as the binary-copy block above, for the same reason: removing first would
    // delete the only copy out from under the subsequent copy.
    let templateDest = Paths.code + "/policy.json.template"
    let templateSameFile = fm.fileExists(atPath: policySrc)
        && URL(fileURLWithPath: policySrc).resolvingSymlinksInPath().path
        == URL(fileURLWithPath: templateDest).resolvingSymlinksInPath().path
    if fm.fileExists(atPath: policySrc) && !templateSameFile {
        try? fm.removeItem(atPath: templateDest)
        try? fm.copyItem(atPath: policySrc, toPath: templateDest)
    }
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

/// Full teardown. Order matters: bootout daemon → remove managed-settings → UNLOCK every enrolled target
/// (before deleting the registry/account, else they're stuck immutable) → rm tree/state → delete account.
/// Every step is best-effort (`try?`/ignored exit) so a partially-installed system still fully tears down.
/// The root check (this needs privileged ops for real) lives in the CLI dispatch, not here — mirrors
/// installOrchestration (unit-tested, no guard) vs installPrereqs (root-only, guarded): keeps this the
/// pure, [SW]-testable half so `swift test` (which never runs as root) can exercise it directly.
public func uninstall(platform: Platform, enrolledTargets: [String], home: String) throws {
    try? platform.bootoutDaemon()
    try? platform.removeManagedSettings()
    try? FileManager.default.removeItem(atPath: Paths.plist)
    for t in enrolledTargets {
        try? platform.clearImmutable(t)                              // nouchg — unconditional, best-effort
        _ = run("/usr/sbin/chown", ["-R", loginOwner(home: home), t])
    }
    for d in [Paths.code, Paths.keydir, Paths.runDir] { try? FileManager.default.removeItem(atPath: d) }
    try? platform.deleteServiceAccount(name: "_ccfido")
    // key material (login user's home)
    for f in ["gate_sk", "gate_sk.pub", "gate_sk1", "gate_sk1.pub", "gate_sk2", "gate_sk2.pub"] {
        try? FileManager.default.removeItem(atPath: "\(home)/.ccfido/\(f)")
    }
}
func loginOwner(home: String) -> String {
    let user = (home as NSString).lastPathComponent
    return "\(user):staff"
}
