import Foundation
import CCFidoCore

let args = Array(CommandLine.arguments.dropFirst())
func usage() -> Never {
    FileHandle.standardError.write(Data("usage: cc-fido {daemon|hook|write <path>|enroll [--keys N]|install [--policy PATH]|activate|enroll-file <path> [mode]|enroll-dir <path>|status [--json]|_validate-policy <path>|_render-policy <src> <home>}\n".utf8))
    exit(2)
}

// Under `sudo`, HOME is root's; the policy's __HOME__ must be the LOGIN user's home. Derive from SUDO_USER.
func realLoginHome() -> String {
    if let u = ProcessInfo.processInfo.environment["SUDO_USER"], let pw = getpwnam(u) { return String(cString: pw.pointee.pw_dir) }
    return NSHomeDirectory()
}
func installRepoPolicyDefault() -> String { Paths.code + "/policy.json.template" }  // see Task 7 note

func ccfidoUIDOr(_ fallback: Int) -> Int { getpwnam("_ccfido").map { Int($0.pointee.pw_uid) } ?? fallback }
func warnAncestors(_ path: String) {
    let w = checkAncestors(path, safeOwners: [0, ccfidoUIDOr(-1)])
    if !w.isEmpty { FileHandle.standardError.write(Data("cc-fido: WARNING agent-writable ancestors (parent-swap residual, spec §2): \(w)\n".utf8)) }
}
func enrollSteps(_ plan: [[String]]) {
    for a in plan where !runPrivileged(a) {
        FileHandle.standardError.write(Data("cc-fido: privileged step failed: \(a)\n".utf8)); exit(1)
    }
}
// on registry-add failure, undo the lock so the file returns to its pre-enroll (usable) state.
// Restores the CAPTURED original uid AND mode (not assumed ones), and reports whether every step succeeded.
func rollbackFileLock(_ path: String, toUID uid: UInt32, toMode mode: mode_t) {
    let unlocked = runPrivileged(["/usr/bin/chflags", "nouchg", path])
    let chowned = runPrivileged(["/usr/sbin/chown", String(uid), path])
    let chmoded = runPrivileged(["/bin/chmod", String(mode & 0o7777, radix: 8), path])
    if unlocked && chowned && chmoded {
        FileHandle.standardError.write(Data("cc-fido: rolled back lock on \(path) (uid+mode restored)\n".utf8))
    } else {
        FileHandle.standardError.write(Data("cc-fido: ROLLBACK INCOMPLETE on \(path) (nouchg=\(unlocked) chown=\(chowned) chmod=\(chmoded)) — fix manually\n".utf8))
    }
}

guard let cmd = args.first else { usage() }
switch cmd {
case "daemon":
    try Broker().serve()
case "hook":
    hookMain()
case "write":
    guard args.count >= 2 else { usage() }
    exit(runWrite(path: args[1], content: FileHandle.standardInput.readDataToEndOfFile()))
case "install":
    guard getuid() == 0 else {
        FileHandle.standardError.write(Data("cc-fido install: must run as root — use: sudo cc-fido install\n".utf8)); exit(1)
    }
    let policySrc = flagValue("--policy", in: args) ?? (installRepoPolicyDefault())
    let home = realLoginHome()   // login user's home (from SUDO_USER), NOT root's /var/root
    do {
        try installPrereqs(policySrc: policySrc, home: home, binarySource: CommandLine.arguments[0], platform: MacOSPlatform())
        print("cc-fido: prereqs installed. Next: cc-fido enroll  (then: sudo cc-fido activate)")
        exit(0)
    } catch { FileHandle.standardError.write(Data("cc-fido install failed: \(error)\n".utf8)); exit(1) }
case "activate":
    guard getuid() == 0 else {
        FileHandle.standardError.write(Data("cc-fido activate: must run as root — use: sudo cc-fido activate\n".utf8)); exit(1)
    }
    let enrolled = (try? String(contentsOfFile: Paths.allowedSigners, encoding: .utf8))?.isEmpty == false
    do {
        try activate(platform: MacOSPlatform(), keyEnrolled: enrolled)
        usleep(1_000_000)
        let running = MacOSPlatform().daemonState().running
        print("cc-fido: daemon activated — socket \(running ? "reachable" : "NOT reachable (re-run activate)")")
        exit(running ? 0 : 1)
    } catch { FileHandle.standardError.write(Data("cc-fido activate failed: \(error)\n".utf8)); exit(1) }
case "enroll":
    if getuid() == 0 { FileHandle.standardError.write(Data("cc-fido enroll: run as your login user (not sudo) — it needs your key + a touch\n".utf8)); exit(1) }
    let keys = flagValue("--keys", in: args).flatMap { Int($0) } ?? 1
    do { try runEnroll(home: NSHomeDirectory(), keys: keys); print("cc-fido: enrolled. Next: sudo cc-fido activate"); exit(0) }
    catch { FileHandle.standardError.write(Data("cc-fido enroll failed: \(error)\n".utf8)); exit(1) }
case "_render-plist": print(renderPlist()); exit(0)
case "_render-managed": print(renderManagedSettings(hookCmd: Paths.code + "/cc-fido hook")); exit(0)
case "_cc-version":   // record the Claude Code version for the install-time re-probe
    guard args.count >= 2 else { usage() }
    print(ccVersion(args[1])); exit(0)
case "_blink-test":
    guard args.count >= 2 else { usage() }
    exit(negativeBlinkTest(handle: args[1], namespace: Paths.namespace) ? 0 : 1)
case "_verify-audit":   // runs AS _ccfido so it can read the 0600 _ccfido-owned audit log
    if auditVerifyChain() { print("audit chain OK"); exit(0) }
    FileHandle.standardError.write(Data("audit chain BROKEN\n".utf8)); exit(1)
case "_validate-policy":   // read-only: parse + summary + lint. exactly one path.
    guard args.count == 2 else { usage() }
    do {
        let policy = try Policy.fromFile(args[1])
        let (fatal, warnings) = policy.lint()
        for w in warnings { FileHandle.standardError.write(Data("cc-fido: WARNING \(w)\n".utf8)) }
        guard fatal.isEmpty else {
            for f in fatal { FileHandle.standardError.write(Data("cc-fido: FATAL \(f)\n".utf8)) }
            exit(1)
        }
        print(policy.summary()); exit(0)
    } catch {
        FileHandle.standardError.write(Data("cc-fido: invalid policy: \(error)\n".utf8)); exit(1)
    }
case "_render-policy":   // substitute __HOME__, guard home, validate + lint, emit JSON on success ONLY.
    guard args.count == 3 else { usage() }
    do {
        let rendered = try renderPolicy(srcPath: args[1], home: args[2])
        guard let obj = try JSONSerialization.jsonObject(with: rendered) as? [String: Any] else {
            throw PolicyError.badFile("rendered policy is not a JSON object")
        }
        let policy = try Policy.fromDict(obj)
        let (fatal, warnings) = policy.lint()
        for w in warnings { FileHandle.standardError.write(Data("cc-fido: WARNING \(w)\n".utf8)) }
        guard fatal.isEmpty else {
            for f in fatal { FileHandle.standardError.write(Data("cc-fido: FATAL \(f)\n".utf8)) }
            exit(1)   // NO stdout — a downstream `tee` writes nothing, live policy untouched
        }
        FileHandle.standardOutput.write(rendered); exit(0)   // emit only when valid
    } catch {
        FileHandle.standardError.write(Data("cc-fido: render failed: \(error)\n".utf8)); exit(1)
    }
// runs AS _ccfido (via `sudo -u _ccfido`) so it can write the 0600 _ccfido-owned custody.json:
case "_registry-add":
    guard args.count >= 3, args[1] == "file" || args[1] == "dir" else { usage() }
    do {
        try CustodyRegistry.add(file: args[1] == "file" ? args[2] : nil,
                                dir: args[1] == "dir" ? args[2] : nil)
        exit(0)
    } catch {
        FileHandle.standardError.write(Data("cc-fido: registry add failed: \(error)\n".utf8)); exit(1)
    }
case "status":
    let report = gatherStatus(platform: MacOSPlatform())
    if args.contains("--json") {
        let data = try JSONEncoder().encode(report)
        print(String(data: data, encoding: .utf8)!)
    } else {
        func mark(_ b: Bool) -> String { b ? "✓" : "·" }
        print("""
        cc-fido status: \(report.rollup)
          \(mark(report.account)) account   \(mark(report.dirs)) dirs   \(mark(report.binary)) binary
          \(mark(report.policyValid)) policy   \(mark(report.keyEnrolled)) key   \(mark(report.daemonRunning)) daemon   \(mark(report.managedSettings)) managed-settings
        """)
    }
    exit(0)
case "enroll-file":
    guard args.count >= 2 else { usage() }
    let path = (args[1] as NSString).standardizingPath
    let mode = args.count > 2 ? (Int(args[2], radix: 8) ?? 0o600) : 0o600
    warnAncestors(path)
    var pre = stat(); let hadStat = lstat(path, &pre) == 0    // capture owner+mode BEFORE enroll
    let origUID = hadStat ? pre.st_uid : getuid()
    let origMode = hadStat ? pre.st_mode : mode_t(0o600)
    // Lock FIRST, then register. This ordering fails SAFE: a registry failure leaves the file
    // locked-but-unregistered (over-protected, `cc-fido write` won't touch it) — never
    // registered-but-writable (which would advertise protection it doesn't have). We roll the lock back.
    enrollSteps(planEnrollFile(path, mode: mode))
    if !runPrivileged(["-u", "_ccfido", Paths.code + "/cc-fido", "_registry-add", "file", path]) {
        rollbackFileLock(path, toUID: origUID, toMode: origMode)
        FileHandle.standardError.write(Data("cc-fido: registry add failed for \(path)\n".utf8)); exit(1)
    }
    print("cc-fido: enrolled + registered file \(path)"); exit(0)
case "enroll-dir":
    guard args.count >= 2 else { usage() }
    let path = (args[1] as NSString).standardizingPath
    warnAncestors(path)
    enrollSteps(planEnrollDir(path))
    if !runPrivileged(["-u", "_ccfido", Paths.code + "/cc-fido", "_registry-add", "dir", path]) {
        FileHandle.standardError.write(Data("cc-fido: registry add failed for \(path); dir remains _ccfido-owned — re-run enroll-dir to register\n".utf8)); exit(1)
    }
    print("cc-fido: enrolled + registered dir \(path)"); exit(0)
default:
    FileHandle.standardError.write(Data("cc-fido: unknown command \(cmd)\n".utf8)); exit(2)
}
