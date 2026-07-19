import Foundation
import Darwin

/// OS-specific install-time privileged primitives. macOS impl below; a LinuxPlatform is a future spec.
/// The mutating methods assume the process is root (install/activate/uninstall run via `sudo` with the gate binary).
public protocol Platform {
    func serviceAccountExists(name: String) -> Bool
    func createServiceAccount(name: String) throws       // dscl  (Linux: useradd)
    func deleteServiceAccount(name: String) throws
    func installDaemonPlist(_ xml: String) throws         // write the LaunchDaemon plist
    func activateDaemon() throws                          // bootout||true → bootstrap → kickstart -k
    func bootoutDaemon() throws
    func daemonState() -> (loaded: Bool, running: Bool, pid: Int?)
    func writeManagedSettings(_ json: String) throws
    func removeManagedSettings() throws
    func makeImmutable(_ path: String) throws             // chflags uchg (Linux: chattr +i)
    func clearImmutable(_ path: String) throws
}

public enum PlatformError: Error { case failed(String) }

#if os(macOS)
/// Runs a command to completion, returns (exit, stdout, stderr). Direct (no sudo) — the caller is root.
/// Public: backend enroll ceremonies (e.g. `FidoEnroller.enroll` in CCFidoBackend) spawn `ssh-keygen`
/// etc. through this same env-scrubbed runner rather than reimplementing Process plumbing.
@discardableResult
public func run(_ path: String, _ args: [String]) -> (Int32, String, String) {
    let p = Process(); p.executableURL = URL(fileURLWithPath: path); p.arguments = args
    p.environment = scrubbedEnv()
    let o = Pipe(), e = Pipe(); p.standardOutput = o; p.standardError = e
    do { try p.run() } catch { return (-1, "", "\(error)") }
    let out = String(data: o.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
    let err = String(data: e.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
    p.waitUntilExit()
    return (p.terminationStatus, out, err)
}

public struct MacOSPlatform: Platform {
    let profile: GateProfile
    public init(profile: GateProfile) { self.profile = profile }
    public func serviceAccountExists(name: String) -> Bool {
        // Check IsHidden — the LAST attribute `-create`d below — as a completion sentinel, not
        // UniqueID. UniqueID is written early, so a half-formed record (interrupted create, has a
        // UniqueID but no IsHidden yet) would otherwise read as "exists" and never get repaired.
        // Checking the last-written attribute means "exists" only once every attribute is present.
        // IsHidden MUST stay the last `-create` below or this sentinel is invalid.
        run("/usr/bin/dscl", [".", "-read", "/Users/\(name)", "IsHidden"]).0 == 0
    }
    public func createServiceAccount(name: String) throws {
        // Reached only when serviceAccountExists(name:) is false, i.e. the account is missing or
        // incomplete (no IsHidden yet) — possibly a half-formed record from an interrupted prior
        // run that DOES already have a UniqueID. Reuse that uid rather than reassigning, so a
        // repair never orphans anything that may already reference the old uid; `dscl -create` is
        // an idempotent overwrite, so re-running every attribute below on a partial record is safe.
        let existing = run("/usr/bin/dscl", [".", "-read", "/Users/\(name)", "UniqueID"])
        let uid: Int
        if existing.0 == 0,
           let n = existing.1.split(separator: ":").last,
           let existingUID = Int(n.trimmingCharacters(in: .whitespacesAndNewlines)) {
            // `dscl -read` output is e.g. "UniqueID: 250\n" — split on ":" (not " ") so the
            // value is robust to formatting, then trim before Int(...) (no implicit trim).
            uid = existingUID
        } else {
            // Pick a free uid in the 200-400 service range (mirrors account-setup.sh).
            let list = run("/usr/bin/dscl", [".", "-list", "/Users", "UniqueID"]).1
            let used = list.split(separator: "\n").compactMap { Int($0.split(whereSeparator: { $0 == " " }).last ?? "") }
            uid = (used.filter { $0 >= 200 && $0 < 400 }.max() ?? 299) + 1
        }
        do {
            // IsHidden MUST remain the last entry — serviceAccountExists(name:) reads it as the
            // completion sentinel.
            for arg in [["-create", "/Users/\(name)"],
                        ["-create", "/Users/\(name)", "UserShell", "/usr/bin/false"],
                        ["-create", "/Users/\(name)", "RealName", profile.accountRealName],
                        ["-create", "/Users/\(name)", "UniqueID", String(uid)],
                        ["-create", "/Users/\(name)", "PrimaryGroupID", "20"],
                        ["-create", "/Users/\(name)", "NFSHomeDirectory", "/var/empty"],
                        ["-create", "/Users/\(name)", "IsHidden", "1"]] {
                let r = run("/usr/bin/dscl", ["."] + arg)
                if r.0 != 0 { throw PlatformError.failed("dscl \(arg): \(r.2)") }
            }
        } catch {
            // Best-effort cleanup so a failed create doesn't wedge a half-formed record that the
            // existence check would otherwise skip repairing forever.
            _ = run("/usr/bin/dscl", [".", "-delete", "/Users/\(name)"])
            throw error
        }
    }
    public func deleteServiceAccount(name: String) throws {
        _ = run("/usr/bin/dscl", [".", "-delete", "/Users/\(name)"])   // idempotent; ignore "not found"
    }
    public func installDaemonPlist(_ xml: String) throws {
        try xml.write(toFile: profile.plist, atomically: true, encoding: .utf8)
        _ = run("/usr/sbin/chown", ["root:wheel", profile.plist]); _ = run("/bin/chmod", ["644", profile.plist])
    }
    public func activateDaemon() throws {
        _ = run("/bin/launchctl", ["bootout", "system", profile.plist])               // ||true — may not be loaded
        let b = run("/bin/launchctl", ["bootstrap", "system", profile.plist])
        if b.0 != 0 { throw PlatformError.failed("bootstrap: \(b.2)") }
        _ = run("/bin/launchctl", ["kickstart", "-k", "system/\(profile.launchdLabel)"]) // fresh socket
    }
    public func bootoutDaemon() throws {
        _ = run("/bin/launchctl", ["bootout", "system", profile.plist])
        _ = run("/usr/bin/pkill", ["-f", profile.daemonMatchPattern])
    }
    public func daemonState() -> (loaded: Bool, running: Bool, pid: Int?) {
        // Socket-reachability is the authoritative "running" signal and works as any uid (0666 socket).
        let reachable = { () -> Bool in let fd = connectSock(profile.sock); if fd >= 0 { close(fd); return true }; return false }()
        let loaded = FileManager.default.fileExists(atPath: profile.plist)
        return (loaded, reachable, nil)
    }
    public func writeManagedSettings(_ json: String) throws {
        try FileManager.default.createDirectory(atPath: profile.claudeCodeDir, withIntermediateDirectories: true)
        try json.write(toFile: profile.managedSettings, atomically: true, encoding: .utf8)
        _ = run("/usr/sbin/chown", ["root:wheel", profile.managedSettings]); _ = run("/bin/chmod", ["644", profile.managedSettings])
    }
    public func removeManagedSettings() throws { try? FileManager.default.removeItem(atPath: profile.managedSettings) }
    public func makeImmutable(_ path: String) throws {
        if run("/usr/bin/chflags", ["uchg", path]).0 != 0 { throw PlatformError.failed("chflags uchg \(path)") }
    }
    public func clearImmutable(_ path: String) throws { _ = run("/usr/bin/chflags", ["nouchg", path]) }
}
#endif
