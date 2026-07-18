import Foundation
import Darwin

/// OS-specific install-time privileged primitives. macOS impl below; a LinuxPlatform is a future spec.
/// The mutating methods assume the process is root (install/activate/uninstall run via `sudo cc-fido …`).
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
@discardableResult
func run(_ path: String, _ args: [String]) -> (Int32, String, String) {
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
    public init() {}
    public func serviceAccountExists(name: String) -> Bool {
        // Check for the UniqueID attribute specifically — a record missing it (e.g. left over from an
        // interrupted create) is treated as absent, so it gets repaired rather than permanently skipped.
        run("/usr/bin/dscl", [".", "-read", "/Users/\(name)", "UniqueID"]).0 == 0
    }
    public func createServiceAccount(name: String) throws {
        if serviceAccountExists(name: name) { return }               // idempotent
        // Reuse an existing uid if a half-formed record is being repaired, so a repair never
        // reassigns the uid out from under anything that may already reference it.
        let existing = run("/usr/bin/dscl", [".", "-read", "/Users/\(name)", "UniqueID"])
        let uid: Int
        if existing.0 == 0, let n = existing.1.split(separator: " ").last, let existingUID = Int(n) {
            uid = existingUID
        } else {
            // Pick a free uid in the 200-400 service range (mirrors account-setup.sh).
            let list = run("/usr/bin/dscl", [".", "-list", "/Users", "UniqueID"]).1
            let used = list.split(separator: "\n").compactMap { Int($0.split(whereSeparator: { $0 == " " }).last ?? "") }
            uid = (used.filter { $0 >= 200 && $0 < 400 }.max() ?? 299) + 1
        }
        do {
            for arg in [["-create", "/Users/\(name)"],
                        ["-create", "/Users/\(name)", "UserShell", "/usr/bin/false"],
                        ["-create", "/Users/\(name)", "RealName", "cc-fido broker"],
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
        try xml.write(toFile: Paths.plist, atomically: true, encoding: .utf8)
        _ = run("/usr/sbin/chown", ["root:wheel", Paths.plist]); _ = run("/bin/chmod", ["644", Paths.plist])
    }
    public func activateDaemon() throws {
        _ = run("/bin/launchctl", ["bootout", "system", Paths.plist])                 // ||true — may not be loaded
        let b = run("/bin/launchctl", ["bootstrap", "system", Paths.plist])
        if b.0 != 0 { throw PlatformError.failed("bootstrap: \(b.2)") }
        _ = run("/bin/launchctl", ["kickstart", "-k", "system/\(Paths.launchdLabel)"]) // fresh socket
    }
    public func bootoutDaemon() throws {
        _ = run("/bin/launchctl", ["bootout", "system", Paths.plist])
        _ = run("/usr/bin/pkill", ["-f", "cc-fido daemon"])
    }
    public func daemonState() -> (loaded: Bool, running: Bool, pid: Int?) {
        // Socket-reachability is the authoritative "running" signal and works as any uid (0666 socket).
        let reachable = { () -> Bool in let fd = connectSock(Paths.sock); if fd >= 0 { close(fd); return true }; return false }()
        let loaded = FileManager.default.fileExists(atPath: Paths.plist)
        return (loaded, reachable, nil)
    }
    public func writeManagedSettings(_ json: String) throws {
        try FileManager.default.createDirectory(atPath: Paths.claudeCodeDir, withIntermediateDirectories: true)
        try json.write(toFile: Paths.managedSettings, atomically: true, encoding: .utf8)
        _ = run("/usr/sbin/chown", ["root:wheel", Paths.managedSettings]); _ = run("/bin/chmod", ["644", Paths.managedSettings])
    }
    public func removeManagedSettings() throws { try? FileManager.default.removeItem(atPath: Paths.managedSettings) }
    public func makeImmutable(_ path: String) throws {
        if run("/usr/bin/chflags", ["uchg", path]).0 != 0 { throw PlatformError.failed("chflags uchg \(path)") }
    }
    public func clearImmutable(_ path: String) throws { _ = run("/usr/bin/chflags", ["nouchg", path]) }
}
#endif
