import Foundation

public enum EnrollError: Error { case failed(String) }

/// Runs as the LOGIN user. Generates key(s) (touch), registers pubkeys in allowed_signers (one escalation),
/// symlinks the handle (private+public), and blink-tests key #1. `blink` is injected — the FIDO-specific
/// negative-blink-test lives in CCFidoBackend, which core cannot import. `enroller` supplies the
/// per-key keygen argv and the enrolled-probe/cleanup — backend-specific, injected so core stays FIDO-agnostic.
public func runEnroll(home: String, keys: Int, enroller: Enroller, blink: (_ handle: String, _ namespace: String) -> Bool) throws {
    let dir = "\(home)/.ccfido"
    try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
    _ = run("/bin/chmod", ["700", dir])
    let count = max(1, keys)
    for n in 1...count {
        guard let argv = enroller.enrollPlan(home: home, index: n).first else {
            throw EnrollError.failed("no enroll plan for key #\(n)")
        }
        FileHandle.standardError.write(Data(">>> TOUCH to enroll key #\(n) of \(count) <<<\n".utf8))
        if run(Paths.signKeygen, argv).0 != 0 { throw EnrollError.failed("ssh-keygen key #\(n)") }
        _ = run("/bin/chmod", ["600", "\(dir)/gate_sk\(n)"])
        // a failed or empty pubkey read must NOT silently register a keyless principal (printf '' exits 0)
        guard let pub = (try? String(contentsOfFile: "\(dir)/gate_sk\(n).pub", encoding: .utf8))?
                .trimmingCharacters(in: .whitespacesAndNewlines), !pub.isEmpty else {
            throw EnrollError.failed("read pubkey #\(n)")
        }
        // one escalation: append to the root-owned allowed_signers. The script body is FIXED
        // (only Paths.allowedSigners, our own constant, is interpolated into it); `pub` is passed
        // as a positional parameter ($1) instead of being interpolated into the script text, so
        // it can't break out of the shell no matter its shape.
        if !runPrivileged(["/bin/sh", "-c", "printf 'gate-principal %s\\n' \"$1\" >> \(Paths.allowedSigners)", "sh", pub]) {
            throw EnrollError.failed("register key #\(n)")
        }
    }
    // active handle = key #1 (BOTH private and public — a stale .pub aborts signing)
    _ = run("/bin/ln", ["-sf", "\(dir)/gate_sk1", Paths.handle])
    _ = run("/bin/ln", ["-sf", "\(dir)/gate_sk1.pub", Paths.handle + ".pub"])
    _ = runPrivileged(["/usr/sbin/chown", "_ccfido", Paths.allowedSigners])
    _ = runPrivileged(["/bin/chmod", "600", Paths.allowedSigners])
    if !blink("\(dir)/gate_sk1", Paths.namespace) {
        throw EnrollError.failed("blink-test (touch-required not verified)")
    }
}
