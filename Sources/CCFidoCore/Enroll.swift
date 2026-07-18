import Foundation

public enum EnrollError: Error { case failed(String) }

/// The `ssh-keygen -t ed25519-sk` argv per key (touch required). Pure/testable.
public func enrollPlan(home: String, keys: Int) -> [[String]] {
    (1...max(1, keys)).map { n in
        ["-t", "ed25519-sk", "-O", "application=ssh:cc-fido-gate", "-N", "", "-C", "cc-fido-key\(n)",
         "-f", "\(home)/.ccfido/gate_sk\(n)"]
    }
}

/// Runs as the LOGIN user. Generates key(s) (touch), registers pubkeys in allowed_signers (one escalation),
/// symlinks the handle (private+public), and blink-tests key #1.
public func runEnroll(home: String, keys: Int) throws {
    let dir = "\(home)/.ccfido"
    try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
    _ = run("/bin/chmod", ["700", dir])
    let count = max(1, keys)
    for (i, argv) in enrollPlan(home: home, keys: keys).enumerated() {
        let n = i + 1
        FileHandle.standardError.write(Data(">>> TOUCH to enroll key #\(n) of \(count) <<<\n".utf8))
        if run(Paths.signKeygen, argv).0 != 0 { throw EnrollError.failed("ssh-keygen key #\(n)") }
        _ = run("/bin/chmod", ["600", "\(dir)/gate_sk\(n)"])
        // a failed or empty pubkey read must NOT silently register a keyless principal (printf '' exits 0)
        guard let pub = (try? String(contentsOfFile: "\(dir)/gate_sk\(n).pub", encoding: .utf8))?
                .trimmingCharacters(in: .whitespacesAndNewlines), !pub.isEmpty else {
            throw EnrollError.failed("read pubkey #\(n)")
        }
        // one escalation: append to the root-owned allowed_signers
        if !runPrivileged(["/bin/sh", "-c", "printf 'gate-principal %s\\n' '\(pub)' >> \(Paths.allowedSigners)"]) {
            throw EnrollError.failed("register key #\(n)")
        }
    }
    // active handle = key #1 (BOTH private and public — a stale .pub aborts signing)
    _ = run("/bin/ln", ["-sf", "\(dir)/gate_sk1", Paths.handle])
    _ = run("/bin/ln", ["-sf", "\(dir)/gate_sk1.pub", Paths.handle + ".pub"])
    _ = runPrivileged(["/usr/sbin/chown", "_ccfido", Paths.allowedSigners])
    _ = runPrivileged(["/bin/chmod", "600", Paths.allowedSigners])
    if !negativeBlinkTest(handle: "\(dir)/gate_sk1", namespace: Paths.namespace) {
        throw EnrollError.failed("blink-test (touch-required not verified)")
    }
}
