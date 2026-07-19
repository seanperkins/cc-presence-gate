import Foundation
import CCGateCore

/// FIDO-specific `Enroller`: sk-keygen argv, on-disk handle probe, and key-file cleanup. Core's
/// `runEnroll`/`gatherStatus`/`uninstall` are backend-agnostic and consume this through the
/// `Enroller` protocol so a future Secure-Enclave backend can supply its own without touching core.
public struct FidoEnroller: Enroller {
    public init() {}
    /// The `ssh-keygen -t ed25519-sk` argv for key #index (1-based). Touch required. Kept as an
    /// internal (non-protocol) method — `enroll(home:keys:profile:)` below is the sole caller now
    /// that the ceremony itself lives here; `FidoEnrollerTests` still exercises it directly.
    func enrollPlan(home: String, index: Int) -> [[String]] {
        [["-t", "ed25519-sk", "-O", "application=ssh:cc-fido-gate", "-N", "", "-C", "cc-fido-key\(index)",
          "-f", "\(home)/.ccfido/gate_sk\(index)"]]
    }
    /// Runs as the LOGIN user. Generates key(s) (touch), registers pubkeys in allowed_signers (one
    /// escalation), and symlinks the handle (private+public) to key #1. Relocated verbatim from the
    /// former core `runEnroll` (Sources/CCGateCore/Enroll.swift) — same sequence, same effects;
    /// `signKeygen`/`handle`/`namespace` are now the FIDO backend constants directly instead of
    /// injected params, since this method lives in the FIDO backend itself.
    public func enroll(home: String, keys: Int, profile: GateProfile) throws {
        let dir = "\(home)/.ccfido"
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        _ = run("/bin/chmod", ["700", dir])
        let count = max(1, keys)
        for n in 1...count {
            guard let argv = enrollPlan(home: home, index: n).first else {
                throw EnrollError.failed("no enroll plan for key #\(n)")
            }
            FileHandle.standardError.write(Data(">>> TOUCH to enroll key #\(n) of \(count) <<<\n".utf8))
            if run(fidoSignKeygen, argv).0 != 0 { throw EnrollError.failed("ssh-keygen key #\(n)") }
            _ = run("/bin/chmod", ["600", "\(dir)/gate_sk\(n)"])
            // a failed or empty pubkey read must NOT silently register a keyless principal (printf '' exits 0)
            guard let pub = (try? String(contentsOfFile: "\(dir)/gate_sk\(n).pub", encoding: .utf8))?
                    .trimmingCharacters(in: .whitespacesAndNewlines), !pub.isEmpty else {
                throw EnrollError.failed("read pubkey #\(n)")
            }
            // one escalation: append to the root-owned allowed_signers. The script body is FIXED
            // (only profile.allowedSigners is interpolated into it); `pub` is passed as a positional
            // parameter ($1) instead of being interpolated into the script text, so it can't break out
            // of the shell no matter its shape.
            if !runPrivileged(["/bin/sh", "-c", "printf 'gate-principal %s\\n' \"$1\" >> \(profile.allowedSigners)", "sh", pub]) {
                throw EnrollError.failed("register key #\(n)")
            }
        }
        // active handle = key #1 (BOTH private and public — a stale .pub aborts signing)
        _ = run("/bin/ln", ["-sf", "\(dir)/gate_sk1", fidoKeyHandle(home: home)])
        _ = run("/bin/ln", ["-sf", "\(dir)/gate_sk1.pub", fidoKeyHandle(home: home) + ".pub"])
        _ = runPrivileged(["/usr/sbin/chown", profile.serviceAccount, profile.allowedSigners])
        _ = runPrivileged(["/bin/chmod", "600", profile.allowedSigners])
    }
    /// Post-enroll touch-required verification, run AFTER `enroll` — exactly where the old
    /// `runEnroll`'s injected `blink` closure ran last.
    public func positiveControl(home: String, profile: GateProfile) -> Bool {
        fidoNegativeBlinkTest(handle: "\(home)/.ccfido/gate_sk1", namespace: profile.namespace)
    }
    /// Privilege-independent probe: is the enroll handle present in the login user's own home?
    public func isEnrolled(home: String) -> Bool {
        FileManager.default.fileExists(atPath: home + "/.ccfido/gate_sk")
    }
    /// Uninstall: delete this user's FIDO key material (handle symlinks + the keys themselves).
    public func removeKeyMaterial(home: String) {
        for f in ["gate_sk", "gate_sk.pub", "gate_sk1", "gate_sk1.pub", "gate_sk2", "gate_sk2.pub"] {
            try? FileManager.default.removeItem(atPath: "\(home)/.ccfido/\(f)")
        }
    }
}
