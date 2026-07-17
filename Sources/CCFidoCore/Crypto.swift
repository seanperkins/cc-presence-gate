import Foundation
import Darwin

public enum SignError: Error { case failed(String) }
public let MAX_SIG = 64 * 1024   // sk signatures are < 1 KiB; cap defensively

// The runtime child-spawn env (sign/verify/dialog/blink). Single source of truth = scrubEnv (HookLogic):
// one literal allowlist, so hardening it in one place can't desync hook-context vs child-spawn scrubbing
// (Task-6 review Important).
public func scrubbedEnv() -> [String: String] {
    return scrubEnv(ProcessInfo.processInfo.environment)
}

/// Cooperative cancellation for an in-flight `sign()`. Lets a concurrent dialog abort the armed key
/// (user clicked Cancel / dialog gave up) by terminating the live ssh-keygen. Thread-safe.
public final class SignCanceller {
    private let lock = NSLock()
    private var proc: Process?
    private var cancelled = false
    /// Adopt the running signer so a later cancel() can terminate it. Returns false if already cancelled.
    func adopt(_ p: Process) -> Bool { lock.lock(); defer { lock.unlock() }; if cancelled { return false }; proc = p; return true }
    public func cancel() { lock.lock(); defer { lock.unlock() }; cancelled = true; proc?.terminate() }
    var isCancelled: Bool { lock.lock(); defer { lock.unlock() }; return cancelled }
}

public func sign(challenge: Data, handlePath: String, namespace: String,
                 retries: Int = 3, keygen: String = Paths.signKeygen,
                 canceller: SignCanceller? = nil) throws -> Data {
    var lastErr = ""
    for attempt in 0..<retries {
        if canceller?.isCancelled == true { throw SignError.failed("cancelled") }
        let p = Process(); p.executableURL = URL(fileURLWithPath: keygen)
        p.arguments = ["-Y", "sign", "-f", handlePath, "-n", namespace]
        p.environment = scrubbedEnv()
        let inP = Pipe(), outP = Pipe(), errP = Pipe()
        p.standardInput = inP; p.standardOutput = outP; p.standardError = errP
        try p.run()
        // Adopt AFTER run() (terminate() on an unlaunched Process throws); if cancel raced in first, kill now.
        if let c = canceller, !c.adopt(p) { p.terminate(); throw SignError.failed("cancelled") }
        inP.fileHandleForWriting.write(challenge)
        try? inP.fileHandleForWriting.close()
        let out = outP.fileHandleForReading.readDataToEndOfFile()
        let err = errP.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        if p.terminationStatus == 0, out.range(of: Data("BEGIN SSH SIGNATURE".utf8)) != nil { return out }
        if canceller?.isCancelled == true { throw SignError.failed("cancelled") }
        lastErr = String(data: err, encoding: .utf8) ?? ""
        if lastErr.contains("device not found") && attempt < retries - 1 {
            Thread.sleep(forTimeInterval: 1.5 * Double(attempt + 1)); continue
        }
        break
    }
    throw SignError.failed(lastErr)
}

/// Daemon-side. Writes the signature to a temp file inside `keydir` (0700, agent-unreachable),
/// message on stdin, then unlinks. NOT an inherited /dev/fd pipe (Foundation.Process closes it).
public func verify(challenge: Data, signature: Data, allowedSigners: String,
                   principal: String, namespace: String,
                   keygen: String = Paths.verifyKeygen, keydir: String = Paths.keydir) -> Bool {
    if signature.count > MAX_SIG || signature.isEmpty { return false }
    var tmpl = Array((keydir + "/.sig.XXXXXX").utf8CString)
    let fd = mkstemp(&tmpl)
    if fd < 0 { return false }
    let sigPath = String(cString: tmpl)
    defer { unlink(sigPath) }
    let ok = signature.withUnsafeBytes { raw -> Bool in
        var off = 0
        while off < signature.count {
            let w = write(fd, raw.baseAddress!.advanced(by: off), signature.count - off)
            if w < 0 && errno == EINTR { continue }
            if w <= 0 { return false }; off += w
        }
        return true
    }
    if close(fd) != 0 { return false }
    if !ok { return false }
    let p = Process(); p.executableURL = URL(fileURLWithPath: keygen)
    p.arguments = ["-Y", "verify", "-f", allowedSigners, "-I", principal, "-n", namespace, "-s", sigPath]
    p.environment = scrubbedEnv()
    let inP = Pipe(); p.standardInput = inP
    p.standardOutput = FileHandle.nullDevice; p.standardError = FileHandle.nullDevice
    do { try p.run() } catch { return false }
    inP.fileHandleForWriting.write(challenge)
    try? inP.fileHandleForWriting.close()
    p.waitUntilExit()
    return p.terminationStatus == 0
}
