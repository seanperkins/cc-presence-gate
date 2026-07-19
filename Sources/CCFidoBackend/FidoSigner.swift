import Foundation
import Darwin
import CCGateCore

/// Cooperative cancellation for an in-flight `sign()`. Lets a concurrent dialog abort the armed key
/// (user clicked Cancel / dialog gave up) by terminating the live ssh-keygen. Thread-safe.
public final class SignCanceller: CeremonyCanceller {
    private let lock = NSLock()
    private var proc: Process?
    private var cancelled = false
    /// Adopt the running signer so a later cancel() can terminate it. Returns false if already cancelled.
    func adopt(_ p: Process) -> Bool { lock.lock(); defer { lock.unlock() }; if cancelled { return false }; proc = p; return true }
    public func cancel() { lock.lock(); defer { lock.unlock() }; cancelled = true; proc?.terminate() }
    var isCancelled: Bool { lock.lock(); defer { lock.unlock() }; return cancelled }
}

func fidoSign(challenge: Data, handlePath: String, namespace: String,
                 retries: Int = 3, keygen: String,
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

public struct FidoSigner: Signer {
    let keygen: String; let handlePath: String; let namespace: String
    public init(keygen: String, handlePath: String, namespace: String) {
        self.keygen = keygen; self.handlePath = handlePath; self.namespace = namespace
    }
    public func makeCanceller() -> CeremonyCanceller { SignCanceller() }
    public func sign(challenge: Data, canceller: CeremonyCanceller) throws -> Data {
        try fidoSign(challenge: challenge, handlePath: handlePath, namespace: namespace,
                     keygen: keygen, canceller: canceller as? SignCanceller)
    }
}
