import Foundation
import CCGateCore

/// Arm+withhold must NOT sign within `window`s; positive control (touch) must sign. Terminates the
/// leaked negative signer before the positive control so they don't contend for the device. USER-RUN.
public func fidoNegativeBlinkTest(handle: String, namespace: String, window: Int = 8) -> Bool {
    FileHandle.standardError.write(Data(">>> Do NOT touch the key for a few seconds <<<\n".utf8))
    let neg = Process(); neg.executableURL = URL(fileURLWithPath: Paths.signKeygen)
    neg.arguments = ["-Y", "sign", "-f", handle, "-n", namespace]; neg.environment = scrubbedEnv()
    let inP = Pipe(); neg.standardInput = inP
    neg.standardOutput = FileHandle.nullDevice; neg.standardError = FileHandle.nullDevice
    do { try neg.run() } catch { return false }
    inP.fileHandleForWriting.write(Data("negative-blink".utf8)); try? inP.fileHandleForWriting.close()
    let deadline = Date().addingTimeInterval(Double(window))
    while neg.isRunning && Date() < deadline { Thread.sleep(forTimeInterval: 0.2) }
    let signedWithoutTouch = !neg.isRunning && neg.terminationStatus == 0
    if neg.isRunning { neg.terminate() }; neg.waitUntilExit()   // reap the leaked signer
    if signedWithoutTouch { return false }                       // signed with NO touch -> not touch-required
    FileHandle.standardError.write(Data(">>> Now TOUCH the key (positive control) <<<\n".utf8))
    return (try? fidoSign(challenge: Data("positive-control".utf8), handlePath: handle, namespace: namespace,
                          retries: 1, keygen: Paths.signKeygen)) != nil
}
