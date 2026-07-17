import Foundation
import Darwin

public func renderPlist(binary: String = Paths.code + "/cc-fido") -> String {
    """
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0"><dict>
      <key>Label</key><string>com.cc-fido-gate.brokerd</string>
      <key>UserName</key><string>_ccfido</string>
      <key>ProgramArguments</key><array><string>\(binary)</string><string>daemon</string></array>
      <key>KeepAlive</key><true/>
      <key>RunAtLoad</key><true/>
      <key>StandardErrorPath</key><string>/var/ccfido/brokerd.err</string>
    </dict></plist>
    """
}
public func renderManagedSettings(hookCmd: String) -> String {
    let obj: [String: Any] = ["allowManagedHooksOnly": true,
        "hooks": ["PreToolUse": [["matcher": "Write|Edit|MultiEdit|NotebookEdit|Bash|mcp__.*",
                                  "hooks": [["type": "command", "command": hookCmd, "timeout": 90]]]]]]
    return String(data: try! JSONSerialization.data(withJSONObject: obj, options: [.prettyPrinted, .sortedKeys]), encoding: .utf8)!
}
public func ccVersion(_ claudeBin: String) -> String {
    let p = Process(); p.executableURL = URL(fileURLWithPath: claudeBin); p.arguments = ["--version"]
    p.environment = scrubbedEnv()   // consistency: every spawned child is env-scrubbed
    let out = Pipe(); p.standardOutput = out; p.standardError = FileHandle.nullDevice
    do { try p.run() } catch { return "unknown" }
    let s = String(data: out.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""; p.waitUntilExit()
    if let m = s.range(of: #"\d+\.\d+\.\d+"#, options: .regularExpression) { return String(s[m]) }
    return "unknown"
}
@discardableResult
public func runPrivileged(_ argv: [String]) -> Bool {
    let p = Process(); p.executableURL = URL(fileURLWithPath: "/usr/bin/sudo"); p.arguments = argv
    p.environment = scrubbedEnv()   // same invariant as every other spawned child (Task-7 review)
    do { try p.run() } catch { return false }
    p.waitUntilExit(); return p.terminationStatus == 0
}
/// Arm+withhold must NOT sign within `window`s; positive control (touch) must sign. Terminates the
/// leaked negative signer before the positive control so they don't contend for the device. USER-RUN.
public func negativeBlinkTest(handle: String, namespace: String, window: Int = 8) -> Bool {
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
    return (try? sign(challenge: Data("positive-control".utf8), handlePath: handle, namespace: namespace, retries: 1)) != nil
}
