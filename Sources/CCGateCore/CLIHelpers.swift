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
/// Value immediately following `flag` in `args`, or nil if `flag` is absent or has no trailing value
/// (a flag as the last arg must not index out of bounds).
public func flagValue(_ flag: String, in args: [String]) -> String? {
    guard let i = args.firstIndex(of: flag), i + 1 < args.count else { return nil }
    return args[i + 1]
}
@discardableResult
public func runPrivileged(_ argv: [String]) -> Bool {
    let p = Process(); p.executableURL = URL(fileURLWithPath: "/usr/bin/sudo"); p.arguments = argv
    p.environment = scrubbedEnv()   // same invariant as every other spawned child (Task-7 review)
    do { try p.run() } catch { return false }
    p.waitUntilExit(); return p.terminationStatus == 0
}
public enum RenderError: Error { case badHome(String), badSource(String) }

/// Reads a policy template, guards `home`, substitutes `__HOME__`→`home` in every JSON string value
/// (parse → walk → re-serialize, so a home with `"`/`\`/`&` can never corrupt the JSON), and returns
/// pretty JSON. Does NOT check policy semantics — the caller runs `Policy.fromDict` + `lint()`.
public func renderPolicy(srcPath: String, home: String) throws -> Data {
    let banned: Set<String> = ["", "/", "/var/root", "/root"]
    guard !banned.contains(home), (home as NSString).isAbsolutePath else {
        throw RenderError.badHome("refusing HOME='\(home)' — run as the login user, not root")
    }
    guard let data = try? Data(contentsOf: URL(fileURLWithPath: srcPath)) else {
        throw RenderError.badSource("cannot read \(srcPath)")
    }
    guard let obj = try? JSONSerialization.jsonObject(with: data) else {
        throw RenderError.badSource("invalid JSON in \(srcPath)")
    }
    let substituted = substituteHome(obj, home)
    return try JSONSerialization.data(withJSONObject: substituted, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes])
}
private func substituteHome(_ v: Any, _ home: String) -> Any {
    if let s = v as? String { return s.replacingOccurrences(of: "__HOME__", with: home) }
    if let a = v as? [Any] { return a.map { substituteHome($0, home) } }
    if let d = v as? [String: Any] { return d.mapValues { substituteHome($0, home) } }
    return v
}
