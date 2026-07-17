import Foundation
import Darwin

public enum PolicyError: Error { case badRegex(String), badFile }

public func matchPath(_ path: String, cwd: String) -> String {
    let abs = (path as NSString).isAbsolutePath ? path : (cwd as NSString).appendingPathComponent(path)
    // realpath the existing ancestor so /var vs /private/var can't fork the match; append the lexical suffix.
    // (realpath already resolves symlinks in `dir`; do NOT pre-resolve with destinationOfSymbolicLink —
    // that returns a possibly-relative target and would be re-resolved against CWD. Round-2 fix.)
    let ns = (abs as NSString).standardizingPath
    var dir = (ns as NSString).deletingLastPathComponent
    let leaf = (ns as NSString).lastPathComponent
    var resolved = [Int8](repeating: 0, count: Int(PATH_MAX))
    if realpath(dir, &resolved) != nil { dir = String(cString: resolved) }
    return (dir as NSString).appendingPathComponent(leaf)
}
func globMatch(_ pattern: String, _ path: String) -> Bool { fnmatch(pattern, path, 0) == 0 }

public struct Policy {
    public enum Verdict { case pass, gate, denyNudge }
    let sensitiveGlobs, allowTier: [String]
    let lockedPaths: Set<String>
    let bashAdvisory: [NSRegularExpression]
    let mcpAllow: Set<[String]>
    // Single public initializer matching the interface list: bashAdvisory is raw patterns.
    // Force-compiled here because this direct constructor is for hardcoded call sites (tests, literals);
    // untrusted input must go through fromDict/fromFile, which validate each pattern before ever
    // reaching this initializer, so the force-try below cannot crash on that path.
    public init(sensitiveGlobs: [String], allowTier: [String], lockedPaths: [String],
                bashAdvisory: [String], mcpAllow: [[String]]) {
        self.sensitiveGlobs = sensitiveGlobs; self.allowTier = allowTier
        self.lockedPaths = Set(lockedPaths.map { matchPath($0, cwd: "/") })
        self.bashAdvisory = bashAdvisory.map { try! NSRegularExpression(pattern: $0) }
        self.mcpAllow = Set(mcpAllow)
    }
    public static func fromDict(_ d: [String: Any]) throws -> Policy {
        guard let sg = d["sensitive_globs"] as? [String], let at = d["allow_tier"] as? [String],
              let lp = d["locked_paths"] as? [String], let ba = d["bash_advisory"] as? [String],
              let ma = d["mcp_allow"] as? [[String]] else { throw PolicyError.badFile }
        // Fail-closed: validate every regex before construction (no as!, no silent compactMap-drop).
        for s in ba {
            do { _ = try NSRegularExpression(pattern: s) } catch { throw PolicyError.badRegex(s) }
        }
        return Policy(sensitiveGlobs: sg, allowTier: at, lockedPaths: lp, bashAdvisory: ba, mcpAllow: ma)
    }
    public static func fromFile(_ path: String) throws -> Policy {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
              let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else { throw PolicyError.badFile }
        return try fromDict(obj)
    }
    func decideWrite(_ path: String, _ cwd: String) -> Verdict {
        let p = matchPath(path, cwd: cwd)
        if lockedPaths.contains(p) { return .denyNudge }
        if sensitiveGlobs.contains(where: { globMatch($0, p) }) { return .gate }
        if allowTier.contains(where: { globMatch($0, p) }) { return .pass }
        return .gate
    }
    func decideMcp(_ tool: String) -> Verdict {
        let parts = tool.components(separatedBy: "__")
        guard parts.count >= 3 else { return .gate }
        return mcpAllow.contains([parts[1], parts[2...].joined(separator: "__")]) ? .pass : .gate
    }
    public func decide(tool: String, toolInput: [String: Any], cwd: String) -> Verdict {
        switch tool {
        case "Write", "Edit": return decideWrite(toolInput["file_path"] as? String ?? "", cwd)
        case "Bash":
            guard let cmd = toolInput["command"] as? String else { return .gate }  // missing -> gate, not pass
            let r = NSRange(cmd.startIndex..., in: cmd)
            return bashAdvisory.contains { $0.firstMatch(in: cmd, range: r) != nil } ? .gate : .pass
        default: return tool.hasPrefix("mcp__") ? decideMcp(tool) : .gate
        }
    }
}
