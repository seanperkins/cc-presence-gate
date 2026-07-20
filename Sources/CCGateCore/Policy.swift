import Foundation
import Darwin

public enum PolicyError: Error { case badRegex(String), badFile(String) }

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
    // Internal initializer for hardcoded call sites (tests, literals).
    // Untrusted input MUST go through fromDict/fromFile, which validate each regex pattern before
    // reaching this point — so force-try below cannot crash on that path.
    // Internal (not public) so external code cannot accidentally pass raw unvalidated strings.
    init(sensitiveGlobs: [String], allowTier: [String], lockedPaths: [String],
         bashAdvisory: [String], mcpAllow: [[String]]) {
        self.sensitiveGlobs = sensitiveGlobs; self.allowTier = allowTier
        self.lockedPaths = Set(lockedPaths.map { matchPath($0, cwd: "/") })
        self.bashAdvisory = bashAdvisory.map { try! NSRegularExpression(pattern: $0) }
        self.mcpAllow = Set(mcpAllow)
    }
    public static func fromDict(_ d: [String: Any]) throws -> Policy {
        guard let sg = d["sensitive_globs"] as? [String] else { throw PolicyError.badFile("'sensitive_globs' missing or not a string array") }
        guard let at = d["allow_tier"] as? [String] else { throw PolicyError.badFile("'allow_tier' missing or not a string array") }
        guard let lp = d["locked_paths"] as? [String] else { throw PolicyError.badFile("'locked_paths' missing or not a string array") }
        guard let ba = d["bash_advisory"] as? [String] else { throw PolicyError.badFile("'bash_advisory' missing or not a string array") }
        guard let ma = d["mcp_allow"] as? [[String]] else { throw PolicyError.badFile("'mcp_allow' missing or not an array of string arrays") }
        for entry in ma where entry.count != 2 { throw PolicyError.badFile("mcp_allow entry \(entry) must be exactly [server, tool]") }
        for s in ba {   // fail-closed: validate every regex before construction
            do { _ = try NSRegularExpression(pattern: s) } catch { throw PolicyError.badRegex(s) }
        }
        return Policy(sensitiveGlobs: sg, allowTier: at, lockedPaths: lp, bashAdvisory: ba, mcpAllow: ma)
    }
    public static func fromFile(_ path: String) throws -> Policy {
        let data: Data
        do { data = try Data(contentsOf: URL(fileURLWithPath: path)) }
        catch { throw PolicyError.badFile("cannot read \(path): \(error.localizedDescription)") }
        let obj: Any
        do { obj = try JSONSerialization.jsonObject(with: data) }
        catch { throw PolicyError.badFile("invalid JSON in \(path): \(error.localizedDescription)") }
        guard let dict = obj as? [String: Any] else { throw PolicyError.badFile("\(path): top-level JSON must be an object") }
        return try fromDict(dict)
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
    public func summary() -> String {
        "policy OK: \(sensitiveGlobs.count) sensitive, \(allowTier.count) allow, \(lockedPaths.count) locked, \(bashAdvisory.count) bash, \(mcpAllow.count) mcp"
    }
    /// Static analysis of allow_tier for install-time review. fatal ⇒ refuse to install.
    public func lint() -> (fatal: [String], warnings: [String]) {
        var fatal: [String] = [], warnings: [String] = []
        let blanket: Set<String> = ["**", "/**", "*", "/*"]   // exact-match only — must NOT flag "/Users/x/**"
        for g in allowTier {
            if blanket.contains(g) {
                fatal.append("allow_tier contains blanket grant \"\(g)\" — trusts the entire filesystem un-gated")
                continue
            }
            let prefix = Policy.staticPrefix(g)
            if prefix.isEmpty { continue }
            var buf = [Int8](repeating: 0, count: Int(PATH_MAX))
            if realpath(prefix, &buf) != nil {
                let real = String(cString: buf)
                if real != prefix {
                    warnings.append("allow_tier \"\(g)\": prefix \(prefix) resolves to \(real) — writes arrive symlink-resolved and won't match; write \(real) instead")
                }
            } else {
                warnings.append("allow_tier \"\(g)\": prefix \(prefix) does not exist — this entry can never match")
            }
        }
        if allowTier.contains(where: { $0.hasSuffix("/**") }) && sensitiveGlobs.count < 3 {
            warnings.append("allow_tier grants a broad subtree while sensitive_globs is short (\(sensitiveGlobs.count)) — most writes will pass un-gated")
        }
        return (fatal, warnings)
    }
    /// The literal directory prefix of a glob, up to the segment containing the first metacharacter.
    static func staticPrefix(_ glob: String) -> String {
        guard let i = glob.firstIndex(where: { "*?[".contains($0) }) else { return glob }
        let head = String(glob[..<i])
        if head.hasSuffix("/") { return String(head.dropLast()) }   // "/Users/x/" -> "/Users/x"
        return (head as NSString).deletingLastPathComponent          // "/Users/x/foo" -> "/Users/x"
    }
}
