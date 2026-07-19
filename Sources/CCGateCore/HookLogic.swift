import Foundation

func denyNudgeMsg(_ profile: GateProfile) -> String {
    "\(profile.binaryName): this path is gate-locked. Use `\(profile.binaryName) write <path>` (content on stdin) to change it — a physical touch is required."
}
func allowJSON(_ profile: GateProfile) -> String {
    #"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","permissionDecisionReason":"\#(profile.binaryName): touch verified"}}"#
}

/// Pure allowlist filter (unit-tested). The RUNTIME application is `scrubbedEnv()` in Crypto.swift,
/// which every child spawn (sign/verify/dialog) already sets as `Process.environment`. This function
/// is the same policy expressed over an arbitrary env dict, used where an explicit env must be built.
public func scrubEnv(_ env: [String: String]) -> [String: String] {
    var keep: [String: String] = [:]
    for k in ["HOME", "USER", "LANG", "__CF_USER_TEXT_ENCODING"] { if let v = env[k] { keep[k] = v } }
    keep["PATH"] = "/usr/bin:/bin:/usr/sbin:/sbin"
    return keep
}
public func decideAndEmit(event: [String: Any], policy: Policy, profile: GateProfile, out: FileHandle, err: FileHandle,
                          approve: (String, [String: Any], String) -> Bool) -> Int32 {
    let tool = event["tool_name"] as? String ?? ""
    let input = event["tool_input"] as? [String: Any] ?? [:]
    let cwd = event["cwd"] as? String ?? ""
    switch policy.decide(tool: tool, toolInput: input, cwd: cwd) {
    case .pass: return 0
    case .denyNudge: err.write(Data((denyNudgeMsg(profile) + "\n").utf8)); return 2
    case .gate:
        if approve(tool, input, cwd) { out.write(Data((allowJSON(profile) + "\n").utf8)); return 0 }
        err.write(Data("\(profile.binaryName): touch not provided — denied\n".utf8)); return 2
    }
}
public func hookMain(ctx: GateContext) -> Never {
    let data = FileHandle.standardInput.readDataToEndOfFile()
    guard let event = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else {
        FileHandle.standardError.write(Data("\(ctx.profile.binaryName): unreadable payload — failing closed\n".utf8)); exit(2)
    }
    guard let policy = try? Policy.fromFile(ctx.profile.policy) else {
        FileHandle.standardError.write(Data("\(ctx.profile.binaryName): no policy — failing closed\n".utf8)); exit(2)
    }
    exit(decideAndEmit(event: event, policy: policy, profile: ctx.profile, out: FileHandle.standardOutput,
                       err: FileHandle.standardError) { t, i, c in runApprove(ctx: ctx, tool: t, toolInput: i, cwd: c) })
}
