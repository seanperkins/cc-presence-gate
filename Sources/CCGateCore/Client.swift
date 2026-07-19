import Foundation
import Darwin

func connectSock(_ path: String) -> Int32 {
    signal(SIGPIPE, SIG_IGN)
    let s = socket(AF_UNIX, SOCK_STREAM, 0)
    var addr = sockaddr_un(); addr.sun_family = sa_family_t(AF_UNIX)
    let pb = Array(path.utf8)
    withUnsafeMutablePointer(to: &addr.sun_path) {
        $0.withMemoryRebound(to: CChar.self, capacity: pb.count + 1) { dst in
            for (i, b) in pb.enumerated() { dst[i] = CChar(bitPattern: b) }; dst[pb.count] = 0 }
    }
    let sz = socklen_t(MemoryLayout<sockaddr_un>.size)
    let rc = withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(s, $0, sz) } }
    return rc == 0 ? s : -1
}

public func runWrite(ctx: GateContext, path: String, content: Data) -> Int32 {
    let fd = connectSock(ctx.profile.sock)
    guard fd >= 0 else { FileHandle.standardError.write(Data("\(ctx.profile.binaryName): broker unreachable\n".utf8)); return 1 }
    defer { close(fd) }
    do {
        try sendMsg(fd, ["op": "execute-write", "path": path,
                         "content_b64": content.base64EncodedString(), "cwd": ""])
        let msg = try recvMsg(fd)
        guard msg["phase"] as? String == "challenge", let human = msg["human_rendering"] as? String,
              let chB64 = msg["challenge_b64"] as? String, let challenge = Data(base64Encoded: chB64) else {
            let reason = (msg["reason"] as? String) ?? "protocol error"
            FileHandle.standardError.write(Data("\(ctx.profile.binaryName): \(reason)\n".utf8)); return 1
        }
        guard let sig = ctx.ceremony.confirmAndSign(rendering: human, challenge: challenge, displayName: ctx.profile.displayName) else {
            try sendMsg(fd, ["phase": "abort", "reason": "denied"]); return 1
        }
        try sendMsg(fd, ["phase": "signature", "signature_b64": sig.base64EncodedString()])
        let result = try recvMsg(fd)
        if result["status"] as? String == "ok" { print("\(ctx.profile.binaryName): wrote \(path)"); return 0 }
        FileHandle.standardError.write(Data("\(ctx.profile.binaryName): denied (\(result["reason"] ?? ""))\n".utf8)); return 1
    } catch { return 1 }
}

public func runApprove(ctx: GateContext, tool: String, toolInput: [String: Any], cwd: String) -> Bool {
    let fd = connectSock(ctx.profile.sock); guard fd >= 0 else { return false }
    defer { close(fd) }
    do {
        try sendMsg(fd, ["op": "approve", "tool": tool, "input": toolInput, "cwd": cwd])
        let msg = try recvMsg(fd)
        guard let human = msg["human_rendering"] as? String, let chB64 = msg["challenge_b64"] as? String,
              let challenge = Data(base64Encoded: chB64) else { return false }
        guard let sig = ctx.ceremony.confirmAndSign(rendering: human, challenge: challenge, displayName: ctx.profile.displayName) else {
            try sendMsg(fd, ["phase": "abort", "reason": "denied"]); return false
        }
        try sendMsg(fd, ["phase": "signature", "signature_b64": sig.base64EncodedString()])
        return (try recvMsg(fd))["status"] as? String == "ok"
    } catch { return false }
}
