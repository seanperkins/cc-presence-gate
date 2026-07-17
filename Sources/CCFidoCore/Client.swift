import Foundation
import Darwin

/// Softened WYSIWYS dialog. Rendering passed as an AppleScript argv item, never interpolated into -e.
func dialog(_ humanRendering: String) -> Bool {
    let p = Process(); p.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
    p.arguments = ["-l", "AppleScript",
        "-e", "on run argv",
        "-e", "display dialog (item 1 of argv) buttons {\"Cancel\", \"Approve\"} default button \"Cancel\" with title \"cc-fido-gate\" giving up after 60",
        "-e", "end run",
        humanRendering]
    p.environment = scrubbedEnv()
    let out = Pipe(); p.standardOutput = out; p.standardError = FileHandle.nullDevice
    do { try p.run() } catch { return false }
    let data = out.fileHandleForReading.readDataToEndOfFile(); p.waitUntilExit()
    let s = String(data: data, encoding: .utf8) ?? ""
    return p.terminationStatus == 0 && s.contains("button returned:Approve") && !s.contains("gave up:true")
}

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

public func runWrite(path: String, content: Data, sockPath: String = Paths.sock) -> Int32 {
    let fd = connectSock(sockPath)
    guard fd >= 0 else { FileHandle.standardError.write(Data("cc-fido: broker unreachable\n".utf8)); return 1 }
    defer { close(fd) }
    do {
        try sendMsg(fd, ["op": "execute-write", "path": path,
                         "content_b64": content.base64EncodedString(), "cwd": ""])
        let msg = try recvMsg(fd)
        guard msg["phase"] as? String == "challenge", let human = msg["human_rendering"] as? String,
              let chB64 = msg["challenge_b64"] as? String, let challenge = Data(base64Encoded: chB64) else {
            let reason = (msg["reason"] as? String) ?? "protocol error"
            FileHandle.standardError.write(Data("cc-fido: \(reason)\n".utf8)); return 1
        }
        if !dialog(human) { try sendMsg(fd, ["phase": "abort", "reason": "cancelled"]); return 1 }
        let sig: Data
        do { sig = try sign(challenge: challenge, handlePath: Paths.handle, namespace: Paths.namespace) }
        catch { try sendMsg(fd, ["phase": "abort", "reason": "sign failed"]); return 1 }
        try sendMsg(fd, ["phase": "signature", "signature_b64": sig.base64EncodedString()])
        let result = try recvMsg(fd)
        if result["status"] as? String == "ok" { print("cc-fido: wrote \(path)"); return 0 }
        FileHandle.standardError.write(Data("cc-fido: denied (\(result["reason"] ?? ""))\n".utf8)); return 1
    } catch { return 1 }
}
