import Foundation
import Darwin

/// Softened WYSIWYS + touch-to-approve, run CONCURRENTLY: the dialog shows what's being signed AND the
/// key is armed at the same time, so any of { touch, Enter, click Approve } approves from the get-go, and
/// { Cancel, walk away (dialog gives up after 60s) } denies. Returns the signature on approval, nil otherwise.
/// The physical touch remains the real gate — the daemon still verifies a challenge-bound signature; this is
/// pure client UX. Rendering is passed as an AppleScript argv item, never interpolated into -e.
func confirmAndSign(_ humanRendering: String, challenge: Data,
                    signer: Signer, displayName: String = "cc-fido-gate") -> Data? {
    let dlg = Process(); dlg.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
    dlg.arguments = ["-l", "AppleScript",
        "-e", "on run argv",
        "-e", "display dialog (item 1 of argv) buttons {\"Cancel\", \"Approve\"} default button \"Approve\" with title \"\(displayName)\" giving up after 60",
        "-e", "end run",
        humanRendering]
    dlg.environment = scrubbedEnv()
    let dOut = Pipe(); dlg.standardOutput = dOut; dlg.standardError = FileHandle.nullDevice
    do { try dlg.run() } catch { return nil }   // no dialog → deny (fail-safe)

    let canceller = signer.makeCanceller()
    let lock = NSLock()
    var sig: Data? = nil
    var done = false                 // first resolver (touch OR button) wins
    let group = DispatchGroup()

    // Signer: arm the key immediately; a touch resolves it. On success, dismiss the still-open dialog.
    group.enter()
    DispatchQueue.global().async {
        let s = try? signer.sign(challenge: challenge, canceller: canceller)
        lock.lock()
        if let s = s, !done { sig = s; done = true; if dlg.isRunning { dlg.terminate() } }
        lock.unlock()
        group.leave()
    }
    // Dialog: Cancel/give-up denies (kills the armed key). Approve just leaves the key armed for the touch.
    group.enter()
    DispatchQueue.global().async {
        let out = dOut.fileHandleForReading.readDataToEndOfFile()
        dlg.waitUntilExit()
        let str = String(data: out, encoding: .utf8) ?? ""
        let approved = dlg.terminationStatus == 0 && str.contains("button returned:Approve") && !str.contains("gave up:true")
        lock.lock()
        if !approved && !done { done = true; canceller.cancel() }
        lock.unlock()
        group.leave()
    }
    // Backstop so an Approve-but-never-touch can't hang the client (matches the daemon's ceremonyDeadline).
    if group.wait(timeout: .now() + 90) == .timedOut {
        canceller.cancel(); if dlg.isRunning { dlg.terminate() }; group.wait()
    }
    return sig
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

public func runWrite(path: String, content: Data, signer: Signer, sockPath: String = Paths.sock) -> Int32 {
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
        guard let sig = confirmAndSign(human, challenge: challenge, signer: signer) else {
            try sendMsg(fd, ["phase": "abort", "reason": "denied"]); return 1
        }
        try sendMsg(fd, ["phase": "signature", "signature_b64": sig.base64EncodedString()])
        let result = try recvMsg(fd)
        if result["status"] as? String == "ok" { print("cc-fido: wrote \(path)"); return 0 }
        FileHandle.standardError.write(Data("cc-fido: denied (\(result["reason"] ?? ""))\n".utf8)); return 1
    } catch { return 1 }
}

public func runApprove(tool: String, toolInput: [String: Any], cwd: String, signer: Signer, sockPath: String = Paths.sock) -> Bool {
    let fd = connectSock(sockPath); guard fd >= 0 else { return false }
    defer { close(fd) }
    do {
        try sendMsg(fd, ["op": "approve", "tool": tool, "input": toolInput, "cwd": cwd])
        let msg = try recvMsg(fd)
        guard let human = msg["human_rendering"] as? String, let chB64 = msg["challenge_b64"] as? String,
              let challenge = Data(base64Encoded: chB64) else { return false }
        guard let sig = confirmAndSign(human, challenge: challenge, signer: signer) else {
            try sendMsg(fd, ["phase": "abort", "reason": "denied"]); return false
        }
        try sendMsg(fd, ["phase": "signature", "signature_b64": sig.base64EncodedString()])
        return (try recvMsg(fd))["status"] as? String == "ok"
    } catch { return false }
}
