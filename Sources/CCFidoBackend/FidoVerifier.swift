import Foundation
import Darwin
import CCGateCore

/// Daemon-side. Writes the signature to a temp file inside `keydir` (0700, agent-unreachable),
/// message on stdin, then unlinks. NOT an inherited /dev/fd pipe (Foundation.Process closes it).
func fidoVerify(challenge: Data, signature: Data, allowedSigners: String,
                   principal: String, namespace: String,
                   keygen: String, keydir: String) -> Bool {
    if signature.count > MAX_SIG || signature.isEmpty { return false }
    var tmpl = Array((keydir + "/.sig.XXXXXX").utf8CString)
    let fd = mkstemp(&tmpl)
    if fd < 0 { return false }
    let sigPath = String(cString: tmpl)
    defer { unlink(sigPath) }
    let ok = signature.withUnsafeBytes { raw -> Bool in
        var off = 0
        while off < signature.count {
            let w = write(fd, raw.baseAddress!.advanced(by: off), signature.count - off)
            if w < 0 && errno == EINTR { continue }
            if w <= 0 { return false }; off += w
        }
        return true
    }
    if close(fd) != 0 { return false }
    if !ok { return false }
    let p = Process(); p.executableURL = URL(fileURLWithPath: keygen)
    p.arguments = ["-Y", "verify", "-f", allowedSigners, "-I", principal, "-n", namespace, "-s", sigPath]
    p.environment = scrubbedEnv()
    let inP = Pipe(); p.standardInput = inP
    p.standardOutput = FileHandle.nullDevice; p.standardError = FileHandle.nullDevice
    do { try p.run() } catch { return false }
    inP.fileHandleForWriting.write(challenge)
    try? inP.fileHandleForWriting.close()
    p.waitUntilExit()
    return p.terminationStatus == 0
}

public struct FidoVerifier: Verifier {
    let keygen: String; let allowedSigners: String; let principal: String
    let namespace: String; let keydir: String
    public init(keygen: String, allowedSigners: String, principal: String, namespace: String, keydir: String) {
        self.keygen = keygen; self.allowedSigners = allowedSigners; self.principal = principal
        self.namespace = namespace; self.keydir = keydir
    }
    public func verify(challenge: Data, signature: Data) -> Bool {
        fidoVerify(challenge: challenge, signature: signature, allowedSigners: allowedSigners,
                   principal: principal, namespace: namespace, keygen: keygen, keydir: keydir)
    }
}
