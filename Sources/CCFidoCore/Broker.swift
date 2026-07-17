import Foundation
import Darwin

public enum BrokerError: Error { case writeFailed(String) }

public final class Broker {
    let sockPath: String
    let allowedSigners: String
    public init(sockPath: String = Paths.sock, allowedSigners: String = Paths.allowedSigners) {
        self.sockPath = sockPath; self.allowedSigners = allowedSigners
    }

    // --- authorization helpers (pure, [SW]-tested) ---
    /// Canonical comparison form: standardize + strip the macOS `/private` firmlink prefix, so `/var…`
    /// and `/private/var…` (the form `F_GETPATH` returns) map to ONE string. NO `realpath` — realpathing
    /// only `norm` forked `/var` vs `/private/var` against the lexical constants + registry (round-3
    /// regression). Symlink-redirect defense is the `F_GETPATH` post-open re-check in `uchgWrite`, not
    /// this string normalization.
    public static func normPath(_ path: String) -> String {
        let p = (path as NSString).standardizingPath
        // Only the ACTUAL macOS firmlinked roots fold — NOT every /private/* path (else /private/foo→/foo,
        // which could alias registry auth onto the wrong object). Verification-pass codex HIGH.
        for root in ["/var", "/etc", "/tmp"] {
            if p == "/private" + root { return root }
            if p.hasPrefix("/private" + root + "/") { return String(p.dropFirst("/private".count)) }
        }
        return p
    }
    public static func isControlPath(_ path: String) -> Bool {
        let p = normPath(path)
        if Paths.controlDenylist.map(normPath).contains(p) { return true }
        return p.hasPrefix(Paths.keydir + "/") || p == Paths.keydir
            || p.hasPrefix(Paths.code + "/") || p == Paths.code
    }
    public static func isEnrolledTarget(_ path: String, registry: [String]) -> Bool {
        let p = normPath(path)
        return registry.contains { normPath($0) == p }
    }
    func loadRegistry() -> [String] {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: Paths.custody)),
              let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
              let files = obj["files"] as? [String] else { return [] }
        return files
    }

    // nouchg -> O_NOFOLLOW open (NO O_TRUNC) -> validate the OPEN FD -> ftruncate -> write -> fsync -> checked uchg.
    // Round-3 fixes (codex CRITICAL + pentester HIGH): DO NOT O_TRUNC before validating — a redirect would
    // truncate the target before the fstat guard catches it, so we open without O_TRUNC and only ftruncate
    // AFTER every check passes. fstat asserts regular + st_nlink==1 + owner==_ccfido, FAIL-CLOSED if the
    // _ccfido lookup fails. Then F_GETPATH re-derives the ACTUALLY-OPENED path (fully symlink-resolved) and
    // re-runs the control/enrolled checks on it — this is what closes the intermediate-directory-symlink
    // redirect that O_NOFOLLOW (final-component only) cannot. `norm` is the already-validated enrolled target.
    func uchgWrite(_ norm: String, _ content: Data, registry: [String]) throws {
        guard let ccfidoUID = getpwnam("_ccfido").map({ $0.pointee.pw_uid }) else {
            throw BrokerError.writeFailed("_ccfido lookup failed — refusing (fail closed)")
        }
        var relocked = false
        func relock() throws {
            if relocked { return }
            if chflags(norm, UInt32(UF_IMMUTABLE)) != 0 {
                throw BrokerError.writeFailed("RELOCK FAILED — target left unlocked: \(String(cString: strerror(errno)))")
            }
            relocked = true
        }
        chflags(norm, 0)  // unlock; on the failure paths below we relock via the catch
        do {
            let fd = open(norm, O_WRONLY | O_CREAT | O_NOFOLLOW, 0o600)   // NOTE: no O_TRUNC
            if fd < 0 { throw BrokerError.writeFailed("open: \(String(cString: strerror(errno)))") }
            defer { close(fd) }   // (close() errno on a write fd is not meaningfully recoverable after fsync)
            var st = stat()
            guard fstat(fd, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG,
                  st.st_nlink == 1, st.st_uid == ccfidoUID else {
                throw BrokerError.writeFailed("target is not a lone _ccfido-owned regular file (nlink/owner)")
            }
            // Re-check the path the fd ACTUALLY points at (defeats intermediate-symlink ancestor swap):
            var pbuf = [Int8](repeating: 0, count: Int(PATH_MAX))
            guard fcntl(fd, F_GETPATH, &pbuf) == 0 else { throw BrokerError.writeFailed("F_GETPATH") }
            let real = Broker.normPath(String(cString: pbuf))
            // `norm` was already validated (non-control + enrolled) in handle(); requiring the OPENED
            // path to equal it is strictly stronger than membership — it also closes the enrolled→enrolled
            // basename-collision redirect (pentester-verify residual 1). isControlPath(real) kept as an
            // explicit belt. (A legit target with a symlinked ancestor over-denies here — fail-closed, and
            // checkAncestors already WARNed at enroll time.)
            guard real == norm, !Broker.isControlPath(real), Broker.isEnrolledTarget(real, registry: registry) else {
                throw BrokerError.writeFailed("post-open path escaped: \(real) (norm=\(norm))")
            }
            if ftruncate(fd, 0) != 0 { throw BrokerError.writeFailed("ftruncate: \(String(cString: strerror(errno)))") }
            try content.withUnsafeBytes { raw in
                var off = 0
                while off < content.count {
                    let w = write(fd, raw.baseAddress!.advanced(by: off), content.count - off)
                    if w < 0 && errno == EINTR { continue }
                    if w <= 0 { throw BrokerError.writeFailed("write: \(String(cString: strerror(errno)))") }
                    off += w
                }
            }
            if fsync(fd) != 0 { throw BrokerError.writeFailed("fsync failed") }
        } catch {
            try? relock(); throw error   // best-effort relock on failure; original error propagates
        }
        try relock()   // MUST succeed on the success path or we throw (caller logs write_error, not write_ok)
    }

    func handle(_ fd: Int32) throws {
        let caller = peerUID(fd)
        let req = try recvMsg(fd)
        guard req["op"] as? String == "execute-write",
              let path = req["path"] as? String,
              let b64 = req["content_b64"] as? String,
              let content = Data(base64Encoded: b64) else {
            try sendMsg(fd, ["phase": "result", "status": "deny", "reason": "bad request"]); return
        }
        let norm = Broker.normPath(path)    // /private-stripped; same string feeds the checks AND uchgWrite's open
        let reg = loadRegistry()
        if Broker.isControlPath(norm) || !Broker.isEnrolledTarget(norm, registry: reg) {
            try auditAppend(["event": "deny_target", "path": norm, "caller": caller])
            try sendMsg(fd, ["phase": "result", "status": "deny", "reason": "not an enrolled target"]); return
        }
        let nonce = (0..<16).map { _ in String(format: "%02x", UInt8.random(in: 0...255)) }.joined()
        let doc = buildSignedDocument(op: "execute-write", path: norm,
                                      contentSha256: sha256Hex(content),
                                      cwd: req["cwd"] as? String ?? "", nonceHex: nonce, callerUid: caller)
        let challenge = try canonicalBytes(doc)
        try sendMsg(fd, ["phase": "challenge", "challenge_b64": challenge.base64EncodedString(),
                         "human_rendering": "WRITE \(norm)\n\(content.count) bytes  sha256:\(doc.contentSha256)"])
        let reply = try recvMsg(fd)
        guard reply["phase"] as? String == "signature",
              let sigB64 = reply["signature_b64"] as? String, let sig = Data(base64Encoded: sigB64),
              verify(challenge: challenge, signature: sig, allowedSigners: allowedSigners,
                     principal: Paths.principal, namespace: Paths.namespace) else {
            try auditAppend(["event": "deny", "path": norm, "caller": caller])
            try sendMsg(fd, ["phase": "result", "status": "deny", "reason": "no valid touch"]); return
        }
        do { try uchgWrite(norm, content, registry: reg) }
        catch {
            try auditAppend(["event": "write_error", "path": norm, "caller": caller, "err": "\(error)"])
            try sendMsg(fd, ["phase": "result", "status": "deny", "reason": "write failed"]); return
        }
        try auditAppend(["event": "write_ok", "path": norm, "caller": caller,
                         "content_sha256": doc.contentSha256])
        try sendMsg(fd, ["phase": "result", "status": "ok"])
    }

    public func serve() throws {
        signal(SIGPIPE, SIG_IGN)
        unlink(sockPath)
        let s = socket(AF_UNIX, SOCK_STREAM, 0)
        if s < 0 { throw BrokerError.writeFailed("socket()") }
        var addr = sockaddr_un(); addr.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = Array(sockPath.utf8)
        if pathBytes.count >= MemoryLayout.size(ofValue: addr.sun_path) {
            throw BrokerError.writeFailed("socket path too long")
        }
        withUnsafeMutablePointer(to: &addr.sun_path) {
            $0.withMemoryRebound(to: CChar.self, capacity: pathBytes.count + 1) { dst in
                for (i, b) in pathBytes.enumerated() { dst[i] = CChar(bitPattern: b) }; dst[pathBytes.count] = 0
            }
        }
        let sz = socklen_t(MemoryLayout<sockaddr_un>.size)
        let bindRC = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(s, $0, sz) }
        }
        if bindRC != 0 { throw BrokerError.writeFailed("bind: \(String(cString: strerror(errno)))") }
        chmod(sockPath, 0o666)      // any local caller; auth is by touch, not identity
        if listen(s, 16) != 0 { throw BrokerError.writeFailed("listen") }
        while true {
            let conn = accept(s, nil, nil)
            if conn < 0 { if errno == EINTR { continue }; usleep(100_000); continue }
            // per-connection thread so one slow ceremony never starves accept (DoS fix)
            Thread.detachNewThread { [weak self] in self?.handleGuarded(conn) }
        }
    }

    static let ceremonyDeadline: TimeInterval = 90

    func handleGuarded(_ conn: Int32) {
        defer { close(conn) }
        // REAL absolute wall-clock cap (round-2 fix): SO_RCVTIMEO is only a per-recv idle timeout and a
        // slow-drip peer can reset it forever, holding the ceremony flock and starving every other write.
        // A one-shot watchdog thread shutdown()s the connection at start+deadline, which unblocks any
        // recv AND (because the fd is force-closed) collapses the ceremony so the flock defer releases.
        var tv = timeval(tv_sec: 90, tv_usec: 0)   // belt: per-recv idle bound
        setsockopt(conn, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        let done = DispatchSemaphore(value: 0)
        Thread.detachNewThread {
            if done.wait(timeout: .now() + Broker.ceremonyDeadline) == .timedOut {
                shutdown(conn, SHUT_RDWR)   // absolute cap: force the blocked recv/handle to error out
            }
        }
        defer { done.signal() }
        // flock is load-bearing BEYOND serialization: auditAppend is read-modify-write (reads all lines to
        // compute seq/prev_hash, then appends) and is NOT atomic — two concurrent ceremonies would both write
        // seq=N and corrupt the chain. The flock serializes them. Do NOT drop it when tuning the watchdog;
        // if per-connection concurrency is ever wanted, give auditAppend its own flock on the audit file.
        let lockFD = open(Paths.ceremonyLock, O_CREAT | O_RDWR, 0o600)
        if lockFD < 0 { return }
        if flock(lockFD, LOCK_EX) != 0 { close(lockFD); return }
        defer { flock(lockFD, LOCK_UN); close(lockFD) }
        do { try handle(conn) } catch { /* malformed/aborted/deadline: drop */ }
    }
}
