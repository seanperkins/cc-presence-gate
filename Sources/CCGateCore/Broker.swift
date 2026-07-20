import Foundation
import Darwin

public enum BrokerError: Error { case writeFailed(String) }

public final class Broker {
    let profile: GateProfile
    let verifier: Verifier
    var sockPath: String { profile.sock }
    public init(profile: GateProfile, verifier: Verifier) {
        self.profile = profile; self.verifier = verifier
    }

    // --- authorization helpers (pure, [SW]-tested) ---
    /// Canonical comparison form: standardize + strip the macOS `/private` firmlink prefix, so `/var…`
    /// and `/private/var…` (the form `F_GETPATH` returns) map to ONE string. NO `realpath` — realpathing
    /// only `norm` forked `/var` vs `/private/var` against the lexical constants + registry (round-3
    /// regression). Symlink-redirect defense is the `F_GETPATH` post-open re-check in `uchgWrite`, not
    /// this string normalization. Profile-independent — the firmlinked roots are a fixed platform fact.
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
    /// Profile-dependent — reads the product's own control-file roots.
    func isControlPath(_ path: String) -> Bool {
        let p = Broker.normPath(path)
        if profile.controlDenylist.map(Broker.normPath).contains(p) { return true }
        return p.hasPrefix(profile.keydir + "/") || p == profile.keydir
            || p.hasPrefix(profile.codeDir + "/") || p == profile.codeDir
    }
    /// Profile-independent — the registry itself carries the enrolled paths.
    public static func isEnrolledTarget(_ path: String, registry: [String]) -> Bool {
        let p = normPath(path)
        return registry.contains { normPath($0) == p }
    }
    func loadRegistry() -> [String] {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: profile.custody)),
              let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
              let files = obj["files"] as? [String] else { return [] }
        return files
    }

    // nouchg -> O_NOFOLLOW open (NO O_TRUNC) -> validate the OPEN FD -> ftruncate -> write -> fsync -> checked uchg.
    // Round-3 fixes (codex CRITICAL + pentester HIGH): DO NOT O_TRUNC before validating — a redirect would
    // truncate the target before the fstat guard catches it, so we open without O_TRUNC and only ftruncate
    // AFTER every check passes. fstat asserts regular + st_nlink==1 + owner==the service account, FAIL-CLOSED
    // if the service-account lookup fails. Then F_GETPATH re-derives the ACTUALLY-OPENED path (fully
    // symlink-resolved) and re-runs the control/enrolled checks on it — this is what closes the
    // intermediate-directory-symlink redirect that O_NOFOLLOW (final-component only) cannot. `norm` is the
    // already-validated enrolled target.
    func uchgWrite(_ norm: String, _ content: Data, registry: [String]) throws {
        guard let serviceUID = getpwnam(profile.serviceAccount).map({ $0.pointee.pw_uid }) else {
            throw BrokerError.writeFailed("service account lookup failed — refusing (fail closed)")
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
                  st.st_nlink == 1, st.st_uid == serviceUID else {
                throw BrokerError.writeFailed("target is not a lone \(profile.serviceAccount)-owned regular file (nlink/owner)")
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
            guard real == norm, !isControlPath(real), Broker.isEnrolledTarget(real, registry: registry) else {
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

    /// Client-facing result for a write that has ALREADY landed durably. Status is `ok` either way —
    /// the write happened, and reporting failure would tell the client nothing changed when the
    /// target did (M1). A non-nil `auditError` means the record didn't make it into the log; that
    /// gap is surfaced explicitly rather than swallowed.
    static func writeResult(auditError: Error?) -> [String: Any] {
        var r: [String: Any] = ["phase": "result", "status": "ok"]
        if let e = auditError { r["audit_error"] = "write succeeded but audit append failed: \(e)" }
        return r
    }

    func handle(_ fd: Int32) throws {
        let caller = peerUID(fd)
        let req = try recvMsg(fd)
        switch req["op"] as? String {
        case "execute-write": try handleExecuteWrite(fd, req, caller)
        case "approve": try handleApprove(fd, req, caller)
        default:
            try sendMsg(fd, ["phase": "result", "status": "deny", "reason": "bad request"])
        }
    }

    // approve: best-effort verdict, no write. Challenges over the SAME canonicalJSON payload that
    // decideApprove built, verifies the signature against that SAME challenge, audits approve_ok — never
    // calls uchgWrite.
    func handleApprove(_ fd: Int32, _ req: [String: Any], _ caller: Int) throws {
        guard let (challengeB64, human, doc) = try? decideApprove(req, caller: caller) else {
            try sendMsg(fd, ["phase": "result", "status": "deny", "reason": "bad request"]); return
        }
        guard let challenge = Data(base64Encoded: challengeB64) else {
            try sendMsg(fd, ["phase": "result", "status": "deny", "reason": "bad request"]); return
        }
        try sendMsg(fd, ["phase": "challenge", "challenge_b64": challengeB64, "human_rendering": human])
        let reply = try recvMsg(fd)
        // Audit records WHAT was approved (tool + payload hash) so the log is a real forensic record of
        // the WYSIWYS ceremony — consistent shape on both approve_ok and deny. (Task-3 review Important.)
        guard reply["phase"] as? String == "signature",
              let sigB64 = reply["signature_b64"] as? String, let sig = Data(base64Encoded: sigB64),
              verifier.verify(challenge: challenge, signature: sig) else {
            try auditAppend(["event": "deny", "op": "approve", "tool": doc.path,
                             "content_sha256": doc.contentSha256, "caller": caller], path: profile.audit)
            try sendMsg(fd, ["phase": "result", "status": "deny", "reason": "no valid touch"]); return
        }
        try auditAppend(["event": "approve_ok", "op": "approve", "tool": doc.path,
                         "content_sha256": doc.contentSha256, "caller": caller], path: profile.audit)
        try sendMsg(fd, ["phase": "result", "status": "ok"])
    }

    func handleExecuteWrite(_ fd: Int32, _ req: [String: Any], _ caller: Int) throws {
        guard let path = req["path"] as? String,
              let b64 = req["content_b64"] as? String,
              let content = Data(base64Encoded: b64) else {
            try sendMsg(fd, ["phase": "result", "status": "deny", "reason": "bad request"]); return
        }
        let norm = Broker.normPath(path)    // /private-stripped; same string feeds the checks AND uchgWrite's open
        let reg = loadRegistry()
        if isControlPath(norm) || !Broker.isEnrolledTarget(norm, registry: reg) {
            try auditAppend(["event": "deny_target", "path": norm, "caller": caller], path: profile.audit)
            try sendMsg(fd, ["phase": "result", "status": "deny", "reason": "not an enrolled target"]); return
        }
        let nonce = (0..<16).map { _ in String(format: "%02x", UInt8.random(in: 0...255)) }.joined()
        let doc = buildSignedDocument(op: "execute-write", path: norm,
                                      contentSha256: sha256Hex(content),
                                      cwd: req["cwd"] as? String ?? "", nonceHex: nonce, callerUid: caller,
                                      contentMode: content.count > INLINE_MAX ? "digest" : "inline",
                                      ns: profile.namespace)
        let challenge = try canonicalBytes(doc)
        try sendMsg(fd, ["phase": "challenge", "challenge_b64": challenge.base64EncodedString(),
                         "human_rendering": humanRendering(doc, content: content)])
        let reply = try recvMsg(fd)
        guard reply["phase"] as? String == "signature",
              let sigB64 = reply["signature_b64"] as? String, let sig = Data(base64Encoded: sigB64),
              verifier.verify(challenge: challenge, signature: sig) else {
            try auditAppend(["event": "deny", "path": norm, "caller": caller], path: profile.audit)
            try sendMsg(fd, ["phase": "result", "status": "deny", "reason": "no valid touch"]); return
        }
        do { try uchgWrite(norm, content, registry: reg) }
        catch {
            try auditAppend(["event": "write_error", "path": norm, "caller": caller, "err": "\(error)"], path: profile.audit)
            try sendMsg(fd, ["phase": "result", "status": "deny", "reason": "write failed"]); return
        }
        // The write is DURABLE from here on. An auditAppend failure must NOT propagate as a thrown
        // error: handleGuarded would drop it, the client would see a spurious failure, and the log
        // would carry neither write_ok nor write_error for a change that really happened (M1). So
        // report success either way, and surface the audit gap explicitly instead of silently.
        var auditErr: Error?
        do {
            try auditAppend(["event": "write_ok", "path": norm, "caller": caller,
                             "content_sha256": doc.contentSha256], path: profile.audit)
        } catch {
            auditErr = error
        }
        try sendMsg(fd, Broker.writeResult(auditError: auditErr))
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
        // Absolute wall-clock cap: SO_RCVTIMEO is only a per-recv idle timeout and a slow-drip peer can reset
        // it forever, pinning a connection/thread indefinitely. A one-shot watchdog thread shutdown()s the
        // connection at start+deadline, which unblocks any pending recv and collapses this ceremony.
        var tv = timeval(tv_sec: 90, tv_usec: 0)   // belt: per-recv idle bound
        setsockopt(conn, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        let done = DispatchSemaphore(value: 0)
        Thread.detachNewThread {
            if done.wait(timeout: .now() + Broker.ceremonyDeadline) == .timedOut {
                shutdown(conn, SHUT_RDWR)   // absolute cap: force the blocked recv/handle to error out
            }
        }
        defer { done.signal() }
        // Ceremonies run CONCURRENTLY — no ceremony-wide lock (task3 DoS fix). Previously this flock wrapped
        // the whole ceremony INCLUDING the human-touch wait, so a slow client that grabbed it first starved
        // every other write for up to ceremonyDeadline. The only shared state needing serialization is the
        // audit hash-chain RMW, which auditAppend now guards with its own flock. Residual: same-path
        // concurrent uchgWrite can race, but stays fail-safe — service-account ownership (not the uchg
        // flag) is the write barrier, and the loser gets a spurious write_error with the target left
        // relocked. See docs/FOLLOWUPS.md.
        do { try handle(conn) } catch { /* malformed/aborted/deadline: drop */ }
    }
}

extension Broker {
    public func decideApprove(_ req: [String: Any], caller: Int) throws -> (challengeB64: String, human: String, doc: SignedDocument) {
        guard let tool = req["tool"] as? String else { throw WireError.badBody }
        let cwd = req["cwd"] as? String ?? ""
        let payload = try canonicalJSON(["tool": tool, "input": req["input"] ?? [:], "cwd": cwd])
        let doc = buildSignedDocument(op: "approve", path: tool, contentSha256: sha256Hex(payload),
                                      cwd: cwd,
                                      nonceHex: (0..<16).map { _ in String(format:"%02x", UInt8.random(in:0...255)) }.joined(),
                                      callerUid: caller, ns: profile.namespace)
        // humanRendering already prints "APPROVE <tool>" (doc.op/doc.path) — don't double it (round-2 cosmetic).
        let human = humanRendering(doc, content: payload)
        return (try canonicalBytes(doc).base64EncodedString(), human, doc)
    }
}
