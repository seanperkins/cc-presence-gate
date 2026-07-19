import Foundation
import Darwin
import CCGateCore

/// Softened WYSIWYS + touch-to-approve, run CONCURRENTLY: the dialog shows what's being signed AND the
/// key is armed at the same time, so any of { touch, Enter, click Approve } approves from the get-go, and
/// { Cancel, walk away (dialog gives up after 60s) } denies. Returns the signature on approval, nil otherwise.
/// The physical touch remains the real gate — the daemon still verifies a challenge-bound signature; this is
/// pure client UX. Both rendering and the dialog title (`displayName`) are passed as AppleScript argv
/// items, never interpolated into -e — a `"` in either could otherwise break out of the script text.
public struct FidoCeremony: GateCeremony {
    let signer: Signer
    public init(signer: Signer) { self.signer = signer }
    public func confirmAndSign(rendering humanRendering: String, challenge: Data, displayName: String) -> Data? {
        let dlg = Process(); dlg.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        dlg.arguments = ["-l", "AppleScript",
            "-e", "on run argv",
            "-e", "display dialog (item 1 of argv) buttons {\"Cancel\", \"Approve\"} default button \"Approve\" with title (item 2 of argv) giving up after 60",
            "-e", "end run",
            humanRendering, displayName]
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
}
