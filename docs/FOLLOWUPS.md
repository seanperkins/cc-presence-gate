# cc-fido-gate v2 — tracked follow-ups

Non-blocking issues surfaced during subagent-driven implementation + the whole-branch merge-gate
review (all reviewers agreed: **none block merge**; the C-1/C-3 hard guarantee holds end-to-end and
was hardware-verified). Fixed inline before merge: audit EINTR retry (M2), hook matcher +MultiEdit/
NotebookEdit (M3), plus the per-task review fixes already committed. The below ship as tracked issues.

## Highest value (real user-facing consequences)
- **Task7 #1 — partial-enroll leaves a broken state.** `enrollSteps` (`Sources/cc-fido/main.swift`)
  `exit(1)`s the moment any step of `planEnrollFile` (chown→chmod→chflags) fails. If chown succeeds
  but chmod fails, the file is re-owned to `_ccfido`, not locked, not registered, and NOT rolled back.
  Fix: track plan progress and roll back on partial failure (the registry-add-failure path already
  has `rollbackFileLock`).
- **Task7 #4 — `enroll-file` follows symlinks inconsistently.** `lstat` captures the *symlink's* uid
  but `chown`/`chmod`/`chflags` follow to the target. An agent could plant a symlink and induce the
  admin to enroll it, chowning/locking the target; rollback would restore the wrong uid. Does NOT
  break C-1/C-3 (no agent write to a trust anchor). Fix: reject or `-h`/O_NOFOLLOW-resolve `path`
  consistently before use.

## Audit completeness
- **M1 — a successful privileged write can complete with no audit record.** `Broker.uchgWrite`
  writes+relocks, *then* `auditAppend("write_ok")`; if the append throws, `handle` throws and
  `handleGuarded` drops it — durable write logged as neither ok nor error, client sees spurious
  failure. Not a security bypass (touch verified). M2 (EINTR retry, fixed) removes the likely trigger.
  Consider audit-before-relock or a write-happened sentinel.
- **Task6 — hook-level denials leave no audit entry** (broker-side denials log `deny_target`/`deny`).
  An operator can't see *why* a tool was blocked at the hook tier.

## Hardening / latent
- **Task3 — same-path concurrent `uchgWrite` can race** (introduced when the ceremony-wide flock was
  narrowed to the audit chain so ceremonies run concurrently — the task3 slow-loris DoS fix; see
  `Broker.handleGuarded` + `auditAppend`). Two *separately-touched* ceremonies writing the SAME enrolled
  target can interleave `chflags`/write/relock. Fail-safe: `_ccfido` ownership (not the `uchg` flag) is the
  real write barrier, so no agent-writable window opens; the loser gets a spurious `write_error` and the
  target is always left relocked. Only the audit chain's RMW is serialized (its own flock). Fix if ever
  needed: a per-path write lock around `uchgWrite`. Pathological for a single-user tool.
- **Task5 — `Policy.init` is `public` + `try!`-on-regex.** Safe today (only `fromDict`/tests reach it;
  untrusted input validates first). Landmine if future code builds `Policy` from raw strings. Fix:
  make the non-throwing init `internal`.
- **Task6 — `FileHandle.write(Data)` can raise an uncatchable `NSException` on EPIPE** → crash instead
  of fail-closed (pre-existing house style, also in `main.swift`). SIGPIPE is ignored so this is
  theoretical on the hook path. Fix: `write(contentsOf:)` + `try?`, or raw `write(2)`.
- **Task4 — `custody.json` read-modify-write is not locked.** Concurrent `enroll-*` could drop an
  entry (last-writer-wins on the whole file). Low risk: enrollment is serial admin. Fix: flock the
  registry file across the RMW.

## Operational (hardware-verified 2026-07-17)
- **launchd broker needs a `kickstart` if a stale socket is present.** After prior *manual* daemon runs
  (`sudo -u _ccfido cc-fido daemon &`, as in task3/4/6), the LaunchDaemon-started broker can bind while an
  orphaned socket file shadows it — clients then get `cc-fido: broker unreachable` even though the daemon is
  up (`runs=1`, holds the socket via lsof). `sudo launchctl kickstart -k system/com.cc-fido-gate.brokerd`
  re-binds a fresh socket and fixes it. A clean install with no manual-daemon churn is unaffected.
  RESOLVED in `task7_install.sh`: install now does `bootout || true → bootstrap → kickstart -k` so it
  self-heals a stale socket and is re-runnable. (Latent alternative if it ever recurs: `serve()` refusing
  to start when another daemon already holds the socket.)

## Minor / cosmetic
- **Client — Cancel now hard-kills a live signer** (introduced by the touch-from-the-get-go ceremony,
  `confirmAndSign`). Because the key is armed concurrently with the dialog, clicking Cancel `terminate()`s a
  running `ssh-keygen` mid-FIDO-op. Per the task0-broker findings that *can* leave the device transiently
  `device not found` for the next arm; `sign()`'s existing retry (3× / 1.5s→3s backoff) would re-arm and
  recover. NOT observed in practice yet — theoretical, flagged because the concurrent design is a new trigger
  for that known transient. Fix only if it ever surfaces: a short settle delay or a gentler signer teardown.
- **Task2 — binary content ≤ INLINE_MAX signs `content_mode:"inline"`** though the dialog body shows
  `[binary, N bytes]`. Injectivity holds (op/path/cwd/content_sha256 are separate signed fields; the
  dialog tail shows the full sha256). design.md's "path+cwd+op disambiguator" is satisfied structurally.
- **Task3 — nonce one-liner + `cwd` double-read duplicated** in `handleExecuteWrite`/`decideApprove`;
  extract a `randomNonceHex()`.
- **Task7 #6 — unparseable octal mode silently → `0600`** (no warning). **#8 — `negativeBlinkTest`
  can't distinguish spawn-fail from signed-without-touch** (both → false). **#9 — `ccfidoUIDOr`
  duplicates the `getpwnam` lookup** already in `Broker`.
- **Task5 — `install/policy.json` bash_advisory regexes are broad** (e.g. bare `deploy`) — the safe
  (over-gate) direction; eyeball when tuning.

## Configurable install policy (2026-07-17 branch — tracked from final review)
- **CLI-level executable tests missing (Important).** The spec's §Testing "CLI-level executable test
  (stdout/stderr/exit)" for `_validate-policy`/`_render-policy` was downgraded to a manual smoke test
  during implementation. The security-critical emit-on-valid-only / exit-1-no-stdout contract
  (`Sources/cc-fido/main.swift` `_render-policy` case) has no automated coverage — only the USER-RUN
  `task7_accept.sh` sections 6-7 and the install script's `sudo test -s` belt. Add a test that spawns
  the built `cc-fido` and asserts exit code + empty-stdout for a blanket/bad policy and non-empty-stdout
  for a valid one.
- **Two untested guard branches (Minor).** `renderPolicy`'s non-absolute-but-nonempty `$HOME` rejection
  and its exists-but-invalid-JSON source rejection are verified correct by reading but have no test
  (existing tests hit banned/empty home + missing file only).
- **task6_hook.sh set -e fragility (Minor, latent).** Under `set -eu -o pipefail`, a non-zero
  `claude -p` would abort before the `[ -f "$D/.env" ] && … || echo note` reporting line. In practice
  `claude -p` returns 0 even on a hook denial, so latent; it's a USER-RUN test harness.
