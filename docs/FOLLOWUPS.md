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
- **Task6 review — directory-enrolled targets: uninstall vs. broker write-authorization scope
  mismatch.** `uninstall` unlocks registered dir paths (`registry.dirs`) via `clearImmutable`, but
  the broker's write-authorization (`Broker.loadRegistry()`) is files-only, exact-path match.
  Whether files written *inside* a registered dir end up individually `uchg`-locked in a way
  `clearImmutable(dirPath)` wouldn't reach is a pre-existing broker-architecture question, not
  addressed by the guided-install work.

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
- **Task7 — `task7_install.sh`/`task7_enroll.sh`/`task7_teardown.sh` retired**, replaced by the
  `cc-fido install`/`enroll`/`activate`/`uninstall` subcommands (and the `/cc-fido:install` guided
  skill). `task7_accept.sh` is retained as the deep USER-RUN acceptance test.

## Guided install (2026-07-18 branch — tracked from per-task + whole-branch review)
All ship-as-tracked; the whole-branch review verdict was **Ready to merge: Yes**. The live
`sudo cc-fido install → enroll → activate → uninstall` (sudo + a real touch) remains **USER-RUN** —
not yet exercised on hardware; drive it via the `/cc-fido:install` skill.
- **`status`'s `key_enrolled` now means "login user completed enrollment" (handle present), not
  "allowed_signers non-empty."** `gatherStatus` probes the login user's `~/.ccfido/gate_sk` handle
  (via `realLoginHome()`) because `status` runs unprivileged and can't read the `_ccfido`-owned 0600
  `allowed_signers` inside 0700 `/var/ccfido`. The handle is created *after* the registration succeeds,
  so it's a valid enrollment-complete sentinel; the security-critical `activate` gate still reads
  `allowed_signers` as root independently. If the handle and the trust store ever diverge (manual
  tampering), `status` could report `enrolled` without a registered signer — `activate` would still
  refuse. Consider a `sudo -u _ccfido test -s allowed_signers` cross-check if that matters.
- **`status` `policy_valid` = schema-valid only (`Policy.fromFile`), not `lint()`.** A policy with a
  blanket `allow_tier` grant reports `policy_valid:true` though `lint()` calls it fatal. `install`
  still lint-gates before writing, so a bad policy never installs via `cc-fido install`; this only
  affects the `status` display of an externally-planted policy.
- **`status` `degraded` rollup is a catch-all** binning semantically different partial states (e.g.
  account-only vs daemon-up-but-prereq-broken). The skill diagnoses from the raw JSON fields, so the
  rollup label is advisory.
- **`gatherStatus` FS-wiring only partially unit-tested.** The `key_enrolled`-from-`home` probe now has
  tests; `dirs`/`binary`/`policy_valid` read absolute system `Paths` and can't be exercised under
  `swift test` without path injection.
- **`activate` reachability probe is a fixed 1s `usleep`** then a socket check — a slow launchd
  bootstrap yields a false "NOT reachable (re-run activate)"; re-running is safe/idempotent. `activate`
  also shares `exit(1)` between key-refusal and activated-but-not-yet-reachable (the stderr message
  distinguishes them).
- **`install` — fail-closed `_ccfido` chown right after `dscl` account-create** can abort if
  opendirectoryd hasn't propagated the new account name yet; self-heals on an idempotent re-run.
- **`enroll` — `chmod 700`/`600` return values discarded** (best-effort hardening; `ssh-keygen`
  already writes the private key `0600`).
- **`uninstall` — `loginOwner` hardcodes group `:staff`** vs the retired shell's `id -gn`. Correct for
  a standard macOS account (primary group `staff`, gid 20); wrong for a non-standard primary group.
- **`/cc-fido:install` skill — the default-policy scope note is loosely worded** ("gates sensitive/home
  paths"): the default `allow_tier` is `__HOME__/**` (most of `$HOME` passes without a touch); only
  `sensitive_globs` (dotfiles/credentials/LaunchAgents) and non-home writes gate.

## cc-touch-id packaging/install (Task 10 review)
- **`installOrchestration`'s managed-hook binary is not profile-aware — `cc-touch-id install` writes
  the WRONG hook command.** `installOrchestration` (`Sources/CCGateCore/Install.swift:16`) calls
  `renderManagedSettings(hookCmd: profile.codeDir + "/" + profile.binaryName + " hook")` — i.e. the
  PLAIN binary path. That's correct for `cc-fido` (a plain signed CLI does everything, including the
  hook). For `cc-touch-id`, the hook process signs with the Secure Enclave key and needs the
  keychain-access-group entitlement that only the provisioned `.app` bundle carries
  (`Sources/CCTouchIDBackend/TouchIdConstants.swift touchIdAppBinary`) — the plain daemon binary is
  amfid-killed the moment the hook tries to use the key. The shipped install path works around this:
  `install/install.sh` finishes by calling `cc-touch-id _render-managed` directly (main.swift wires
  that internal subcommand to `touchIdAppBinary`, not `profile.codeDir/binaryName`), overwriting
  whatever `installOrchestration` wrote. Fail-closed (a broken hook just fails signing, doesn't bypass
  the gate) but broken if anyone runs `sudo cc-touch-id install` directly instead of going through
  `install/install.sh` — they'll get a managed-settings hook pointing at a binary that can never
  complete a Touch ID signature. Deferred / Pillar-C-adjacent proper fix: make the managed-hook binary
  profile-aware (e.g. a `hookBinaryPath` field on `GateProfile`, defaulting to
  `codeDir/binaryName` for `cc-fido` and to `touchIdAppBinary` for `cc-touch-id`) so the `install`
  subcommand alone is correct without the install.sh workaround.
- **Developer-ID notarized *distribution* — RESOLVED (2026-07-19).** `packaging/build-distribution.sh`
  now produces a notarized, stapled, Gatekeeper-clean `cc-touch-id.app` that runs on any Mac with
  `get-task-allow` absent (TID-5 intact). The blocker was real: a persistent Secure-Enclave key is a
  data-protection-keychain item that MUST land in an authorized keychain access group, and a bare
  Developer ID signature has none — asserting `keychain-access-groups` with no profile → amfid SIGKILL
  at launch (rc 137); asserting nothing → app launches but `SecKeyCreateRandomKey` → -34018
  `errSecMissingEntitlement`. Both confirmed empirically on macOS 26. **The fix:** a *Developer ID*
  provisioning profile grants `application-identifier` (= `HH3SJBAS42.com.seanperkins.cc-touch-id`),
  which is exactly the access group the SE key needs, and — unlike the Development profile — does NOT
  force `get-task-allow`. Xcode `archive` + `-exportArchive` with `method: developer-id`
  (`packaging/ExportOptions.plist`) + `-allowProvisioningUpdates` creates/embeds that profile, signs
  Developer ID + hardened runtime, and strips get-task-allow automatically (the App ID's Keychain
  Sharing capability + the Developer ID profile were minted by `-allowProvisioningUpdates`, no portal
  support request needed). `build-signed.sh` (author-machine build) is retained as the no-Developer-ID
  fallback; `CCTouchID.distribution.entitlements` remains for a direct-`codesign` path. Residual: an
  on-hardware `enroll` + a gated write under the freshly *installed* notarized app is the final
  end-to-end acceptance (the SE persist + biometric-sign primitives are already proven).
- **macOS 26: `stapler` and `spctl` are broken; distribution ships notarized-but-UN-stapled (accepted
  residual).** On the macOS 26 build machine, `xcrun stapler staple` fails with Error 73 ("could not
  remove existing ticket from …/Contents/CodeResources — No such file or directory") even though the
  notarization ticket downloads fine from Apple's CloudKit, and `spctl -a -t exec` returns "invalid API
  object reference". Both are local Gatekeeper-tooling regressions, not artifact problems —
  notarization is authoritative and confirmed via `notarytool` (Accepted), and `codesign --verify
  --strict` passes. Consequence: `build-distribution.sh` now treats stapling as **best-effort** (warns,
  continues) and the verify/`fetch-app.sh`/`publish-release.sh`/`touchid_notarize_accept.sh` paths gate
  on the **deterministic** checks (SHA-256 pin + `codesign --verify` + team + no `get-task-allow`) with
  `spctl`/`stapler` demoted to informational. A notarized-but-unstapled app passes Gatekeeper via the
  ONLINE check (needs network at first launch); it just lacks offline validation. To restore offline
  stapling: staple on a non-macOS-26 machine, or wrap the `.app` in a signed+notarized **DMG** and
  staple the DMG (different code path, likely dodges the bug).
- **`_presence-test` false-fails when run as the login user (harness gotcha, not a gate bug).**
  `cc-touch-id _presence-test` signs a nonce with the SE key (needs the login user's GUI/biometric
  session) and then verifies it via `TouchIdVerifier`, which READS `allowed_signers`. But `enroll`
  chowns `allowed_signers` to the service account (`/var/cctouchid/allowed_signers`, `-rw-------`
  `_cctouchid`), so the login user gets EACCES and the verify step reports "signature did not verify"
  even though the signature is valid. At runtime this is a non-issue — the **broker** (running as
  `_cctouchid`) is what verifies. So don't use `_presence-test` as a login-user acceptance step
  (removed from `touchid_notarize_accept.sh`); prove sign+verify via enroll's positive-control
  (verifies against the live-exported pubkey) and the on-disk path via `touchid_accept.sh`'s broker
  gated-write. A real fix would have `_presence-test` verify against the live SE export like
  `positiveControl` does, rather than reading the service-account-owned file.
- **`ns` domain-separator is defined but NOT wired into the broker's challenge (defense-in-depth,
  deferred).** SP2 added an optional `ns` field to `SignedDocument` (`Sources/CCGateCore/Canonical.swift`)
  so a Secure-Enclave signature — raw P-256 over `canonicalBytes`, with no external namespace like
  `ssh-keygen -n` — could carry a domain separator. But nothing sets it: `Broker` builds the challenge
  via `buildSignedDocument(...)` without passing `ns`, so it stays nil for BOTH cc-fido and cc-touch-id.
  Not a functional/security hole for the current setup — the per-op `nonce` already prevents replay, and
  the two products use different keys, verifiers, sockets, and service accounts (a cc-fido signature can
  never validate under cc-touch-id's verifier and vice-versa). To wire it: have `Broker` pass
  `ns: profile.namespace` (`"cc-touch-id-gate/v1"` / a cc-fido equivalent). NOTE: this changes the
  daemon's challenge bytes, so it needs a rebuild + reinstall + on-hardware re-validation of the gate.
- **`status.keyEnrolled` may under-report when run from the plain binary (Minor, final review).**
  `gatherStatus` sets `keyEnrolled = enroller.isEnrolled(home:)` → `seKeyExists(tag:)`, a keychain query.
  The SE key lives in access group `HH3SJBAS42.com.seanperkins.cc-touch-id`, which only the entitled
  `.app` binary belongs to. The install SKILL runs `status` from the plain `.build/release/cc-touch-id`,
  which isn't in that group and may not see the key → the rollup can show `prereqs-only` after a real
  enroll. Conservative (never OVER-reports enrollment), not security-relevant; misleads the guided flow.
  Fix: probe enrollment for status via the app binary, or (as root) via a non-empty `allowed_signers`
  check, rather than a keychain query from the plain binary.
- **denyNudge points at `cc-touch-id write`, which can't sign from the plain binary (Minor).**
  `denyNudgeMsg` (`HookLogic.swift`) emits ``Use `cc-touch-id write <path>` `` via `profile.binaryName`.
  For Touch ID, `write`→`seSign` needs the entitled `.app` binary; bare `cc-touch-id` on PATH (if any)
  would amfid-kill. Only reachable when a user populates `locked_paths` (shipped `policy.json` has it
  empty) and fails closed. Same family as the plain-binary-hook residual. Fix: nudge the app-binary path
  for the Touch ID profile.
