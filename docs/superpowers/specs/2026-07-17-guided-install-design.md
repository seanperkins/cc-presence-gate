# cc-fido-gate — guided install (design)

**Date:** 2026-07-17
**Status:** approved (brainstorming); pending implementation plan
**Scope:** replace the install→enroll→install circularity and the test-harness `task7_*.sh` scripts with
clean, idempotent `cc-fido` subcommands behind a `Platform` seam, and a Claude-guided `/cc-fido:install`
skill that sequences them into one experience. Sets the portability foundation for a future Linux port.

Out of scope (separate specs): the config-authoring skill (`/cc-fido:policy`); a full Linux `Platform`
implementation (this spec only establishes the seam with a macOS impl).

## Problem

A from-scratch install today is `task7_install.sh` → `task7_enroll.sh` → `task7_install.sh` again — two
runs of a test-harness script with a canary and a manual circularity stop, plus a separate enroll and a
separate teardown. It's clunky, macOS-detail is smeared across bash, and there's no machine-readable state.
The tool is meant to become a Claude Code **plugin**, so install should be a guided, single experience.

## Decisions (from brainstorming)

- **Clean primitives, not a thin guide:** the privileged logic moves into idempotent `cc-fido` subcommands.
- **Primitives in Swift** (the binary), consolidating the existing `runPrivileged` logic; retire the
  `task7_install/enroll/teardown.sh` scripts. `task7_accept.sh` stays as the deep acceptance test.
- **Claude guides the flow:** a `/cc-fido:install` skill drives the subcommands, hiding the sequence and
  applying the recovery we learned (stale-socket `kickstart`, key-swap gotchas, broker-unreachable → activate).
- **`Platform` seam:** every OS-specific primitive sits behind a protocol so a future Linux port is
  "fill in the impls," not a rewrite. Swift is cross-platform; the macOS *primitives* (uchg/launchd/dscl/
  LOCAL_PEERCRED/osascript) are the real OS coupling, and the seam isolates them.
- **One root process per privileged command:** `sudo cc-fido install|activate|uninstall` each do ALL their
  privileged work in a single root process (one password prompt), not many internal `sudo` shell-outs.
  Claude never types the password — the skill hands the user the `sudo cc-fido …` line and reads back status.

## Design

### 1. `Platform` seam (`Sources/CCFidoCore/Platform.swift`)
A protocol isolating install-time OS-specific operations, with a `MacOSPlatform` implementation now:
```
public protocol Platform {
    func createServiceAccount(name: String) throws          // dscl  → Linux: useradd
    func deleteServiceAccount(name: String) throws
    func installDaemon(plistOrUnit: String) throws          // launchctl bootstrap → Linux: systemctl
    func activateDaemon() throws                             // bootout||true → bootstrap → kickstart -k
    func bootoutDaemon() throws
    func daemonState() -> (loaded: Bool, running: Bool, pid: Int?)
    func installManagedSettings(_ json: String) throws       // macOS managed-settings path
    func removeManagedSettings() throws
    func makeImmutable(_ path: String) throws                // chflags uchg → Linux: chattr +i
    func clearImmutable(_ path: String) throws
}
```
This spec provides `MacOSPlatform` only, `#if os(macOS)`; a `LinuxPlatform` is a future spec. The RUNTIME
OS primitives already in the code (`Broker.uchgWrite`'s `chflags`, `peerUID`'s `LOCAL_PEERCRED`, the
osascript dialog) are noted for migration behind the same seam later — not moved in this spec (keeps it
install-scoped), but the seam is designed to accommodate them.

### 2. Subcommands (replace `task7_install/enroll/teardown.sh`)
All idempotent and re-runnable. Privileged ones (`install`/`activate`/`uninstall`) expect to run **as root**
(the user invokes `sudo cc-fido …`); `status`/`enroll` run as the login user.

- **`cc-fido status [--json]`** — read-only state contract (no mutation, no sudo needed for the read paths;
  where a check needs root, it reports `unknown` rather than prompting). Reports, per component:
  `account` (present, uid), `dirs` (`/opt/cc-fido-gate`, `/var/ccfido`, `/var/ccfido-run` + expected perms),
  `binary` (installed, codesigned, version), `policy` (installed, validates, counts, no `__HOME__`),
  `key` (enrolled: handle present, in `allowed_signers`), `daemon` (loaded, running, **socket reachable**),
  `managed_settings` (present). Human table by default; `--json` emits a stable schema the skill parses.
  Overall rollup: `clean | prereqs-only | enrolled | active | degraded`.
- **`sudo cc-fido install [--policy PATH]`** — idempotent prereqs in one root process: create account (via
  `Platform`), make dirs with perms, copy+codesign the binary into `/opt/cc-fido-gate`, render+validate+
  install the policy (reuse `_render-policy` logic; `--policy` overrides the default template), write the
  plist + managed-settings. Does NOT start the daemon.
- **`cc-fido enroll [--keys N]`** — runs as the user: generate the sk gate key(s) (touch), register public
  key(s) in `allowed_signers` (a single escalation for that root-owned write), symlink the handle
  (private + `.pub`), blink-test. `N` defaults to 1; backup keys enrolled one at a time.
- **`sudo cc-fido activate`** — `Platform.activateDaemon()` (bootout||true → bootstrap → kickstart -k);
  requires an enrolled key (fail with a clear message if none). Self-heals a stale socket.
- **`sudo cc-fido uninstall`** — teardown in one root process: bootout+remove daemon, remove managed-settings,
  unlock+restore every enrolled target (from the registry), remove the install tree/state/account, remove
  key material. Idempotent; ends by printing a clean `status`.

`usage()` gains these; the `_render-plist`/`_render-managed`/`_registry-add`/`_render-policy`/`_validate-policy`
helpers stay as internal building blocks the new subcommands call.

### 3. The `/cc-fido:install` skill (plugin-guided experience)
A Claude Code skill that drives the subcommands interactively. Because Claude can't sudo or touch, it is a
guide: it reads `cc-fido status --json`, tells the user the single next command to run, reads the result,
and advances. Flow:
1. `cc-fido status --json` → branch on the rollup.
2. Policy: if none configured, note the default and `--policy`; once the config skill exists, offer to run it.
3. `sudo cc-fido install [--policy …]` → verify via status (`prereqs-only`).
4. `cc-fido enroll` → "touch your key when it blinks" (×N); verify (`enrolled`).
5. `sudo cc-fido activate` → verify socket reachable (`active`); if unreachable, re-run activate (kickstart).
6. Final `status` → GREEN summary; optional broker-write smoke test.
Recovery baked in: stale socket → re-activate; key-swap `invalid format` → guidance; partial state → resume
from the rollup (the skill is restart-safe because every subcommand is idempotent and `status` is authoritative).

### 4. Policy hookup
`install` uses the default template or `--policy PATH`. No hard dependency on the config-authoring skill; the
install skill offers to invoke it once it exists.

## Components / boundaries
- `Platform.swift` — the OS seam (macOS impl now). One responsibility: OS-specific privileged primitives.
- Subcommand cases in `main.swift` — thin dispatch → orchestration functions in `CCFidoCore` (testable).
- `CCFidoCore` install-orchestration (`Install.swift`): pure plan/idempotency/status logic, delegating OS
  ops to `Platform`; unit-testable without touching the real system.
- The skill (`.md` in the plugin) — orchestration + guidance, no privileged logic of its own.

## Testing / success criteria
- Unit: `status` JSON schema + rollup computation from injected component states; each subcommand's plan/
  idempotency logic against a **mock `Platform`** (assert the right ops in the right order, re-run is a no-op,
  `activate` refuses with no key). No real sudo in unit tests.
- USER-RUN integration: the skill drives a real from-scratch install→enroll→activate→verify→uninstall on
  hardware (replacing today's manual task7 sequence); `task7_accept.sh` still runs as the deep acceptance.
- Success: a new machine goes clean → active in one guided skill session with one password prompt per
  privileged step and the enroll touches; `status` reports `active`; `uninstall` returns to `clean`.

## Out of scope (future specs)
- Config-authoring skill (`/cc-fido:policy`) — the next spec; produces the `--policy` file.
- `LinuxPlatform` implementation + migrating the runtime primitives (uchgWrite/peerUID/dialog) behind the seam.
- Plugin packaging (manifest bundling the binary + skills + commands).
