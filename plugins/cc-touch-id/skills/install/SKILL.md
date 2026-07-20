---
name: install
description: Guided install/enroll/activate (and repair/uninstall) of cc-touch-id-gate. Use when the user wants to install, set up, activate, check, repair, or remove cc-touch-id-gate — it drives the privileged cc-touch-id subcommands, prompting the user for sudo/Touch ID at each step.
---

# Guided cc-touch-id-gate install

You orchestrate the `cc-touch-id` subcommands. You CANNOT type the user's sudo password or place
their finger on the sensor — you are a guide: tell the user the ONE command to run next, have them
run it in their terminal (with the `! ` prefix, so sudo can prompt and the Touch ID sheet can appear),
read the output, and advance.

> **cc-touch-id and cc-fido do NOT coexist yet.** Both plugins install a `PreToolUse` hook by writing
> the SAME file, `/Library/Application Support/ClaudeCode/managed-settings.json`. Installing one
> **overwrites** the other's managed hook wholesale — there is no merge, and no warning at install
> time. (The design's Pillar C — a coexistence/merge story for multiple gates — is explicitly
> deferred; see `docs/superpowers/specs/2026-07-18-cc-presence-gate-sp2-touch-id-design.md`.) If the
> user already has cc-fido installed and active, tell them plainly: installing cc-touch-id now will
> silently replace the FIDO hook with the Touch ID hook, and vice versa. Confirm they want that
> before proceeding — do not install both and assume they'll layer.

## Step 0 — Preflight + obtain the provisioned, entitled `.app`

Unlike `cc-fido` (a plain signed CLI), `cc-touch-id`'s hook/enroll/write roles touch a Secure Enclave
key, which requires a **provisioned, entitled `.app` bundle** — a bare CLI binary is killed by amfid
the moment it tries to create/use that key (see `task0-se/REPORT.md`). You either **download** the
maintainer's prebuilt notarized `.app` or **build** one yourself; the rest of the install is identical.

**Preflight (all paths):**
1. Establish `$REPO_ROOT` — a local clone with `Package.swift` at its root (the plugin cache subtree
   alone is not enough — see `docs/superpowers/spikes/2026-07-18-marketplace-clone-mechanics.md`). If
   the user has one, use it; otherwise `! git clone <repo-url> ~/cc-presence-gate && REPO_ROOT=~/cc-presence-gate`.
2. Touch ID hardware + an enrolled fingerprint: `! bioutil -r` (or `bioutil -c`). No sensor / zero
   fingerprints ⇒ the plugin is a dead end on this Mac — stop and say so before going further.

**Then pick the path** — check whether the user has a Developer ID identity:
`! security find-identity -v -p codesigning | grep "Developer ID Application"`.

### Path A — download the maintainer's prebuilt notarized `.app` (no Apple account needed)
Best for users without their own Developer ID. Fetches the pinned release and verifies it (SHA-256 pin
+ notarization + team + no `get-task-allow` + stapled) before use:
```
! APP="$(bash $REPO_ROOT/install/fetch-app.sh)" && echo "verified app: $APP"
```
If it reports **no published release pinned yet**, there is no prebuilt binary available — the user
must either self-build (Path B) or wait for a release. Do not fabricate a download.

### Path B — self-build with your own Developer ID (higher trust: you compiled + signed it)
Best for users with an Apple Developer account. Two sub-options:
- **Proper notarized build** (`! cd $REPO_ROOT && bash packaging/build-distribution.sh`): archive →
  export `developer-id` → notarize → staple. Uses team `HH3SJBAS42` by default; a self-builder with a
  DIFFERENT team must first retarget `DEVELOPMENT_TEAM`/`teamID` in `packaging/project.yml` +
  `packaging/ExportOptions.plist` (and the `com.seanperkins.cc-touch-id` bundle id, since an explicit
  App ID is team-unique) and store a `cc-touch-id-notary` notarytool credential. Output:
  `packaging/.dd/export/cc-touch-id.app`.
- **Quick this-Mac dev build** (`! cd $REPO_ROOT && bash packaging/build-signed.sh`): author-machine
  build (Development profile, carries `get-task-allow`, **not** notarized). Works only on the signing
  Mac and cannot be redistributed — fine for local use. Output under `packaging/.dd/Build/Products/Release/`.

When self-building with a non-`HH3SJBAS42` team, pass `EXPECTED_TEAM=<your-team>` to `install.sh` in
Step 1 (its default team check is `HH3SJBAS42`).

**Confirm the `.app` path** (the `APP=` value for Step 1): Path A prints it; Path B leaves it at the
path noted above.

## Always start by reading state
Ask the user to run `status --json` and parse the `rollup`. **Which binary you run it from matters
once a key is enrolled:** `key_enrolled` comes from a keychain query for the Secure Enclave key, and
that key lives in an access group only the entitled `.app` belongs to. The plain
`.build/release/cc-touch-id` is not in that group, so it reports `key_enrolled:false` even when a key
is genuinely enrolled — confirmed on a working install, where the same machine reported
`key_enrolled:true` from the `.app` and `false` from the plain binary at the same moment. Depending on
what else is true, that either drags the rollup down to `prereqs-only` (looping you back into
re-enrolling a key that already exists) or leaves it `active` with a contradictory `key_enrolled:false`.

- **Before Step 1 (nothing installed yet):** `$REPO_ROOT/.build/release/cc-touch-id status --json` —
  the app isn't in place yet and there's no key to miss.
- **After Step 2 (a key exists):** prefer
  `/opt/cc-touch-id-gate/cc-touch-id.app/Contents/MacOS/cc-touch-id status --json`.

If the two disagree on `key_enrolled`, believe the `.app`. The error is always conservative (it
under-reports, never claims an enrollment that didn't happen), so a `prereqs-only` rollup from the
plain binary right after a clean enroll means you're reading it from the wrong binary — not that the
enroll failed. Branch:
- `clean` → Step 1 (install)
- `prereqs-only` → Step 2 (enroll)
- `enrolled` → Step 3 (activate)
- `active` → already installed; offer `status`, a smoke test, or `uninstall`
- `degraded` → diagnose which component is false in the JSON and repair (usually re-run install or
  activate)

The install/enroll/activate sequence has a strict order, because two DIFFERENT binaries are involved
and only one of them carries the Secure Enclave entitlement:

1. Build the entitled `.app` (Step 0 above, `packaging/build-signed.sh`) — login user.
2. Build the plain daemon binary — login user: `! cd $REPO_ROOT && swift build -c release`. (The
   daemon only verifies signatures; it never touches the Secure Enclave, so it can stay ad-hoc-signed.)
3. Run `install/install.sh` under `sudo` (Step 1 below) — privileged. It places BOTH binaries under
   `/opt/cc-touch-id-gate`, creates dirs/account, installs the policy, writes the LaunchDaemon plist
   pointing at the plain binary, and writes managed-settings pointing at the `.app` binary.
4. Enroll (Step 2 below) using the INSTALLED, ENTITLED `.app` binary — login user, NOT sudo, needs a
   touch.
5. Activate (Step 3 below) — `sudo cc-touch-id activate` (or re-run `install.sh`) — privileged.

## Step 1 — Prereqs + the signed app (one sudo prompt, no touch)
Before running the installer, make sure BOTH binaries exist as the login user (NOT root — building as
root under `sudo` would leave a root-owned `.build/` that breaks future unprivileged builds):
`! cd $REPO_ROOT && swift build -c release` (plain daemon binary; the entitled `.app` was already
built in Step 0).

Then tell the user: `! sudo APP=<path-to-the-.app-from-Step-0> POLICY=<path-or-default> bash $REPO_ROOT/install/install.sh`
(If they haven't authored a policy, note the default gates sensitive/home paths; the default lives at
`$REPO_ROOT/plugins/cc-touch-id/install/policy.json`.) The script (run via `sudo`, so it must be run
from the user's own login shell — see install.sh's `SUDO_USER` requirement) creates the `_cctouchid`
account, copies the ALREADY-BUILT plain daemon binary AND the signed `.app` into place, installs the
policy (keyed off the login user's home, not root's), and writes the LaunchDaemon plist + managed-
settings — then stops with a "run enroll next" message because no key is enrolled yet. Confirm
`status` rollup is now `prereqs-only`.

## Step 2 — Enroll a key (Touch ID prompt; runs as the user, NOT sudo)
Tell the user: `! /opt/cc-touch-id-gate/cc-touch-id.app/Contents/MacOS/cc-touch-id enroll` — run as the
plain login user, no `sudo`. This is the INSTALLED, ENTITLED app binary (`touchIdAppBinary`), not the
plain SwiftPM build under `.build/release/` — the Secure Enclave key-creation call
(`SecKeyCreateRandomKey`) needs the keychain-access-group entitlement that only this binary carries;
the plain `.build/release/cc-touch-id` binary is amfid-killed the moment it tries. It must also run as
the login user (not root/sudo) because the SE key lands in the login user's keychain. They'll see a
Touch ID sheet — have them touch the sensor. Confirm rollup is now `enrolled`.

> **Sudo caveat — have them authenticate sudo FIRST.** Enroll self-escalates via `sudo` for the
> pubkey-registration step, and that mid-run `sudo` password prompt is **unreliable** when enroll is
> triggered standalone or through the `!` runner (no controlling TTY — the prompt shows but won't accept
> the password). Have the user run **`sudo -v` in their real terminal**, then run enroll; the cached
> credential means the registration step won't re-prompt. (Running enroll immediately after Step 1's
> `install.sh` also works — that already cached sudo.) Note the split: `enroll` must be the login user
> (refuses `sudo`), but the **privileged-only** commands — `enroll-file`, `enroll-dir`, `uninstall` —
> can be run **directly under `sudo`** (e.g. `sudo cc-touch-id enroll-file ~/.env`), no prompt needed.

## Step 3 — Activate the daemon (re-run install.sh; one sudo prompt)
Tell the user: `! sudo APP=<same-path> bash $REPO_ROOT/install/install.sh` again. Now that a key is
enrolled, the script proceeds past the circularity stop, bootstraps the LaunchDaemon, kickstarts a
fresh socket, and runs a non-destructive canary (the broker must deny a write to a control path).
Confirm `active`.

## Step 4 — Restart Claude Code (REQUIRED — the gate loads at startup)
The `PreToolUse` hook lives in managed-settings, which Claude Code reads **only at startup**. A Claude
Code session that was already running when you installed is **NOT gated** — its tool calls bypass the
hook entirely (an agent in that session can still write `.env` etc.). Tell the user to **quit and
reopen Claude Code** (or start a fresh session) before relying on the gate. Confirm by, in the new
session, having the agent attempt a gated action (e.g. a Write to a `.env`) and seeing it prompt for
Touch ID / get denied.

## Verify
`/opt/cc-touch-id-gate/cc-touch-id.app/Contents/MacOS/cc-touch-id status` should read `active` (use
the `.app`, not the plain binary — see the `key_enrolled` note above). The full hardware gate acceptance
is `scripts/userrun/touchid_accept.sh` (needs sudo + touches); `scripts/userrun/touchid_notarize_accept.sh`
checks the installed app is the notarized distribution build.

## Repair / Uninstall
- Broker unreachable / stale socket → `! sudo $REPO_ROOT/.build/release/cc-touch-id activate`.
- Full reset → `! sudo $REPO_ROOT/.build/release/cc-touch-id uninstall` → confirm `status` = `clean`.
  (This does NOT restore a previously-overwritten cc-fido managed-settings hook — if the user wants
  cc-fido back, they need to re-run `sudo cc-fido install` afterward.)

Never run a `sudo` command yourself — always hand it to the user. After each step, re-read `status`
before advancing; every subcommand is idempotent, so resuming after an interruption is safe.
