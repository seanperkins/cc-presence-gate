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

## Step 0 — Preflight + build the provisioned, notarized `.app`

Unlike `cc-fido` (a plain signed CLI), `cc-touch-id`'s hook/enroll/write roles touch a Secure Enclave
key, which requires a **provisioned, entitled `.app` bundle** — a bare CLI binary is killed by amfid
the moment it tries to create/use that key (see `task0-se/REPORT.md`). Building that `.app` needs
real Apple Developer credentials on the machine; there is no way around this step.

1. Establish `$REPO_ROOT` — a local clone of `cc-fido-gate` with `Package.swift` at its root (the
   plugin cache subtree alone is not enough — same reasoning as `cc-fido`'s install skill, see
   `docs/superpowers/spikes/2026-07-18-marketplace-clone-mechanics.md`). If the user already has one,
   use it; otherwise `! git clone <repo-url> ~/cc-fido-gate && REPO_ROOT=~/cc-fido-gate`.
2. Toolchain: `! xcode-select -p` (must print a path; if not, `xcode-select --install`).
3. Touch ID hardware + an enrolled fingerprint: `! bioutil -r` (or `bioutil -c` to check the
   fingerprint count). No Touch ID sensor, or zero fingerprints enrolled, means the whole plugin is a
   dead end on this Mac — stop and tell the user so before going further.
4. A Developer ID Application certificate for team `HH3SJBAS42`:
   `! security find-identity -v -p codesigning | grep "Developer ID Application.*HH3SJBAS42"`.
   If **absent**: this plugin cannot produce a distributable, notarized build on this machine. Offer
   the dev-signed fallback — a local, Apple-Development-signed build that works only on THIS Mac (no
   notarization, no `stapler staple`; skip straight to a plain `xcodebuild … -configuration Release`
   without the Developer-ID re-sign/notarize steps in `packaging/build-signed.sh`). Tell the user this
   fallback build cannot be copied to another machine or survive Gatekeeper quarantine re-checks the
   way the notarized build can.
5. A notarization credential: `! xcrun notarytool history --keychain-profile "cc-touch-id-notary"`
   (any output other than a credential/profile error confirms the profile is stored). If missing and
   the user has an App Store Connect API key or app-specific password, have them store one:
   `! xcrun notarytool store-credentials "cc-touch-id-notary" --apple-id <id> --team-id HH3SJBAS42 --password <app-specific-password>`.
   Without this, notarization in step 6 will fail — the dev-signed fallback is the only option.
6. Build: `! cd $REPO_ROOT && bash packaging/build-signed.sh` (Developer-ID path) — or, for the
   dev-signed fallback, walk the user through `packaging/project.yml` → `xcodegen generate` →
   `xcodebuild -project packaging/CCTouchIDGate.xcodeproj -scheme cc-touch-id -configuration Release -allowProvisioningUpdates build`
   by hand, skipping the re-sign/notarize/staple steps, and note the resulting `.app` is
   machine-local only.
7. Confirm the built `.app` path (printed at the end of `build-signed.sh`, or under
   `packaging/.dd/Build/Products/Release/cc-touch-id.app`) — you'll need it for Step 1.

## Always start by reading state
Ask the user to run `$REPO_ROOT/.build/release/cc-touch-id status --json` (or run it yourself if
unprivileged reads suffice) and parse the `rollup`. Branch:
- `clean` → Step 1 (install)
- `prereqs-only` → Step 2 (enroll)
- `enrolled` → Step 3 (activate)
- `active` → already installed; offer `status`, a smoke test, or `uninstall`
- `degraded` → diagnose which component is false in the JSON and repair (usually re-run install or
  activate)

## Step 1 — Prereqs + the signed app (one sudo prompt, no touch)
Tell the user: `! sudo APP=<path-to-the-.app-from-Step-0> POLICY=<path-or-default> bash $REPO_ROOT/install/install.sh`
(If they haven't authored a policy, note the default gates sensitive/home paths; the default lives at
`$REPO_ROOT/plugins/cc-touch-id/install/policy.json`.) The script builds the release binary, creates
the `_cctouchid` account, copies the plain daemon binary AND the signed `.app`, installs the policy,
and writes the LaunchDaemon plist + managed-settings — then stops with a "run enroll next" message
because no key is enrolled yet. Confirm `status` rollup is now `prereqs-only`.

## Step 2 — Enroll a key (Touch ID prompt; runs as the user)
Tell the user: `! $REPO_ROOT/.build/release/cc-touch-id enroll`. They'll see a Touch ID sheet — have
them touch the sensor. Confirm rollup is now `enrolled`.

## Step 3 — Activate the daemon (re-run install.sh; one sudo prompt)
Tell the user: `! sudo APP=<same-path> bash $REPO_ROOT/install/install.sh` again. Now that a key is
enrolled, the script proceeds past the circularity stop, bootstraps the LaunchDaemon, kickstarts a
fresh socket, and runs a non-destructive canary (the broker must deny a write to a control path).
Confirm `active`.

## Verify
`$REPO_ROOT/.build/release/cc-touch-id status` should read `active`. There is no `cc-touch-id`
equivalent of `scripts/userrun/task7_accept.sh` yet — deep hardware acceptance is Task 11
(`scripts/userrun/touchid_accept.sh`).

## Repair / Uninstall
- Broker unreachable / stale socket → `! sudo $REPO_ROOT/.build/release/cc-touch-id activate`.
- Full reset → `! sudo $REPO_ROOT/.build/release/cc-touch-id uninstall` → confirm `status` = `clean`.
  (This does NOT restore a previously-overwritten cc-fido managed-settings hook — if the user wants
  cc-fido back, they need to re-run `sudo cc-fido install` afterward.)

Never run a `sudo` command yourself — always hand it to the user. After each step, re-read `status`
before advancing; every subcommand is idempotent, so resuming after an interruption is safe.
