---
name: install
description: Guided install/enroll/activate (and repair/uninstall) of cc-fido-gate. Use when the user wants to install, set up, activate, check, repair, or remove cc-fido-gate — it drives the privileged cc-fido subcommands, prompting the user for sudo/touch at each step.
---

# Guided cc-fido-gate install

You orchestrate the `cc-fido` subcommands. You CANNOT type the user's sudo password or touch their key —
you are a guide: tell the user the ONE command to run next, have them run it in their terminal (with the
`! ` prefix, so sudo can prompt and the key can blink), read the output, and advance.

## Step 0 — Build the binary (the plugin cache doesn't ship the Swift package)

This skill's plugin cache (`${CLAUDE_PLUGIN_ROOT}`) contains only the `plugins/cc-fido/` subtree —
the repo root `Package.swift` is **not** reachable from it (confirmed by the Task-1 spike,
`docs/superpowers/spikes/2026-07-18-marketplace-clone-mechanics.md`). So before anything else,
establish a built binary from a real clone of the repo:

1. Preflight the toolchain — have the user run `! xcode-select -p` (must print a path; if not,
   `xcode-select --install`) and confirm Homebrew OpenSSH is present at the arch-correct prefix:
   `/opt/homebrew/opt/openssh` on Apple Silicon, `/usr/local/opt/openssh` on Intel (`brew install
   openssh` if missing — stock `ssh-keygen` has no FIDO signing provider).
2. Establish `$REPO_ROOT` — a local clone of `cc-fido-gate` that has `Package.swift` at its root.
   If the user already has one, use it. Otherwise have them clone it to a known directory, e.g.
   `! git clone <repo-url> ~/cc-fido-gate && REPO_ROOT=~/cc-fido-gate`. (You may opportunistically
   check `known_marketplaces.json` for an `installLocation` from adding this marketplace and reuse
   it if present, but never depend on it — the plugin cache subtree alone is not enough.)
3. Build: `! cd $REPO_ROOT && swift build -c release`. The binary is `$REPO_ROOT/.build/release/cc-fido`.
4. Use `$REPO_ROOT/.build/release/cc-fido` for every command below, and point `--policy` at
   `$REPO_ROOT/plugins/cc-fido/install/policy.json`. `scripts/userrun/task7_accept.sh` (used in
   Verify) is also `$REPO_ROOT`-relative.

## Always start by reading state
Ask the user to run `$REPO_ROOT/.build/release/cc-fido status --json` (or run it yourself if unprivileged
reads suffice) and parse the `rollup`. Branch:
- `clean` → Step 1 (install)
- `prereqs-only` → Step 2 (enroll)
- `enrolled` → Step 3 (activate)
- `active` → already installed; offer `status`, a smoke test, or `uninstall`
- `degraded` → diagnose which component is false in the JSON and repair (usually re-run install or activate)

## Step 1 — Prereqs (0 touches; one sudo prompt)
Tell the user: `! sudo $REPO_ROOT/.build/release/cc-fido install --policy <path-to-their-policy-or-$REPO_ROOT/plugins/cc-fido/install/policy.json>`
(If they haven't authored a policy, note the default gates sensitive/home paths; a `/cc-fido:policy`
skill can build one.) Confirm `status` rollup is now `prereqs-only`.

## Step 2 — Enroll a key (touch; runs as the user)
Tell the user: `! $REPO_ROOT/.build/release/cc-fido enroll`  (add `--keys 2` if they want a backup, enrolled one at a time).
Tell them to TOUCH the key when it blinks. If they see `invalid format` swapping two keys, that's the
authenticator not settling — retry with the intended key plugged in. Confirm rollup is now `enrolled`.

## Step 3 — Activate the daemon (one sudo prompt)
Tell the user: `! sudo $REPO_ROOT/.build/release/cc-fido activate`. It prints whether the socket is reachable. If NOT reachable,
have them run it again (it re-kickstarts a fresh socket — the known stale-socket fix). Confirm `active`.

## Verify
`$REPO_ROOT/.build/release/cc-fido status` should read `active`. Optionally have them prove the gate
end-to-end via `$REPO_ROOT/scripts/userrun/task7_accept.sh` (needs a touch).

## Repair / Uninstall
- Broker unreachable / stale socket → `! sudo $REPO_ROOT/.build/release/cc-fido activate`.
- Full reset → `! sudo $REPO_ROOT/.build/release/cc-fido uninstall` → confirm `status` = `clean`.

Never run a `sudo` command yourself — always hand it to the user. After each step, re-read `status` before
advancing; every subcommand is idempotent, so resuming after an interruption is safe.
