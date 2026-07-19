# cc-presence-gate

**Require a physical presence check — a FIDO security key *or* Touch ID — before Claude Code runs a high-risk tool call.**

`cc-presence-gate` ships two Claude Code plugins — **`cc-fido`** (a FIDO/security-key touch) and
**`cc-touch-id`** (a Touch ID / Secure Enclave biometric) — that bind a physical presence gesture to
an agent's most dangerous actions. When a gated tool call fires — a force-push, an `rm -rf`, a prod
deploy, a write to `.env` — a `PreToolUse` hook renders the exact command and demands a hardware
signature before it will allow the call to proceed.

The agent can *trigger* the prompt as often as it likes. It cannot satisfy it: producing
the signature requires touching the key (and optionally entering a PIN), and an agent has
no finger. That inversion is the whole idea.

```
Claude wants to run:  git push --force origin main
Touch your key to approve, or Cancel to deny.
   🔑  *blink*
```

## Why this exists

Cryptographically binding a human presence gesture to an agent's high-risk action is,
as of this writing, **absent from the ecosystem** — no known Claude Code plugin, hook, or
MCP server does it. This plugin is that artifact. It generalizes a proven spike
([Switchyard](https://github.com/MobilityLabs/switchyard)'s signed-affirmation gate for
issue `done`-stamps) into a reusable, self-contained tool with no server dependency.

## What it guarantees — stated honestly

A **recognized** gated action cannot proceed **synchronously** without a valid hardware
signature from an enrolled key — *provided* Claude Code denies a tool call whose hook times
out or errors, and the enrolled key genuinely requires a touch. The agent cannot disable the
gate (managed settings + root-owned, agent-read-only policy + a scrubbed exec environment)
and cannot forge the touch.

It does **not** guarantee that every dangerous action is *recognized* — arbitrary shell-string
gating is undecidable, so the Bash danger-list is *advisory*; the non-launderable guarantee is
for structured tools (MCP name-matches and Write/Edit path-writes via a default-deny tier). It
does not cover **deferred/detached** execution (a `launchd`/`cron`/git-hook job runs outside the
hook), and it does not defend against the host's `root` user (that's you). See
[docs/design.md](docs/design.md) for the full threat model — including the four platform
questions (Task 0) that must resolve favorably before this is buildable at all.

## Status

**Built and working.** Both gates are implemented on a shared privileged-broker core (`CCGateCore`):
`cc-fido` (FIDO security key) and `cc-touch-id` (Touch ID / Secure Enclave). The Touch ID gate is
Developer-ID-signed, notarized, and published — a from-scratch install → enroll → real gated write has
been verified end-to-end on hardware. Known non-blocking residuals are tracked in
[docs/FOLLOWUPS.md](docs/FOLLOWUPS.md); the full threat model and design rationale are in
[docs/design.md](docs/design.md).

## Requirements

- macOS (the touch renderer uses a native dialog; other platforms are a follow-up)
- A FIDO2 / security key that supports SSH `sk-*` keys (e.g. YubiKey 5+)
- OpenSSH with FIDO support for *signing*: `brew install openssh` (stock macOS
  `ssh-keygen` has no FIDO provider). *Verification* works with stock `ssh-keygen`.
- Claude Code

## Install
Guided (recommended): run the `/cc-fido:install` skill and follow the prompts.
Manual:
1. `sudo cc-fido install --policy plugins/cc-fido/install/policy.json`   # prereqs + policy
2. `cc-fido enroll`                                        # generate + register your key (touch)
3. `sudo cc-fido activate`                                 # start the daemon
Check state any time: `cc-fido status`. Remove everything: `sudo cc-fido uninstall`.

> **⚠️ Restart Claude Code after installing.** The `PreToolUse` hook loads from managed-settings at
> Claude Code **startup** — a session already running when you install is **not** gated (its tool calls
> bypass the hook entirely). Quit and reopen Claude Code, or start a fresh session, for the gate to apply.

## Touch ID gate (`cc-touch-id`)

An alternative gate that swaps the hardware security key for your Mac's built-in Touch ID sensor
(Secure Enclave key, no external key required). Same hook/broker architecture as `cc-fido`, same
custody guarantees — the presence ceremony is a Touch ID sheet instead of a key blink.

**Guided (recommended):** run the `/cc-touch-id:install` skill — it detects whether you have an Apple
Developer ID and picks the right path below, then walks each step.

Touch ID's hook/enroll/write roles use a Secure Enclave key, which macOS only permits from a
**provisioned, Developer-ID-signed, notarized `.app` bundle** (a bare CLI binary is killed by amfid).
You obtain that `.app` one of two ways. Both start the same — clone the repo and build the (unentitled,
anyone-can-build) daemon binary:

```
git clone https://github.com/seanperkins/cc-presence-gate.git && cd cc-presence-gate
swift build -c release
```

**Path A — download the prebuilt notarized build (no Apple account needed).**
`fetch-app.sh` downloads the published `.app` and verifies it against a pinned SHA-256 + Developer-ID
signature + team `HH3SJBAS42` + no `get-task-allow` before use:

```
APP="$(bash install/fetch-app.sh)"
sudo APP="$APP" bash install/install.sh
/opt/cc-touch-id-gate/cc-touch-id.app/Contents/MacOS/cc-touch-id enroll     # real terminal, touch
sudo /opt/cc-touch-id-gate/cc-touch-id activate
```

**Path B — build + sign it yourself (highest trust: you compiled it).**
Needs a Developer ID Application certificate and a stored `notarytool` credential (a non-`HH3SJBAS42`
team also retargets `DEVELOPMENT_TEAM`/bundle id in `packaging/` and passes `EXPECTED_TEAM=<team>`):

```
bash packaging/build-distribution.sh
sudo APP="$PWD/packaging/.dd/export/cc-touch-id.app" bash install/install.sh
# then enroll + activate exactly as in Path A
```

Check state with `cc-touch-id status`. Remove everything with `sudo /opt/cc-touch-id-gate/cc-touch-id
uninstall` (delete the Secure Enclave key first via the entitled app's `… _delete-key`). Run the
sudo/touch steps in a **real terminal** so `sudo` can prompt and the Touch ID sheet can appear.

> **⚠️ Restart Claude Code after installing.** The `PreToolUse` hook loads from managed-settings at
> Claude Code **startup** — a session already running when you install is **not** gated (its tool calls
> bypass the hook entirely). Quit and reopen Claude Code, or start a fresh session, for the gate to apply.

> **macOS 26 note:** current `stapler`/`spctl` regressions ship the build notarized but *un-stapled* —
> it passes Gatekeeper via the online check, so first launch needs network. See
> [docs/FOLLOWUPS.md](docs/FOLLOWUPS.md).

**cc-fido and cc-touch-id do not coexist yet.** Both write the same managed-settings hook file;
installing one replaces the other's gate. Pick one per machine until a future coexistence pass
(deferred "Pillar C" in the design doc) lands.

## License

MIT — see [LICENSE](LICENSE).
