# cc-fido-gate

**Require a physical FIDO/security-key touch before Claude Code runs a high-risk tool call.**

`cc-fido-gate` is a Claude Code plugin that binds a hardware security key to an agent's
most dangerous actions. When a gated tool call fires — a force-push, an `rm -rf`, a prod
deploy, a write to `.env` — a `PreToolUse` hook renders the exact command and demands a
signature from an enrolled hardware key before it will allow the call to proceed.

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

🚧 Design revised after **two** five-model review rounds (both unanimous REVISE — every finding
folded in; the concept was affirmed by the whole panel). Buildability is gated on a **Task 0
feasibility spike** (chiefly: does Claude Code deny a tool whose hook is killed/times-out?). See
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

## License

MIT — see [LICENSE](LICENSE).
