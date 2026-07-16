# Task 0 — feasibility gate findings

**Date:** 2026-07-16
**Machine:** darwin 25.5.0 (arm64), Claude Code **2.1.211**, real binary
`/Users/sean/.local/share/claude/versions/2.1.211`.
**Method:** headless `claude -p … --dangerously-skip-permissions --allowedTools Bash`
against isolated `--settings` files wiring a `PreToolUse` (Bash matcher) hook to
`task0/probes/hook-probe.sh`. Observable = a unique **absolute sentinel** the driven
Bash call touches; **present ⇒ tool PROCEEDED, absent ⇒ DENIED**. Sentinels live under
`/tmp/claude/…` so the *inner* `claude -p` Bash sandbox permits the write (else a sandbox
refusal masquerades as a hook-deny and poisons the observable — this bit us once, noted).

Scripts: `task0/probes/hook-probe.sh`, `task0/probes/run-hook-semantics.sh`.

---

## Scoreboard

| # | Item | Status | One-line |
|---|------|--------|----------|
| 0.1a | watchdog exits 2 < outer timeout → blocked? | ✅ **GREEN** | exit 2 blocks; internal-watchdog fail-closed works |
| 0.1b | outer-timeout / `pkill -9` / crash → deny or proceed? | ⛔️ **PROCEED (fail-open)** | **decisive — see below** |
| 0.2 | hooks fire + `deny` blocks under `--dangerously-skip-permissions` | ✅ **GREEN** | `permission_mode:bypassPermissions`, deny still blocks |
| 0.3 | managed-hook precedence + no-sibling-`updatedInput` | ✅ **CORE GREEN** | `allowManagedHooksOnly:true` suppresses user/project hooks; plugin-scope + `updatedInput` still TODO |
| 0.4 | interactive hardware sign+block inside hook env; PIN path | ✅ **HARDWARE GREEN** | negative blink-test passes on a real YubiKey; sign-in-hook-env + PIN still TODO |
| 0.5 | `osascript` dialog survives the `env -i` scrub | ✅ **GREEN** | renders under `env -i` (empty env!) — WindowServer via bootstrap, not env |
| 0.6 | what env does CC hand the hook; agent-influenceable? | ✅ **CHARACTERIZED** | fully unscrubbed & hostile — see below |
| 0.7 | running-process integrity (attach must fail) | ✅ **GREEN (this machine)** | same-uid attach denied even to non-hardened procs |

---

## 0.1 — Fail-closed reality (the load-bearing gate) — **DECISIVE**

Full behavior matrix (`run-hook-semantics.sh`), one run, plus a 3× repeat of the two
unknowns to rule out timing flukes:

| mode | mechanism | observed | repeat |
|---|---|---|---|
| `allow0` | clean exit 0, no output | PROCEED | — (control) |
| `deny0` | exit 0 + `permissionDecision:deny` JSON | DENY | — (control) |
| `exit2` | exit 2 | DENY | — |
| `exit1` | exit 1 | PROCEED | — |
| `watchdog2` | internal watchdog: `sleep 1; exit 2` (< outer timeout 30s) | **DENY** | — |
| `timeout` | `sleep 60`, outer hook timeout **5s** (CC kills it) | **PROCEED** | 3/3 PROCEED |
| `crash` | hook dies by `kill -9 $$` mid-ceremony | **PROCEED** | 3/3 PROCEED |

**Interpretation.**
- The **catchable** fail-closed path works: a hook that *returns* exit 2 (directly, or via
  an internal watchdog that fires before CC's outer timeout) reliably **blocks** the tool.
  This is exactly the mechanism `design.md` proposed (watchdog < outer timeout). ✅
- The **uncatchable** path **fails open**: when the hook does **not** return a decision —
  CC's outer timeout expires and CC SIGKILLs it, or the hook crashes / is `kill -9`'d
  mid-ceremony — **CC lets the tool proceed**. Deterministic (3/3 each).

**Consequence (per `design.md`'s own go/no-go rule, lines 38–43 & 119–122).**
`0.1(b) = proceed` **terminates the interactive synchronous in-hook v1** as a *guaranteed*
design. The internal watchdog salvages only the timeout sub-case (convert to exit-2 before
CC's timeout). It **cannot** salvage crash / external `kill -9`: a same-uid agent that
launches a background killer via an un-gated Bash call (Bash is advisory-only in this design)
and `pkill -9`s the `gate-hook` the instant it spawns gets the tool to **proceed with zero
touches** — a total bypass, through none of the FIDO machinery. This is the "same-uid agent
can kill the holder" residual the threat model conceded, now shown to be **fail-open, not
fail-closed**.

The fix is the one the doc pre-committed to: an **async / privileged-broker** architecture
where the **default is deny** and execution requires a *positive later* signal, so killing
anything mid-flight leaves the call denied (fail-closed by construction). That is a separate,
re-reviewed design — **not** a patch to v1.

> **Bottom line: the synchronous in-hook model is not buildable to its guarantee on CC
> 2.1.211. Proceed to spec the async/broker model, or accept a weaker "best-effort, defeatable
> by a same-uid agent" property for v1.** ← user decision.

## 0.2 — Deny under `--dangerously-skip-permissions` — **GREEN**

Every invocation above ran with `--dangerously-skip-permissions`; the hook stdin showed
`"permission_mode":"bypassPermissions"`, yet `deny0`/`exit2`/`watchdog2` all **blocked**.
So a PreToolUse `deny` (and exit 2) overrides bypass mode. ✅ (Managed-hook *precedence* under
an adversarial project/plugin config is the separate 0.3 question.)

## 0.6 — Hook environment — **CHARACTERIZED (hostile, as feared)**

CC hands the PreToolUse hook a **fully unscrubbed** environment. Live injection vectors present
without any agent effort:

- `NODE_OPTIONS=--require=/var/folders/…/restore-node-options.cjs` — a **node `-r` code-injection
  vector**; any node the hook launches runs that file first.
- `PATH` heavily prepended with cmux shims + user dirs (`~/.local/bin`, plugin bins, …) — a
  hostile `PATH` is the default, not the exception.
- Secrets in plaintext (`OPENAI_API_KEY`, `GEMINI_API_KEY`, …) — **redacted here**; they sit in
  the hook env regardless.
- Not observed but must still be assumed reachable via project/`direnv`/launch profiles:
  `SSH_SK_PROVIDER`, `SSH_SK_HELPER`, `SSH_ASKPASS*`, `DYLD_*`, `BASH_ENV`.

This **validates the Execution Invariant hard**: allowlist-only scrub + absolute root-owned
helper paths + **interpreter hardened at launch** (`bash --noprofile --norc`, `python -E -I`,
neutralize `NODE_OPTIONS`) are load-bearing, not belt-and-suspenders. `env -i` in the *body* is
too late — `NODE_OPTIONS`/`BASH_ENV` fire during interpreter bootstrap, before the body runs.

**Exact stdin schema** CC gives the hook (fields the canonical-doc binding must consume):
`session_id, transcript_path, cwd, prompt_id, permission_mode, hook_event_name, tool_name,
tool_input{…}, tool_use_id`. Note `cwd` is provided (needed for relative-Bash meaning), and
`tool_input` is CC's own serialization (the single validated object the three artifacts derive
from — no re-parse).

## 0.3 — Managed-hook precedence — **CORE GREEN**

`probe-0.3-managed.sh` (run as the user; `sudo`s internally). Observed:

| config | markers fired | tool |
|---|---|---|
| `allowManagedHooksOnly:false` (baseline) | `MANAGED USER` (both) | proceeded |
| `allowManagedHooksOnly:true` | `MANAGED` only — **USER suppressed** | proceeded |

So the OS-level managed setting genuinely **suppresses** a user/project PreToolUse hook, not
merely deprioritizes it. That is the property the gate depends on (the agent can't add a sibling
hook that runs alongside the managed gate). **Still TODO** (need extra fixtures, not blockers):
(1) **plugin-scope** — confirm a force-enabled *plugin* PreToolUse hook is also suppressed;
(2) **no-sibling `updatedInput` (NEW-4)** — confirm no permitted hook can return `updatedInput`
that swaps the approved input after the gate signed it.

(Harness note: the first run of this probe had a cleanup bug — its backup logic captured its own
phase-A file and "restored" it, leaving a stale global `managed-settings.json`. Caught, removed,
and the script rewritten to snapshot original state once before any install. Finding itself
stands.)

## 0.5 — `osascript` under env scrub — **GREEN (better than feared)**

`probe-0.5-osascript.sh`. Two gotchas found and handled: (1) the box's **default OSA language is
JavaScript (JXA)** — `display dialog` must be forced with `-l AppleScript`; (2) `display dialog`
needs **StandardAdditions**, which will **not load under a sandbox-exec** (that + `-10810`
app-launch errors are the sandbox signature) — so this must run un-sandboxed, matching how CC
launches a hook.

Result: the dialog renders under **`env -i` with a completely empty environment** (exit 0). So
WindowServer access rides the **inherited Mach bootstrap port** through the process tree, **not**
any env var. The scrub can therefore drop *everything* — `DYLD_*`, `PATH`, `NODE_OPTIONS`,
`BASH_ENV`, `SSH_*` — and the dialog still shows. (Keep `__CF_USER_TEXT_ENCODING` for correct
**Unicode glyph** rendering of paths in the WYSIWYS content, even though it isn't needed to
*launch* the dialog.)

## 0.7 — Running-process integrity — **GREEN (this machine)**

`probe-0.7-attach.sh`. Same-uid `lldb` attach is **denied even against a plain non-hardened
`sleep`**: "Not allowed to attach to process." This machine has task-port debugging off (the
`system.privilege.taskport.debug` right isn't granted; `DevToolsSecurity` errors). So a same-uid
agent cannot `task_for_pid`/attach to **anything** without authorization — the gate is safe as-is
here.
- **SIP enabled.** Shipped `claude` is **hardened-runtime signed** (`flags=0x10000(runtime)`,
  TeamID `Q6L2SF6YDW`, no `get-task-allow`) — proving attach-resistant same-uid binaries are
  achievable, the portable mitigation for a machine where a dev has run `DevToolsSecurity -enable`.
- Not isolatable here without changing the machine's posture: that a hardened binary blocks attach
  *even with dev-mode on* (the blanket taskgated denial masks it). Deferred to a build-time check
  once the gate binary is signed the same way. **Not** worth enabling developer mode to prove.

## 0.4 — Crypto plumbing (software half) — **GREEN**

`probe-0.4-crypto.sh`, stock `/usr/bin/ssh-keygen` OpenSSH 10.2p1. All green: headless stdin sign,
namespaced verify against `allowed_signers`, tamper rejection, wrong-namespace rejection,
wrong-principal rejection, and the load-bearing **`/dev/fd` non-seekable-pipe transport (NEW-8)**
for **both** signature and message — so the in-memory handoff needs no TOCTOU-prone tmpfile.
**Hardware half — GREEN on a real YubiKey (OTP+FIDO+CCID), 2026-07-16.** Enrolled a dedicated
`sk-ssh-ed25519@openssh.com` key (non-resident, touch-required; Homebrew
`/opt/homebrew/opt/openssh/bin/ssh-keygen` for the *sign* side, stock for verify):
- **Negative phase:** armed the signer, **withheld** touch → blocked on "Confirm user presence",
  killed at 10s → **no signature**. ✅
- **Positive control:** armed again, **touched** → signature produced → **verified with stock
  `/usr/bin/ssh-keygen`** ("Good signature for gate-principal with ED25519-SK key"). ✅

So presence is genuinely enforced by the token and the stock binary verifies — the core guarantee
holds on real hardware.

**NEW operational finding — device-busy after a hard-killed ceremony.** Ending the negative phase
with `kill -9` left the FIDO device transiently unusable: the *next* sign failed
`Couldn't sign message: device not found` and succeeded only on retry (no lingering `ssh-sk-helper`;
device still USB-enumerated). Implication for the gate/broker: the watchdog-cancel path that reaps
a signer will occasionally leave the authenticator briefly unavailable, so the **next** ceremony
must tolerate a `device not found` with a short retry/backoff rather than fail hard. Not in the
current design — add it.

**Still TODO for 0.4** (not platform unknowns): **sign-in-hook-env** (key blinks + blocks inside
the scrubbed hook/broker env, driven end-to-end) and the **PIN path** (verify-required key needs a
root-owned askpass; no controlling terminal). Steps in `probe-0.4-hardware-checklist.md`.

---

## Remaining, and how to run each

- **0.3 extras:** **plugin-scope** suppression and no-sibling **`updatedInput`** (NEW-4) — both
  need a plugin / second-permitted-hook fixture. Core suppression is proven.
- **0.4 sign-in-hook-env + PIN:** the negative blink-test is **done** (passed on real hardware);
  what's left is driving a sign end-to-end from inside the scrubbed hook/broker env, and the PIN
  path — steps in `probe-0.4-hardware-checklist.md`.

---

## Net

All seven platform items now have empirical answers. Remaining bits are integration/fixture work,
not platform unknowns: 0.3's plugin-scope +`updatedInput`, and 0.4's sign-in-hook-env + PIN. Every
question came back favorable **except the one that matters most**: 0.1(b). `design.md` said it
"decides whether this is buildable at all," and it came back the way that **ends the synchronous
in-hook v1 as a guaranteed design** — fail-**open** on hook crash/kill/timeout-expiry,
fail-**closed** only for what the hook itself returns as exit 2. The env is hostile (0.6) but
scrubbable to empty and the dialog still renders (0.5); the crypto path works end to end (0.4);
same-uid attach is blocked (0.7); managed settings suppress user hooks (0.3) and managed deny
overrides bypass (0.2). **So the pieces all work — but the enforcement model must move from
synchronous-in-hook to the async/privileged-broker design (default-deny) for the guarantee to
hold.**
