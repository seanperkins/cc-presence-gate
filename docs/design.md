# cc-fido-gate — design

**Date:** 2026-07-16
**Status:** Revised after multi-model review (round 1, unanimous REVISE — all findings
folded in below); implementation still gated on the Task 0 feasibility spike.
**Prior art / spike this generalizes:**
Switchyard's supervised-sessions **phase 2** (the signed-affirmation gate for issue
`done`-stamps: `ssh-keygen -Y sign` over a canonical action doc, verified server-side).
That work lives on the `feat/affirmation-relay` branch of the Switchyard repo
(`MobilityLabs/switchyard`, PR #194 / SYD-242), **not on `main`** — so a repo checkout of
`main` will not find any `ssh-keygen`/`allowed_signers` code. It was proven end-to-end on a
real security key on 2026-07-16 (verdict: keep). This project lifts the primitive out of
Switchyard into a standalone, server-less Claude Code plugin. See "Provenance of the
'proven' claims" below for exactly what is and isn't independently reproducible.

---

## Review status

This design was pressure-tested by a five-model panel (codex, gemini, and three Claude
personas: fable-skeptic, opus-skeptic, pentester) on 2026-07-16. All five returned REVISE
with a strikingly convergent finding set. **The concept was affirmed** — presence-as-authorizer
is the right inversion, and the crypto was independently re-verified against real
`ssh-keygen` 10.4p1 — but the *first draft's stated guarantees overclaimed relative to what
it specified*, with four holes that would have made it security theater if shipped as
written (environment scrubbing, canonical-document binding, fail-open-on-timeout, and
no-touch-required keys). Every finding is addressed below; the ones that change the shape of
the project are called out inline as **[R1: …]**.

---

## The idea, in one paragraph

A `PreToolUse` hook is the entire enforcement surface. Before Claude Code runs a tool, the
hook decides whether that specific call is *gated*. For a gated call it renders the exact
effect to the human, asks an enrolled hardware key to sign a canonical document of that
call, verifies the signature, and allows the call only on success. An agent can run the
hook's `ssh-keygen -Y sign` as often as it likes and still cannot produce a valid signature,
because a security key requires a physical touch (and optionally a PIN) for every signature,
and an agent has no finger. Presence is proven by the one thing the agent structurally
cannot do.

The guarantee is enforced by the **token at signing time**, not by the verifier: the hook
verifies a valid signature from an enrolled key in the right namespace; it cannot itself
observe the touch (`ssh-keygen -Y verify` has no user-verification check — the four
`ALLOWED SIGNERS` options are `cert-authority`, `namespaces=`, `valid-after=`,
`valid-before=`, none of which assert presence). Presence rests on the authenticator's own
policy, which the design must protect at *enrollment* time (below), not verify after the
fact.

---

## Honest scope of the guarantee (read this before the mechanics)

**[R1 — the single most important revision.]** The first draft implied "dangerous commands
are gated." That is not what this delivers. Stated precisely:

> **A *recognized* gated action cannot proceed *synchronously* without a valid hardware
> signature from an enrolled key — provided (a) Claude Code denies a tool call whose
> PreToolUse hook times out or errors, and (b) the enrolled key genuinely requires a
> touch.** Both provisos are load-bearing and are verified in Task 0 / enrollment, not
> assumed.

What that guarantee does **not** cover, each stated plainly rather than glossed:

1. **Unrecognized actions** (Threat B) — matching an arbitrary shell string for "is this
   dangerous" is undecidable. The Bash danger-list is *advisory*: it catches the naive
   spelling, not a motivated agent (`rm -fr`, `bash ./x.sh`, `printf > .env`, calling the
   deploy script directly). **The non-launderable guarantee is for structured tools:** MCP
   tool-name matches and Write/Edit path-writes. Bash file-writes are *not* reliably caught
   by the path globs — those globs live only on the Write/Edit tools.
2. **Deferred / detached execution** — one un-gated call can install a `launchd`/`cron`/`at`
   job, a git hook, or a detached background process that runs later, outside any
   PreToolUse lifetime. Hence "*synchronously*" in the guarantee.
3. **The host's `root` user** — root can edit managed settings or the policy. The gate
   defends against the *agent*, not the *host owner*. That is the intended floor.

The plugin's copy, README, and dialog text must all reflect this scoped guarantee. Leading
with "dangerous commands are gated" over Bash examples — as the first draft did — misleads
users about what they're protected from.

---

## Task 0 — the feasibility gate (must pass before any implementation)

**[R1: promoted from "Task 1, spike the touch" to a hard go/no-go gate.]** Four platform
questions are each individually fatal if they resolve the wrong way. None is verified today.
Task 0 answers all four empirically against the installed Claude Code, and a wrong answer
kills or reshapes the project *before* any build:

1. **Deny-on-timeout / deny-on-error.** Does a PreToolUse hook that **times out with no
   output**, or **exits non-zero without `permissionDecision:"deny"`**, result in the tool
   being **denied**? Claude Code documents only exit `2` (or an explicit
   `permissionDecision:"deny"` on exit `0`) as blocking; exit `1`, crashes, and timeouts are
   commonly **non-blocking**. If a killed-on-timeout hook fails *open*, the gate is void in
   the unattended case it exists for — and the design must go **deny-first** (write a `deny`
   decision, arm the touch, flip to `allow` only on a verified signature) so any kill leaves
   `deny` as the last word. If even deny-first can't survive a mid-run kill, the synchronous
   in-hook model is abandoned for the async park-then-affirm fallback.
2. **Hooks fire under `--dangerously-skip-permissions` / `bypassPermissions`.** That is the
   mode an autonomous agent most likely runs in. If PreToolUse hooks are skipped there, the
   gate is void precisely where it matters.
3. **Managed-settings hooks are un-overridable and actually active.** Confirm a managed
   `PreToolUse` hook (a) runs, (b) cannot be removed or replaced by user/project/local/plugin
   settings, and (c) isn't silently superseded by a higher-precedence managed source (MDM /
   remote policy) or dropped for being an "invalid entry." The installer must probe this
   end-to-end (below), not assume it.
4. **Interactive sign inside the hook environment.** Can the hook run `ssh-keygen -Y sign`
   against a **real** `sk-` key, surface the ceremony, and block on the physical touch within
   the timeout ceiling (default ~60s — long enough for a human to fumble a key out of a
   drawer)? Include a **verify-required (PIN) key**, not just presence-only, since PIN entry
   needs a working askpass/TTY path the presence-only spike never exercised.

Deliverable: a short report answering all four with the actual commands and outputs. Only on
four green does implementation start.

---

## Provenance of the "proven" claims

**[R1: reviewers correctly flagged the original "Proven" list as unverifiable from `main`.]**

Independently reproduced during brainstorming, against real `ssh-keygen 10.4p1` (and
re-confirmed by the opus-skeptic reviewer on the same binary) — a **software** `ed25519` key
verifies through the identical production path, so these need no hardware:

- Headless stdin sign, no controlling TTY: `printf '%s' "$DOC" | ssh-keygen -Y sign -f k -n cc-fido-gate` succeeds.
- Correct-doc verify succeeds; **tamper** (one-token-different action) → `incorrect signature`, exit 255.
- **Wrong namespace** at verify, and an `allowed_signers namespaces=` restriction, both reject (exit 255).
- `-n` is mandatory at verify (empty namespace can't be used by accident).

**Not** independently reproducible here, and must not be cited as established fact:

- That a **hardware** `sk-` key blocks on a touch during signing — proven on Sean's key in
  the Switchyard spike (2026-07-16), but that lives on `feat/affirmation-relay`, not `main`.
  Link the spike transcript; do not assert it as repo-backed.
- That signing/verify behaves correctly **inside the Claude Code hook environment** — that is
  Task 0.4, still open.

---

## Architecture & components

Trust rests on OS permissions + Claude Code managed-settings precedence + a **scrubbed
execution environment** — **not** on the agent choosing to respect a config file, and **not**
on the exec environment the hook inherits.

| Component | Role | Location / privilege |
|---|---|---|
| `gate-hook` | The `PreToolUse` entrypoint. Reads `{tool_name, tool_input}` on stdin; gated → run ceremony; emits `permissionDecision`. **Deny-first.** | root-owned, agent-read/exec-only |
| `policy.json` | The gated-set definition (matchers). | root-owned, agent-read-only |
| `signing-registry.json` | **[R1]** Root-owned map of `fingerprint → principal → public key → private-key-handle path`. Drives both `-Y sign -f <handle>` and `-Y verify -I <principal>`. Not inferred from `allowed_signers` comments. | root-owned, agent-read-only |
| `allowed_signers` | Enrolled hardware public keys, namespace-scoped, one install-fixed principal for all keys (so one `-I` accepts any). Written only by `enroll`. | root-owned, agent-read-only |
| `enroll` CLI | Privileged, offline. Adds an `sk-*@openssh.com` public key; rejects software keys; **[R1] performs a live blink-test** (sign a nonce, operator confirms the physical touch) so a `no-touch-required` key can't silently enroll. | run with sudo |
| `install` CLI | Privileged. Places files above root-owned (atomic write/rename, correct owner+mode); registers the hook in `managed-settings.json` **with `allowManagedHooksOnly:true`**; **[R1] refuses to claim success without an end-to-end probe** that a known gated test call is actually blocked; refuses to register until ≥1 key is enrolled. | run with sudo |
| audit sink | **[R1] `os_log`/syslog**, not a plain file — a root-owned, append-only stream the unprivileged hook can write but cannot retroactively rewrite. (A plain "root-owned file" is unwritable by the hook, and a world-writable one is agent-truncatable — the original design was self-contradictory.) | OS logging facility |

### Execution-environment invariant [R1 — new, and load-bearing]

The hook is executed by the `claude` process **as the agent user**, inheriting the agent's
environment. Root-owning the *script* stops the agent rewriting it but does **nothing** about
what `ssh-keygen`/`osascript` resolve to at runtime. Without the following, one un-gated call
drops a `ssh-keygen` shim on `PATH` (or sets `SSH_SK_PROVIDER`, `BASH_ENV`, `DYLD_*`) and
`-Y verify` returns exit 0 with no crypto — defeating the entire gate:

- Invoke **every** helper by absolute, root-owned path: `/usr/bin/ssh-keygen`,
  `/usr/bin/osascript`, `/bin/…`. Never a bare name.
- Run the hook body under a **scrubbed environment** — `env -i` with an explicit minimal
  allowlist; drop `SSH_SK_PROVIDER`, `SSH_AUTH_SOCK`, `SSH_ASKPASS*`, `DYLD_*`, `LD_*`,
  `BASH_ENV`, `ENV`, `IFS`, `PATH` (set a fixed one). Force the built-in FIDO provider.
- The signing-key handle path comes from the root-owned `signing-registry.json`, never from
  an agent-writable location.
- This is a stated **invariant with a unit test** (a hostile `PATH`/`SSH_SK_PROVIDER` must
  still verify through the real binary) — the whole crypto argument depends on it.

---

## The gate flow (per-call, action-bound, deny-first)

```
tool call ─► PreToolUse ─► gate-hook  (absolute paths, scrubbed env)
  ├─ acquire global ceremony lock (flock, FD-based, stale-owner recovery)   [R1]
  ├─ not gated?  emit allow / exit 0  (normal flow, ~instant)
  └─ gated:
       0. DECISION := deny            ← deny-first: this is the last word if we're killed [R1]
       1. canonicalize the FULL tool_input → signed doc (see below)          [R1]
       2. arm the signer AND render, concurrently:                           [R1]
            • ssh-keygen -Y sign -f <handle> -n cc-fido-gate   (key blinks; touch / PIN)
            • osascript dialog (command passed as argv, NOT interpolated)     [R1]
              "cc-fido-gate — approve this exact action?  <rendered effect>
               Touch your key to approve, or Cancel to deny."
          mutual cancel: Cancel kills the signer; a completed signature dismisses the dialog;
          an internal watchdog (< hook timeout) reaps BOTH and their process group.          [R1]
       3. ssh-keygen -Y verify -I <principal> -n cc-fido-gate -s <sig via /dev/fd/N>          [R1]
             message = the exact canonical bytes, held in memory (no same-user tempfile)      [R1]
       4. verified?  DECISION := allow.  emit DECISION.  release lock.  log to os_log.
```

- **Deny-first** (step 0) is what makes `fail:"closed"` real rather than aspirational: a
  timeout-kill, crash, or non-zero exit leaves `deny` as the emitted/last decision. Contingent
  on Task 0.1.
- **Concurrent arm+render** (step 2) fixes the sequenced deadlock in the first draft: a modal
  `osascript display dialog` blocks until a button is pressed, so the key can't be armed
  *after* the dialog tells the human to touch it.
- **argv, not source interpolation** (step 2): the command is passed as `argv` to a fixed
  AppleScript (`on run argv … display dialog (item 1 of argv)`), never spliced into script
  source — closing the AppleScript-injection consent-forgery vector. A test asserts the
  displayed bytes equal the signed `action` bytes (WYSIWYS).
- **Global lock** (top): parallel tool calls would otherwise stack N dialogs and contend for
  one token, so the human can't bind a blink to a dialog. One ceremony is live at a time;
  queued gated calls wait (bounded) or deny.
- **Signature transport** (step 3): `-Y sign` writes to stdout, `-Y verify` wants `-s <file>`
  plus the message on stdin. Keep the canonical bytes in process memory and pass the signature
  via an anonymous descriptor (`/dev/fd/N`); a same-user `mktemp` is not a boundary because the
  agent shares the UID.

### Canonical document [R1 — now binds the full call, not a scalar]

The first draft's `{v, tool, action, cwd, ts}` with a single string `action` binds only Bash.
For Write/Edit/MCP the danger is in the *arguments/content*; signing the path to
`managed-settings.json` without binding its content is theatrical. The signed document is a
**recursively-normalized representation of all effect-bearing `tool_input` fields**, per tool:

| Tool | Effect-bearing fields the doc must bind |
|---|---|
| `Bash` | `command` (raw), `timeout`, `run_in_background` |
| `Write` | `file_path`, **content digest** (SHA-256) or, if small, the content |
| `Edit` | `file_path`, `old_string`/`new_string` digests, `replace_all` |
| MCP | the full nested input, recursively normalized |

Rules: an unknown tool, or an unknown effect-bearing field on a gated tool, **denies** until a
renderer exists for it. Canonicalization is a single **byte-level** algorithm — UTF-8,
**recursive** key sort (not top-level `JSON.stringify` only), defined array order, number
restrictions, defined final-newline, rejection of invalid Unicode — pinned by **golden-byte
fixtures**, not semantic JSON equality. The first draft's example was inconsistent with its own
`Object.keys().sort()` rule; the golden fixtures are the source of truth.

**Render/execute equivalence.** The signed/rendered bytes must equal the bytes Claude Code
executes. Two hazards: (a) **NFC normalization** would make signed bytes differ from the raw
executed bytes — so the *executed-equivalence* field is not normalized (normalize only a
separate display copy, and assert display-vs-signed equality). (b) **Shell expansion** —
`$VARS`, command substitution, `eval`, aliases — means a rendered pre-expansion literal need not
equal what runs. Commands containing expansion/substitution/`eval` are treated as a **gated (or
denied) class** so rendered and executed bytes cannot silently diverge; the dialog states it
shows the pre-expansion literal.

Namespace `-n cc-fido-gate` prevents a signature solicited here being replayable in another
domain of use (e.g. a git commit signature). Replay across calls is a non-issue: the signature
is produced and consumed inside one hook invocation and never stored; `ts` is audit-only.

---

## Gating config (`policy.json`)

```json
{
  "rules": [
    { "tool": "Bash", "advisory_command_matches": ["git push .*(--force|--force-with-lease|-f)\\b", "\\brm\\b.*-[rf]", "npm run deploy", "\\bkubectl\\b.*\\bdelete\\b"] },
    { "tool": "Write", "path_globs": ["**/.env*", "infra/**", "**/managed-settings.json"] },
    { "tool": "Edit",  "path_globs": ["**/.env*", "infra/**"] },
    { "tool": ["Write", "Edit", "NotebookEdit"], "write_default": "gate" },
    { "mcp_tool": "mcp__.*__(delete|drop|deploy|write|update)_.*" }
  ],
  "path_match": "realpath",
  "path_base": "<absolute; relative globs resolve against a defined base, symlinks resolved>",
  "fail": "closed"
}
```

**[R1] changes:** Bash matchers are renamed `advisory_command_matches` and documented as
naive-case-only (see Honest Scope); the real file-write guarantee is the `write_default:
"gate"` default-deny tier across the structured write tools (`Write`/`Edit`/`NotebookEdit`),
**not** the Bash regexes. Path globs match **realpath** (symlinks and `../` resolved) against a
defined base directory — the first draft left relative-vs-absolute, symlink, and case
(case-insensitive volumes) behavior undefined, so `infra/**` would not have matched
`/Users/…/infra/x`. `fail:"closed"` is realized by deny-first (above), and depends on Task 0.1.

The policy also protects its own files, `signing-registry.json`, `allowed_signers`, and
`managed-settings.json` as gated paths — belt-and-suspenders over the OS permissions.

---

## Threat model

### Threat A — the agent disables the gate itself
1. Hook registered in **managed settings** with **`allowManagedHooksOnly:true`** [R1] — the
   enterprise tier, unoverridable by user/project/local, *and* excluding agent-installed
   user/project/plugin hooks (which could otherwise return a malicious `updatedInput` that
   swaps a benign call the gate approved for a destructive one — a parallel-hook TOCTOU the
   first draft missed).
2. Policy, hook script, `signing-registry.json`, and `allowed_signers` are **root-owned,
   agent-read-only**; the agent cannot rewrite them.
3. **Scrubbed exec environment + absolute binary paths** [R1] — closes the `PATH`/
   `SSH_SK_PROVIDER`/`BASH_ENV`/`DYLD_*` shim that would otherwise make `-Y verify` theater
   regardless of file ownership.
4. Enrollment is privileged, offline, and **blink-tested** [R1] — the agent can't add a key
   it controls, and a `no-touch-required` key can't silently enroll.
5. The gate treats its own control files as gated paths (tamper-evident even if a mode is
   loosened).

Residual: `root` can edit managed settings. Intended boundary — the gate defends against the
agent, not the host owner.

### Threat B — the agent crafts an action the matcher doesn't recognize
Not fully solvable (undecidable). Mitigations: the `write_default:"gate"` tier for structured
write tools; conservative advisory Bash matchers labelled as such; and the honest,
re-scoped guarantee above. **Plus the time dimension [R1]:** deferred/detached execution
(launchd/cron/at/git-hook/background process) escapes PreToolUse entirely — the guarantee is
"cannot proceed *synchronously*," and the docs warn deferral escapes.

### Threat C — consent forgery at the human boundary [R1 — new section]
Even with valid crypto, the human can be tricked into touching for the wrong thing:
- **AppleScript injection** → argv-not-source (above) + WYSIWYS test.
- **Render/execute mismatch** via shell expansion → expansion/`eval` commands gated-or-denied.
- **Look-alike / touch-fatigue**: because the dialog runs as the agent user, the agent can spam
  pixel-identical prompts to condition reflexive touches. The un-spoofable signal is the
  **key blink correlated with the rendered action**, not "a dialog appeared" — a UX/copy
  requirement, and an argument for a hardware key with its own trusted display where the threat
  model warrants it.

---

## User verification (PIN) vs. presence (touch)

v1's default assurance is **presence** (a touch). But "every `sk-*` key enforces a touch" is
**false** for `-O no-touch-required` keys [R1] — touch policy is a sign-time authenticator
property, not encoded in the public key, and `-Y verify` can't assert the user-presence flag.
So enrollment's blink-test is the real presence guarantee, not the key-type check (which only
proves *hardware-backed*). Copy rule: "hardware-backed, and presence-required *because
enrollment blink-tested it* — not because the key type guarantees it," and never claim the
*verifier* observed the touch/PIN. `verify-required` (PIN) keys are supported but marked
**experimental until Task 0.4** exercises the PIN path inside the real hook environment.

---

## Recovery / key loss

Enroll two or more keys, all under **one install-fixed principal** so a single `-Y verify -I
<principal>` accepts any of them [R1], each registered in `signing-registry.json` with its own
private-key-handle path. Losing one is an inconvenience, not a lockout. Lose all → re-enroll via
the privileged `enroll` CLI (host access, below the gate's floor — not a bypass).

---

## Degraded environments [R1 — new]

`osascript` needs a WindowServer connection; under SSH-to-a-Mac or a bare `tmux`/`screen` it
fails. Combined with `fail:"closed"` that would lock the user out of every gated tool. Rendering
degrades along a chain: native GUI dialog → `/dev/tty` terminal prompt → (if neither is
available) deny with a clear "no trusted render surface" reason. The touch itself still works
headlessly; only the *trusted render* needs the fallback.

---

## Testing

- **Env-hygiene invariant [R1]** — hook with hostile `PATH`/`SSH_SK_PROVIDER`/`BASH_ENV` still
  verifies via the real binary (unit-testable without Claude Code).
- **Crypto plumbing** (green) — software `ed25519`, real `ssh-keygen -Y verify`, no mocks:
  verify, namespace enforcement, principal mismatch, tamper/replay rejection.
- **Canonicalization** — golden-byte fixtures; recursive key sort; a non-Bash (nested MCP /
  Write-with-content) input; NFC display-vs-executed equality; unknown-tool/field → deny.
- **WYSIWYS [R1]** — displayed dialog bytes == signed `action` bytes.
- **Policy matching** — every rule type incl. `write_default:"gate"`; realpath/symlink/`../`
  cases; `fail:"closed"` via deny-first on error / no keys.
- **`enroll`** — accepts real `sk-ssh-ed25519@openssh.com` / `sk-ecdsa-sha2-nistp256@openssh.com`
  wire spellings; rejects software keys and junk; TOCTOU-safe (read `.pub` once, bounded size,
  one record, exclusive lock); blink-test path asserted; two-keys-one-principal verify path.
- **Hook-protocol / harness [R1]** — Task 0 deliverables: deny-on-timeout, deny-on-nonzero,
  hooks-fire-under-bypass, managed-precedence-active, malicious-`updatedInput`-excluded,
  concurrent-call serialization, orphaned-signer cleanup.
- **`install` end-to-end probe [R1]** — a known gated test call is actually blocked post-install.
- **Not automatable, stated plainly** — that a touch/PIN actually happened; the verifier never
  sees it. The manual run on real hardware (and the enrollment blink-test) is the deliverable.

---

## Out of scope (v1)

- Non-macOS renderers (Linux/Windows) — follow-up; the `/dev/tty` fallback is the portable seam.
- WebAuthn/passkeys, push-notification transport.
- Session-unlock / windowed authorization — v1 is strictly per-call action-bound.
- Per-project policy — v1 policy is install-global and root-owned.
- Defending against the host `root` user, and against deferred/detached execution (Threat B) —
  explicit non-goals, documented so users don't over-trust the gate.
