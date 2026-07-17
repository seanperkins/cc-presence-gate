# cc-fido-gate — configurable install policy (design)

**Date:** 2026-07-17
**Status:** approved (brainstorming) + revised after round-1 multi-model review; pending implementation plan
**Scope:** make the best-effort hook's policy (gate / block / allow) admin-configurable at install time,
portably (no hardcoded machine paths) and safely (a bad or over-permissive policy can never silently
weaken the gate or clobber a good installed one). Isolation model is unchanged (agent runs as the login
user; the separate-low-priv-user model is a future direction, out of scope).

## Problem

At HEAD, `install/policy.json` hardcodes one machine's working dirs in `allow_tier`
(`/Users/sean/proj/**`, `/Users/sean/sites/**`). (A `__HOME__/**` fix is already staged uncommitted in the
working tree — this spec supersedes and completes it.) `Policy.decideWrite` is **gate-by-default**
(`Sources/CCFidoCore/Policy.swift:52-58`: `locked_paths`→deny, `sensitive_globs`→gate, `allow_tier`→pass,
else→gate), so `allow_tier` is the only escape from a touch — on any other machine every write would gate.
The policy must be (a) portable and (b) chosen by the installing admin, **without** the default silently
exempting dangerous paths from the gate.

## Decisions

- **Isolation model:** keep same-user (no separate agent uid this round).
- **Config UX:** documented **template + validate**. No interactive wizard, no config DSL (YAGNI).
- **Default `allow_tier`:** `["__HOME__/**"]` — trust the admin's home for un-gated writes; **but** the
  default `sensitive_globs` is widened (below) so home-wide allow does NOT exempt code-exec/persistence
  paths from the gate. Sensitive is checked before allow, so these gate everywhere.
- **Substitution + validation happen in Swift, not `sed`** — a `_render-policy` subcommand does a JSON-safe
  `__HOME__` substitution, guards `$HOME`, validates, and emits. This removes the `sed` replacement/JSON
  escaping bug class (`&`, `\`, `"`, delimiter, trailing slash) entirely and makes the whole path unit-testable.
- **Install is atomic and never touches a user-owned staging file** — render emits to a **root-owned**
  candidate, then `sudo mv` renames it into place. Closes the non-atomic `tee` truncation and the
  same-uid validate→install TOCTOU in one move.
- **A blanket `allow_tier` is FATAL, not a warning** — an over-permissive default (incl. the empty-`$HOME`
  `/**` footgun) is a fail-*open* gate, the wrong failure direction. Exact-string `**`, `/**`, `*`, `/*` in
  `allow_tier` → exit 1. (A narrower over-broad grant, e.g. a home-wide allow with a symlinked prefix, stays
  a non-fatal warning.)

## Design

### 1. Default policy template (`install/policy.json`, strict JSON, `__HOME__` placeholders)
```jsonc
{
  "sensitive_globs": [
    "**/.env*", "**/*.pem", "**/credentials*",
    "**/.ssh/*",
    "**/.zshrc", "**/.zprofile", "**/.zshenv", "**/.bashrc", "**/.bash_profile", "**/.profile",
    "**/Library/LaunchAgents/*", "**/Library/LaunchDaemons/*",
    "**/.gitconfig", "**/.config/git/*", "**/.git/hooks/*",
    "**/.claude/settings*.json", "**/.claude/CLAUDE.md", "**/.claude/hooks/*"
  ],
  "allow_tier": ["__HOME__/**"],
  "locked_paths": [],
  "bash_advisory": [ ... unchanged ... ],
  "mcp_allow": [ ... unchanged ... ]
}
```
Rationale (from review MAJOR — Fable + Pentester independently): under `__HOME__/**` + the old 5-glob
sensitive set, `~/.zshrc`, `~/.ssh/config`, `~/Library/LaunchAgents/*.plist`, `~/.gitconfig`,
`~/.git/hooks/*`, and `~/.claude/settings.json` all passed **un-gated** — shell/git/launchd code-execution
and persistence, plus the gate's own client config. None are on the broker `controlDenylist`, so nothing
backstops them. Widening `sensitive_globs` gates these everywhere at near-zero cost to ordinary project
writes (they gate before `allow_tier`). `.ssh/*` replaces the two narrower `.ssh` globs so `config` is covered.

### 2. Source of truth + override
- `install/policy.json` is the editable default template. Admin edits in place, **or** `POLICY=/path` supplies
  a custom file. Install resolves `SRC="${POLICY:-$REPO/install/policy.json}"`.

### 3. New subcommands (`Sources/cc-fido/main.swift` dispatch, `_`-prefixed like `_render-plist`)
Both are thin wrappers over `CCFidoCore` and require exactly one/two args (`args.count` checked like the
neighbors at `main.swift:45,48`); both wrap `Policy` loading in `do/catch` for a controlled stderr message + exit 1.

- **`_validate-policy <path>`** (read-only, unprivileged — admin "does my policy parse?" tool):
  loads via `Policy.fromFile`, prints a summary of actual counts (`policy OK: N sensitive, M allow, …`) to
  stdout, exit 0; on parse failure prints the error, exit 1. Runs the lints (below).
- **`_render-policy <src> <home>`** (substitution + validation + emit, used by install):
  reads `src` JSON, JSON-safely substitutes `__HOME__`→`home` in string values (parse → replace in the
  object graph → re-serialize; no `sed`), **guards `home`** (reject empty, `/`, `/var/root` → stderr "run as
  the login user, not root" + exit 1), validates the substituted dict via the same `Policy` code, runs the
  lints; **emits the validated JSON to stdout only on success** (exit 0). On any failure: stderr error, exit 1,
  **no stdout** (so a downstream `tee` writes nothing and the live policy is never partially overwritten).

**Lints (shared by both):**
- **FATAL (exit 1):** `allow_tier` contains an exact-string blanket grant — `"**"`, `"/**"`, `"*"`, or
  `"/*"`. Exact match only (a substring/suffix test would wrongly flag the legitimate `"/Users/x/**"`
  default — review MAJOR-3). This also catches the empty-`$HOME`→`/**` case fatally.
- **WARNING (non-fatal, stderr):** for each `allow_tier` glob, realpath its static prefix (up to the first
  metachar); warn if it differs from the literal (`/tmp`→`/private/tmp`, `/var`→`/private/var`) or doesn't
  exist. `matchPath` realpaths incoming paths but globs match literally (`Policy.swift:11-16`), so a
  symlinked-prefix entry silently never matches — the warning surfaces it. Also warns on a home-wide allow
  paired with an empty/short `sensitive_globs` (broad-allow + weak-net).

### 4. `Policy` API + parser changes (`Sources/CCFidoCore/Policy.swift`) — REQUIRED, was missing from the change list
- The summary/lint need `sensitiveGlobs`/`allowTier`/`lockedPaths`/`bashAdvisory`/`mcpAllow`, which are
  **`internal`** (`Policy.swift:22-25`) and unreachable from the `cc-fido` target (separate module). Add
  `public func summary() -> String` and `public func lint() -> (fatal: [String], warnings: [String])` on
  `Policy` (keeps fields encapsulated; cleaner than making them public). The subcommands are thin callers.
- **Strengthen `fromDict` (`Policy.swift:37-46`):** reject `mcp_allow` entries whose element count ≠ 2 (today
  it accepts `[]`/`["s"]`/`["s","t","x"]`, which silently never match the 2-element lookup at `:59-62` yet
  `_validate-policy` would say "OK").
- **Richer `PolicyError.badFile`:** carry the underlying JSONSerialization error text and the first
  missing/mistyped key name (today `fromFile` swallows it with `try?` at `:48-49` and every key error collapses
  to bare `badFile`). Hand-editing strict JSON is now the primary admin UX; a trailing comma or `allow_teir`
  typo must say what's wrong.

### 5. Install flow (`task7_install.sh`, replaces the blind `cp` at `:10`)
```bash
SRC="${POLICY:-$REPO/install/policy.json}"
CAND=/opt/cc-fido-gate/policy.json.new
trap 'sudo rm -f "$CAND"' EXIT
/opt/cc-fido-gate/cc-fido _render-policy "$SRC" "$HOME" | sudo tee "$CAND" >/dev/null   # validates; empty stdout on failure
sudo test -s "$CAND"                                    # non-empty ⇒ render succeeded (set -e + pipefail already on, :3)
sudo mv "$CAND" /opt/cc-fido-gate/policy.json          # atomic replace; agent-tamper-proof root-owned 0644 (chmod at :11)
```
- Render runs as the login user, output piped straight to a **root-owned** `$CAND` — there is no
  user-owned file holding to-be-installed content, and `$CAND` can't be swapped by a same-uid process
  before `mv`. `mv` is atomic, so a concurrent hook never reads a half-written policy and an interrupted
  install leaves the previous good policy byte-for-byte intact.
- `set -eu -o pipefail` (`:3`) already aborts on a failed render.

### 6. `task6_hook.sh` (test harness) — same path, and fix its shell discipline
- Today it's `set -u` only (`:2`) and blind-`cp`s (`:5`), so a failed validation would fall through and
  overwrite the **real** installed policy, after which the hook fails closed and denies everything
  (`HookLogic.swift:33-35`) — a test script bricking the production gate. Give it the same
  `_render-policy → root candidate → mv` flow with an explicit `|| exit 1` (or `set -e`), staged with the
  freshly-built `$BIN` (the installed `/opt/cc-fido-gate/cc-fido` may not exist during this pre-install test).

### 7. Documentation (`install/POLICY.md`)
Documents every field + the verdict order (writes: locked→deny, sensitive→gate, allow→pass, else→gate;
mcp: 2-element `[server,tool]`→pass else gate; bash: regex→gate) **and** the glob semantics that bite
authors: patterns are `fnmatch(…, 0)` — no `FNM_PATHNAME`, so `*` and `**` both cross `/` (NOT gitignore
semantics; `~/x/*` allows arbitrary depth) — and are matched against **symlink-resolved** paths, so authors
must write resolved prefixes (`/private/tmp/**`, not `/tmp/**`). Explicitly enumerates the residual risk of a
home-wide `allow_tier` (what's still gated by the default `sensitive_globs`, and what an admin who narrows
the set gives up) so the choice is informed.

## Components / boundaries
- `install/policy.json` — data (template). `install/POLICY.md` — docs.
- `_validate-policy` / `_render-policy` — thin CLI wrappers over `Policy` (`summary()`/`lint()`); one job each.
- `Policy` — gains `summary()`, `lint()`, stricter `mcp_allow` validation, richer error; the sole parser/matcher.
- `task7_install.sh` / `task6_hook.sh` — staging: render(substitute+validate) → root candidate → atomic mv.

## Testing / success criteria
Unit (`Tests/CCFidoCoreTests/`):
- `Policy.decideWrite` verdicts over the new default (build `Policy` from literals): `$HOME/foo` → `.pass`;
  `/etc/foo` (outside home) → `.gate`; `$HOME/.env` → `.gate` (sensitive beats allow); `$HOME/.ssh/config`,
  `$HOME/Library/LaunchAgents/x.plist`, `$HOME/.git/hooks/pre-commit` → `.gate` (the widened set).
- `fromDict`: `mcp_allow` entry with ≠2 elements → throws; missing/mistyped key → error names it.
- `lint()`: `["/**"]`/`["**"]`/`["*"]` → fatal; **`["/Users/x/**"]` (the default shape) → NOT fatal, no
  warning** (the MAJOR-3 anti-regression negative test); symlinked-prefix (`["/tmp/**"]`) → warning.
- `_render-policy` (via a small unit around the render function): `__HOME__` fully substituted; empty/`/`/`/var/root`
  home → error+exit 1, no output; a home containing `&`/`"`/`\` → still valid JSON (the sed-bug regression).
CLI-level (executable test capturing stdout/stderr/exit — `CLIHelperTests` currently only calls library fns):
- `_validate-policy`: valid → 0; missing file, malformed JSON, missing key, bad regex, bad mcp tuple,
  blanket `/**`, extra args → 1; warning goes to **stderr**.
Install/integration (extend the userrun scripts — the current `task7_accept.sh` runs AFTER install and never
exercises substitution or the policy layer, so the plan's "acceptance exercises install end-to-end" was false):
- post-install assert `! grep -q __HOME__ /opt/cc-fido-gate/policy.json && grep -q "$HOME" …`.
- a bad `POLICY=/path` (broken regex) leaves the previous `/opt/cc-fido-gate/policy.json` byte-for-byte intact.
- a custom `POLICY=/path` source wins over the repo template.

## Out of scope (future specs)
- **Config-authoring skill (planned next companion spec):** a Claude Code skill (`/cc-fido:policy`-style)
  that interviews the admin about their setup (project roots, what to protect, sensitivity tolerance) and
  generates a `policy.json` — then verifies it with the `_validate-policy` subcommand and explains residual
  risk from `POLICY.md`. It *consumes* this spec's deliverables (the validator + the documented schema), so
  it's sequenced after this one, not folded in. Supersedes the deferred shell "interactive wizard" — a skill
  is the lighter, better-fit form of the same guided-authoring goal.
- **Plugin packaging (roadmap target):** distribute cc-fido-gate as a Claude Code plugin — plugin manifest
  bundling the config-authoring skill, install/enroll/teardown as slash commands, `POLICY.md` as reference,
  and the codesigned binary. Portability (this spec) and the config skill are prerequisites for it; its own spec.
- Separate low-privilege agent user; per-file allow/block beyond globs; runtime policy reload.

## Review revisions (round 1 — codex/gemini/Fable/Opus/Pentester → REVISE)
- **MAJOR (Fable+Pentester):** widened default `sensitive_globs` to cover shell-rc/ssh-config/LaunchAgents/
  git/`.claude` code-exec+persistence classes (§1).
- **MAJOR (Opus+codex+Fable):** `_validate-policy` needs public `Policy` API — added `summary()`/`lint()`;
  listed `Policy.swift` as a changed surface (§4).
- **MAJOR (Fable+Opus+codex):** real tests for substitution + the gating verdict + the "default doesn't warn"
  negative case; corrected the false "acceptance tests install end-to-end" claim (§Testing).
- **codex #1/#2 + Fable MINOR-5:** atomic root-owned candidate + `sudo mv` (§5) — closes non-atomic `tee`
  and the validate→install TOCTOU.
- **Opus MAJOR-2/3:** `$HOME` guards (empty/`/`/`/var/root`) + exact-string blanket lint made FATAL (§3, Decisions).
- **All correctness reviewers:** substitution moved into Swift `_render-policy`, eliminating the `sed`
  escaping bug class (§3, Decisions).
- **codex #6:** `mcp_allow` tuple arity validated (§4). **Fable MAJOR-3:** realpath/`fnmatch` glob semantics
  documented + prefix-realpath lint (§3, §7). **codex #3/Fable/Opus:** `task6_hook.sh` shell discipline (§6).
  **Fable MINOR-3:** richer parse errors (§4).
