# cc-fido-gate — configurable install policy (design)

**Date:** 2026-07-17
**Status:** approved (brainstorming), pending implementation plan
**Scope:** make the best-effort hook's policy (gate / block / allow) admin-configurable at install time,
without hardcoding one machine's paths. Isolation model is unchanged (agent runs as the login user; the
separate-low-priv-user model is noted as a future direction, out of scope here).

## Problem

`install/policy.json` shipped with one machine's working dirs baked into `allow_tier`
(`/Users/sean/proj/**`, `/Users/sean/sites/**`). Because `Policy.decideWrite` is **gate-by-default**
(`Policy.swift`: `locked_paths`→deny, `sensitive_globs`→gate, `allow_tier`→pass, **else→gate**),
`allow_tier` is the only escape from a touch — so on any other machine every write would gate. The policy
needs to be (a) portable and (b) chosen by the installing admin.

## Decisions (from brainstorming)

- **Isolation model:** keep same-user. Do NOT re-architect to a separate agent uid this round.
- **Config UX:** documented **template + validate**. No interactive wizard, no new config DSL (YAGNI).
- **Default `allow_tier`:** `["__HOME__/**"]` — trust the admin's whole home for un-gated writes; sensitive
  globs still gate everywhere (they're checked before `allow_tier`); everything outside home gates.

## Design

### 1. Source of truth + override
- `install/policy.json` is the editable **default template**: strict JSON, `__HOME__` placeholder(s) for
  portability. Admin edits it in place, **or** brings their own file.
- Install resolves the source path as `SRC="${POLICY:-$REPO/install/policy.json}"` — set `POLICY=/path`
  to supply a custom policy without editing the repo copy.

### 2. Documentation
- New `install/POLICY.md` documents every field with examples and the **verdict order**:
  - writes: `locked_paths` → hard deny; `sensitive_globs` → gate (touch); `allow_tier` → pass (no touch);
    otherwise → gate.
  - MCP: `mcp_allow` (as `[server, tool]` pairs) → pass; otherwise → gate.
  - bash: `bash_advisory` regexes → gate.
- Guidance lives in `POLICY.md`, **not** inline: JSON has no comments and `Policy.fromFile` requires
  strict JSON. (Rejected alternative: an ignored `"_help"` field in the JSON — keeps the file self-
  documenting but clutters it; the separate doc keeps the parseable file clean.)

### 3. Install flow (replaces the current blind `cp` at `task7_install.sh`)
```bash
SRC="${POLICY:-$REPO/install/policy.json}"
TMP="$(mktemp)"
sed "s|__HOME__|$HOME|g" "$SRC" > "$TMP"                        # portable home substitution (| delimiter)
/opt/cc-fido-gate/cc-fido _validate-policy "$TMP"              # fail-closed; aborts (set -e) on error
sudo tee /opt/cc-fido-gate/policy.json < "$TMP" >/dev/null      # root-owned final copy
rm -f "$TMP"
```
- Validation runs **before** anything is written, on the **substituted** content, so a broken policy aborts
  the install and never clobbers an existing good `/opt/cc-fido-gate/policy.json`.
- The final file stays root-owned (agent can't tamper) — unchanged from today.
- `task6_hook.sh` gets the same `sed`-substitution when it stages `policy.json`.

### 4. New `_validate-policy <path>` subcommand
- Dispatch case in `Sources/cc-fido/main.swift`. Loads the file via the existing fail-closed
  `Policy.fromFile` (already throws on missing keys / uncompilable `bash_advisory` regex — no new parser).
- Success: prints a one-line summary (e.g. `policy OK: 5 sensitive, 1 allow, 0 locked, 4 bash, 2 mcp`),
  exit 0. Failure: prints the error, exit 1.
- **Lint (warning, non-fatal):** if `allow_tier` contains a blanket `/**` or `**` (trusts everything →
  nothing outside sensitive globs ever gates), print a warning to stderr but still exit 0.

## Components / boundaries
- `install/policy.json` — data (template). `install/POLICY.md` — docs.
- `_validate-policy` — thin CLI wrapper over `Policy.fromFile`; one job (parse + report), reuses validated
  code, testable via exit code.
- `task7_install.sh` / `task6_hook.sh` — staging: substitute → validate → install.

## Testing / success criteria
- `_validate-policy`: a valid policy → exit 0; malformed (bad regex, missing required key) → exit 1
  (CLIHelperTests-style or a new PolicyTests case; `Policy.fromFile` fail-closed parse is already covered).
- `allow_tier: ["/**"]` → validate exits 0 but emits the over-permissive warning.
- Default template + `__HOME__` substitution installs cleanly; the existing Step-10 acceptance
  (`task7_accept.sh`) already exercises a real install end-to-end.
- Custom policy via `POLICY=/path` is used instead of the repo template.

## Out of scope (future specs)
- Separate low-privilege agent user (the stronger isolation model).
- Interactive policy wizard / `cc-fido init-policy`.
- Per-file `allow`/`block` beyond globs; runtime policy reload.
