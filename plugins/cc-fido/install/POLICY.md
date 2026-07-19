# cc-fido-gate policy reference

`/opt/cc-fido-gate/policy.json` is the **best-effort hook** policy: it decides which agent tool
calls require a physical FIDO touch. It is root-owned and the agent cannot edit it. (The *hard*
guarantee — `_ccfido`-owned + `uchg` custody — is separate and stronger; this policy is the broad,
honestly-defeatable tier.)

## How to configure

Edit `install/policy.json` before install, **or** point the installer at your own file:
`POLICY=/path/to/policy.json bash scripts/userrun/task7_install.sh`. Install substitutes `__HOME__`
with your home, validates, and installs atomically — a broken or blanket policy aborts the install and
leaves the previous one intact. Check a file yourself any time with
`/opt/cc-fido-gate/cc-fido _validate-policy <file>`.

## Verdict order (writes: Write/Edit only)
1. `locked_paths` → **deny** (hard, with a nudge)
2. `sensitive_globs` → **gate** (touch required)
3. `allow_tier` → **pass** (no touch)
4. anything else → **gate**

`sensitive_globs` is checked *before* `allow_tier`, so a broad `allow_tier` can never un-gate a
sensitive path. Bash: a command matching any `bash_advisory` regex → gate, else pass. MCP: a
`mcp__server__tool` call whose `[server, tool]` is in `mcp_allow` → pass, else gate.
`MultiEdit`/`NotebookEdit` (and any other tool not named above) are **always gated** — they never
take the `allow_tier` pass, erring safe rather than extending the ladder to them.

## Fields
- **`sensitive_globs`** — globs that always gate. Defaults cover secrets (`.env*`, `*.pem`,
  `credentials*`, `.ssh/*`) and code-exec/persistence (`.zshrc`/`.bashrc`/`.profile`,
  `Library/LaunchAgents/*`, `.gitconfig`, `.git/hooks/*`, `.claude/settings*.json`/`hooks`).
- **`allow_tier`** — globs that pass without a touch. Default `__HOME__/**` (whole home, minus
  `sensitive_globs`). Narrow to specific project roots for a stricter posture.
- **`locked_paths`** — exact paths that are hard-denied.
- **`bash_advisory`** — regexes (NSRegularExpression); a matching Bash command gates.
- **`mcp_allow`** — exactly-two-element `[server, tool]` pairs that pass.

## Glob semantics — READ THIS
Patterns use `fnmatch(pattern, path, 0)` — **no `FNM_PATHNAME`**. Consequences:
- `*` and `**` both cross `/`. `~/x/*` allows **arbitrary depth**, not one level. This is NOT
  gitignore/shell-globstar behavior; misreading it produces an *over-permissive* policy.
- Paths are matched **symlink-resolved** (realpath'd). Write **resolved** prefixes: use
  `/private/tmp/**`, not `/tmp/**`; `/private/var/...`, not `/var/...`. `_validate-policy` warns when
  an `allow_tier` prefix resolves elsewhere or doesn't exist.

## Residual risk of the default `__HOME__/**`
Everything under your home that isn't a `sensitive_glob` passes un-gated (the hook is best-effort and
a same-uid `echo > file` already bypasses it — but the Write/Edit gate is the visibility this tier
adds). The default gates the common code-exec/persistence and secret classes; if you add tools or
config outside those globs that you want gated, add them to `sensitive_globs`, or narrow `allow_tier`.
A blanket `allow_tier` (`**`, `/**`, `*`, `/*`) is rejected at install.
