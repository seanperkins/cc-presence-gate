# Handoff — resume the guided-install build (cc-fido-gate)

You are continuing work on **cc-fido-gate** (a macOS tool that requires a physical FIDO/security-key touch
before Claude Code performs a high-risk action). Repo: `/Users/sean/sites/cc-fido-gate`. Swift + SwiftPM
(`swift build`, `swift test`). Commit style: conventional commits, committed directly on the working branch.

## Your immediate job

**Resume the subagent-driven execution of the "guided install" implementation plan.**
- Plan: `docs/superpowers/plans/2026-07-17-guided-install.md` (8 tasks)
- Spec: `docs/superpowers/specs/2026-07-17-guided-install-design.md`
- Branch: **`feat/guided-install`** (base `33c6938` on `main`)
- Skill to follow: **`superpowers:subagent-driven-development`** (invoke it first; it's the workflow).

### STEP 0 — orient before doing anything (a task was in flight when context was cleared)
Run these and trust them over any assumption:
```
git branch --show-current                 # should be feat/guided-install
git log --oneline 33c6938..HEAD           # commits already landed on the branch
cat .superpowers/sdd/progress.md          # the SDD ledger — tasks marked complete are DONE
ls .superpowers/sdd/task-*-report.md      # implementer/reviewer reports
swift test 2>&1 | grep Executed           # current test count/health
```
**Task 1 (the `Platform` seam) had an implementer subagent dispatched and may or may not have finished.**
Determine its state from `git log` + the ledger + `.superpowers/sdd/task-1-report.md`:
- If Task 1 **committed but the ledger doesn't mark it reviewed** → run the task review for it (below), fix
  Critical/Important, mark it complete, then continue at Task 2.
- If Task 1 **did not commit** (no `Platform.swift` in git, no report) → dispatch the Task 1 implementer fresh.
- If the ledger already marks Task 1 complete → resume at the first unmarked task.
Do NOT re-dispatch a task the ledger already marks complete.

## The per-task loop (Tasks 1→8), from the SDD skill
SDD scripts live at:
`/Users/sean/.claude/plugins/cache/claude-plugins-official/superpowers/6.1.1/skills/subagent-driven-development/scripts/`

For each task N:
1. Record `BASE` = current `git rev-parse --short HEAD` (the commit BEFORE this task — never `HEAD~1`).
2. `bash <scripts>/task-brief docs/superpowers/plans/2026-07-17-guided-install.md N` → prints a brief file path.
3. Dispatch an **implementer** subagent (model `sonnet`, `run_in_background: true`) with: one line on where the
   task fits; the brief path ("read this first — your requirements, exact code verbatim"); interfaces/decisions
   from earlier tasks it needs; a report-file path `.superpowers/sdd/task-N-report.md`; the report contract.
4. On DONE: `bash <scripts>/review-package BASE HEAD` → prints a diff file path. Dispatch a **task reviewer**
   (model `sonnet`) with the brief, the report, the diff-file path, and the plan's Global Constraints verbatim.
5. Dispatch a **fix** subagent for any Critical/Important findings; re-review. Record Minors in the ledger.
6. Append one line to `.superpowers/sdd/progress.md`: `Task N: complete (commit <sha>, review clean/…)`.
7. Next task.

After Task 8: dispatch the **whole-branch final review** on **`opus`** (template:
`…/skills/requesting-code-review/code-reviewer.md`) with `review-package $(git merge-base main HEAD) HEAD`.
Fix findings with ONE fix subagent. Then invoke **`superpowers:finishing-a-development-branch`** — the merge
decision is the user's (repo convention is merge to `main`, then the user hardware-verifies).

## Conventions / gotchas specific to this feature
- **Models:** implementers + task reviewers on `sonnet`; the final whole-branch review on `opus`.
- **The privileged Swift can't be unit-tested for real.** Tests use a `MockPlatform` (assert the right OS ops,
  right order, idempotency). NEVER run `sudo`/`dscl`/`launchctl`/`codesign` inside `swift test`. The real
  end-to-end install is **USER-RUN** (the `/cc-fido:install` skill drives it on the user's hardware, with
  sudo + a key touch) — you author + `swift test`/`bash -n` verify; the user runs the live flow.
- Every OS-specific string (`dscl`/`launchctl`/`chflags`/managed-settings path) must live ONLY in
  `MacOSPlatform` — the `Platform` seam is a hard constraint (a Linux port is a future spec).
- `Paths.code` already = `/opt/cc-fido-gate` (don't re-add). `renderPolicy`/`Policy` (policy),
  `renderPlist`/`renderManagedSettings`/`ccVersion` (`CLIHelpers.swift`), `connectSock` (`Client.swift`),
  `Broker().loadRegistry()` (enrolled targets), `runPrivileged`/`negativeBlinkTest` all already exist — reuse.
- The scripts being retired (Task 7) — `task7_install/enroll/teardown.sh` — are the source of the exact
  privileged command sequences; the plan already ports them. Keep `task7_accept.sh` (deep acceptance test).

## Where this sits in the bigger arc (context, not tasks)
- **Already shipped this session (on `main`, pushed):** the "configurable install policy" feature — portable
  `__HOME__`-templated policy, `_validate-policy`/`_render-policy` subcommands, widened default `sensitive_globs`,
  atomic root-owned install. Its spec/plan are in `docs/superpowers/`.
- **This feature (in progress):** guided install (the plan above).
- **Next specs (NOT started):** (1) a config-authoring skill `/cc-fido:policy` that interviews the admin and
  generates a validated `policy.json`; (2) plugin packaging (bundle binary + skills + commands). Both were
  agreed as follow-on specs — brainstorm each before implementing.
- Tracked non-blocking follow-ups: `docs/FOLLOWUPS.md`.

## Process rules (from the user's global config)
- Route TDD/implementer subagent work through `superpowers:test-driven-development`; route reviewer subagent
  work through the `code-review` skill; security passes through `security-review`.
- Anything needing `sudo` or a physical touch is USER-RUN — surface the exact command for the user to run
  (via `! <command>`), read their pasted output, then continue. Never assume a privileged step's result.
- Surface architecture forks with a recommendation (AskUserQuestion); the user makes the calls.
