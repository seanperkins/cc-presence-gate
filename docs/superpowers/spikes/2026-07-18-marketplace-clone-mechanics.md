# Spike: marketplace-clone mechanics for the cc-fido plugin bootstrap

**Date:** 2026-07-18
**Task:** SP1 Task 1 — gates Task 10's skill Step-0 binary bootstrap.
**Question:** When `cc-presence-gate` ships as a Claude Code marketplace and a user installs the
`cc-fido` plugin, does the install place the **whole repo tree** (so `${CLAUDE_PLUGIN_ROOT}/..`
reaches `Package.swift` and the skill can `swift build` in place) — or **only the
`plugins/cc-fido/` subtree**?

**Answer (load-bearing):** Under the planned `plugins/cc-fido/` subdir layout
(`"source": "./plugins/cc-fido"`), **only the plugin subtree ships in the plugin cache.**
`${CLAUDE_PLUGIN_ROOT}` points into a per-plugin cache dir that contains just the plugin's
`source` subtree — **not** the repo root, so `Package.swift` (a root-level SwiftPM manifest)
is NOT reachable from `${CLAUDE_PLUGIN_ROOT}`. The skill's Step-0 must therefore locate and
build the package another way (documented `git clone` + `swift build` prerequisite).

---

## Environment

- `claude` CLI present (shim); `claude plugin` exposes `install`, `list`, `details`,
  `marketplace {add,list,remove,update}`, `validate`, `enable/disable`, `init`, `eval`, `prune`.
- `claude plugin validate <dir>` works and expects `.claude-plugin/marketplace.json` or
  `.claude-plugin/plugin.json`. Run against this repo today it fails as expected (neither file
  exists yet — Task 10 creates them):

  ```
  $ claude plugin validate .
  Validating plugin manifest: /Users/sean/sites/cc-fido-gate
  ✘ directory: No manifest found in directory.
    Expected .claude-plugin/marketplace.json or .claude-plugin/plugin.json
  ```

## On-disk layout (observed)

Two distinct trees exist per installed marketplace:

| Tree | Path | Contents |
|---|---|---|
| **Marketplace clone** | `~/.claude/plugins/marketplaces/<mkt>/` | the **FULL repo** (`.git`, root files, all plugin dirs). Location recorded in `known_marketplaces.json` → `<mkt>.installLocation`. |
| **Plugin cache** | `~/.claude/plugins/cache/<mkt>/<plugin>/<version>/` | **only the plugin's `source` subtree**, copied out per version. This is what `${CLAUDE_PLUGIN_ROOT}` points at. |

### Evidence the plugin is served from the *cache* subtree (not the marketplace clone)

The `superpowers` skill loaded this session from:

```
/Users/sean/.claude/plugins/cache/claude-plugins-official/superpowers/6.1.1/skills/...
```

i.e. `${CLAUDE_PLUGIN_ROOT}` = `cache/<mkt>/<plugin>/<version>/`, **not** the
`marketplaces/<mkt>/` clone.

### Evidence the cache holds only the `source` subtree

`mobility-labs`'s `ml` plugin uses `"source": "./"` (plugin == repo root). Its cache copy equals
the marketplace clone's root exactly:

```
marketplace clone root:  commands hooks README.md skills
cache 0.2.0 root:        commands hooks README.md skills   # identical — because source is "./"
```

For a `"./"` source the subtree *is* the whole repo, so the cache happens to contain everything.
Change the source to a subdir (`"./plugins/cc-fido"`) and the cache would contain **only that
subdir** — the repo root (and a root-level `Package.swift`) would not be present under
`${CLAUDE_PLUGIN_ROOT}`, and `${CLAUDE_PLUGIN_ROOT}/../..` would resolve to
`cache/<mkt>/` (sibling plugins), not the repo.

Marketplace manifests in the wild confirm the subdir source shapes cc-fido will use — e.g.
`claude-plugins-official` mixes `./plugins/agent-sdk-dev` (relative subdir),
`git-subdir` (`path: plugins/<name>`), and whole-repo `url` sources. The relative/`git-subdir`
forms all key the cache per-plugin.

## Implication for cc-fido's SwiftPM package

The plan's Task 10 layout is a marketplace at repo root (`.claude-plugin/marketplace.json`) with
the plugin under `plugins/cc-fido/` (`"source": "./plugins/cc-fido"`). The SwiftPM package
(`Package.swift`, `Sources/`, `Tests/`) lives at the **repo root** — i.e. **above** the plugin
subtree. Consequently the package is **not shipped in the plugin cache** and cannot be built from
`${CLAUDE_PLUGIN_ROOT}`.

### Options considered

- **(A) Build from the marketplace clone** — `known_marketplaces.json`'s `installLocation` points
  at the full repo (`marketplaces/cc-presence-gate/`), which *does* contain `Package.swift`.
  Rejected as the primary path: it depends on undocumented internal Claude Code plugin-store
  layout that can change between versions, and on the marketplace being added under a predictable
  name.
- **(B) Documented `git clone` + `swift build` prerequisite** — the skill's Step-0 clones (or
  points at an existing clone of) the `cc-fido-gate` repo to a known working dir, runs
  `swift build -c release`, and the installer uses that `.build/release/cc-fido`. Robust: depends
  only on git + Swift toolchain, nothing internal to Claude Code. **Chosen as primary.**
- **(C) Self-contained plugin subtree** — move `Package.swift`/`Sources`/`Tests` under
  `plugins/cc-fido/` so the plugin cache is buildable in place. Rejected: contradicts the plan's
  chosen repo layout and the `cc-fido` product/binary-path contract the userrun scripts depend on;
  larger churn than SP1 warrants.

## Recommendation for Task 10 (skill Step-0 bootstrap)

Do **NOT** assume `${CLAUDE_PLUGIN_ROOT}/..` reaches `Package.swift`. Write Step-0 as a
**git-clone + build prerequisite (Option B)**:

1. Preflight the toolchain: `xcode-select -p` (for `swift`); Homebrew OpenSSH at the arch-correct
   prefix (ARM `/opt/homebrew/opt/openssh`, Intel `/usr/local/opt/openssh`).
2. Locate the repo root: use an existing local clone if the user has one; otherwise instruct a
   `git clone` of the `cc-fido-gate` repo to a known dir. (Optionally, *opportunistically* detect
   the marketplace clone at `known_marketplaces.json`'s `installLocation` and reuse it if present —
   but never depend on it.)
3. `swift build -c release` from that repo root; use `.build/release/cc-fido` as the binary the
   privileged installer codesigns/deploys.
4. Point `--policy` at `plugins/cc-fido/install/policy.json` (the Task-10 relocated path).

This keeps the bootstrap independent of Claude Code's internal plugin-store layout while still
delivering the plugin (skill + policy) through the marketplace.
