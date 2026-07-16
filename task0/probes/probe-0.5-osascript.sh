#!/bin/bash
# Task 0.5 — does `osascript` render a dialog under a scrubbed env?
#
# Goal: find the minimal env -i allowlist that BOTH renders the native dialog
# AND drops injection vectors (DYLD_*, PATH, NODE_OPTIONS, BASH_ENV, SSH_*).
# Each dialog self-dismisses after 1s (`giving up after 1`) to minimize screen
# intrusion. SUCCESS = osascript exits 0 and returns a dialog result; FAIL =
# non-zero / "Application isn't running" / -1743 style WindowServer error.
set -u
OSA=/usr/bin/osascript
SCRIPT='display dialog "cc-fido-gate task0.5 probe (auto-dismiss)" buttons {"OK"} default button "OK" giving up after 1'

# NOTE: osascript's default language on this box is JavaScript (JXA), so force
# AppleScript with -l. `display dialog` also needs StandardAdditions, which will
# not load under a sandbox-exec (that + -10810 app-launch errors are how the
# sandbox manifests) — run this probe with the sandbox DISABLED, matching how CC
# actually launches a PreToolUse hook (un-sandboxed).
try() {  # label; rest = env assignments (the env prefix)
  local label="$1"; shift
  echo "=== $label ==="
  # shellcheck disable=SC2068
  out=$("$@" $OSA -l AppleScript -e "$SCRIPT" 2>&1); rc=$?
  echo "exit=$rc out=$out"
  echo
}

echo "## baseline: full inherited env"
try "full-env" env

echo "## empty scrub (expect FAIL if WindowServer needs anything)"
try "env -i (empty)" env -i

echo "## allowlist candidate A: USER HOME __CF_USER_TEXT_ENCODING"
try "env -i +USER+HOME+CFENC" env -i \
  USER="$USER" HOME="$HOME" __CF_USER_TEXT_ENCODING="${__CF_USER_TEXT_ENCODING:-0x1F5:0x0:0x0}"

echo "## allowlist candidate B: A + LANG (locale)"
try "env -i +A+LANG" env -i \
  USER="$USER" HOME="$HOME" __CF_USER_TEXT_ENCODING="${__CF_USER_TEXT_ENCODING:-0x1F5:0x0:0x0}" \
  LANG="${LANG:-en_US.UTF-8}"

echo "Note: the process bootstrap/Mach session port (WindowServer access) is inherited"
echo "through the process tree, not via an env var — so an env -i child of this GUI-"
echo "session process may still reach WindowServer. That is what these cases measure."
