#!/bin/bash
# scripts/userrun/task7_accept.sh — Step 10 full-system acceptance (run AFTER install + enroll).
# Exercises the live LaunchDaemon install end-to-end: dir-custody of the design's primary adversary
# path, file-custody with broker-write-after-touch, the C-3 control-path denial, and audit integrity.
set -u
# Run as your LOGIN USER, not sudo. The script escalates internally where it needs root; the
# "agent-uid cannot do X" checks (dir custody, direct-write EACCES, broker sign) are only valid
# when they run unprivileged. Under an outer sudo, root bypasses the barriers and the client's
# HOME becomes /var/root (no enrolled key) — producing false results.
if [ "$(id -u)" = 0 ]; then
  echo "ERROR: run this as your login user, NOT with sudo (it self-escalates internally)." >&2
  exit 2
fi
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
BIN=/opt/cc-fido-gate/cc-fido
LA="$HOME/Library/LaunchAgents"
BENIGN=/Users/Shared/ccfido-accept.txt
FAILED=0
pass(){ echo "  PASS: $1"; }; fail(){ echo "  FAIL: $1"; FAILED=1; }

echo "=== 1. enroll-dir the primary adversary path (~/Library/LaunchAgents) ==="
mkdir -p "$LA"
"$BIN" enroll-dir "$LA" || { echo "  enroll-dir failed — ABORT"; exit 1; }

echo "=== 2. agent-uid CANNOT create a plist in the enrolled dir (C-3 dir custody) ==="
touch "$LA/x.plist" 2>/dev/null && fail "created plist in locked dir" || pass "create denied in ~/Library/LaunchAgents"

echo "=== 3. enroll a benign file: direct write EACCES, broker write works after a touch ==="
# Reset to a fresh, unlocked, caller-owned file so a re-run isn't blocked by a leftover uchg lock
# from a prior enroll (chown of a uchg'd file fails with Operation not permitted):
sudo chflags nouchg "$BENIGN" 2>/dev/null; sudo rm -f "$BENIGN"; echo before > "$BENIGN"
"$BIN" enroll-file "$BENIGN" || { echo "  enroll-file failed — ABORT"; exit 1; }
echo hostile > "$BENIGN" 2>/dev/null && fail "direct write succeeded (should be denied)" || pass "direct write denied (uchg/EACCES)"
echo ">>> APPROVE + TOUCH to write via the broker <<<"
printf 'ACCEPTED-VIA-BROKER' | "$BIN" write "$BENIGN"
[ "$(sudo cat "$BENIGN" 2>/dev/null)" = "ACCEPTED-VIA-BROKER" ] && pass "broker write landed after touch" || fail "broker write after touch"

echo "=== 4. C-3: cc-fido write to a control path is DENIED with NO touch prompt ==="
OUT=$(printf 'x' | "$BIN" write /var/ccfido/allowed_signers 2>&1 || true)
echo "$OUT" | grep -qi 'deny\|not an enrolled' && pass "control-path write denied (no prompt)" || { fail "control-path not denied"; echo "    $OUT"; }

echo "=== 5. audit chain valid AND at least one write_ok present (empty-chain guard) ==="
sudo -u _ccfido "$BIN" _verify-audit && pass "audit chain OK" || fail "audit chain broken"
sudo grep -q '"event":"write_ok"' /var/ccfido/audit.log && pass "write_ok event present" || fail "no write_ok event in log"

echo "=== 6. installed policy is portable + substituted (no placeholder, home present) ==="
sudo grep -q __HOME__ /opt/cc-fido-gate/policy.json && fail "installed policy still contains __HOME__" || pass "no __HOME__ placeholder survived"
sudo grep -q "\"$HOME/\*\*\"" /opt/cc-fido-gate/policy.json && pass "allow_tier substituted to \$HOME" || fail "allow_tier not substituted to \$HOME"
sudo /opt/cc-fido-gate/cc-fido _validate-policy /opt/cc-fido-gate/policy.json >/dev/null && pass "installed policy validates" || fail "installed policy does not validate"

echo "=== 7. a broken custom policy is REJECTED by validation (read-only; no install side-effects) ==="
# (Was a call to a since-removed task7_install.sh, which made this vacuously pass. Test the real
# rejection logic via the read-only _validate-policy subcommand instead — same fail-closed parser
# the installer runs, with no risk to the live policy.)
printf '{"allow_tier":["("],"sensitive_globs":[],"locked_paths":[],"bash_advisory":["("],"mcp_allow":[]}' > /tmp/pol-bad.json
"$BIN" _validate-policy /tmp/pol-bad.json >/dev/null 2>&1 && fail "validation accepted a broken policy" || pass "broken policy rejected by _validate-policy"

echo
[ "$FAILED" = 0 ] && echo "RESULT: GREEN" || echo "RESULT: RED"
