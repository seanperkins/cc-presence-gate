#!/bin/bash
# scripts/userrun/touchid_accept.sh — cc-touch-id full-system acceptance (run AFTER install + enroll +
# activate). Mirrors scripts/userrun/task7_accept.sh (the SP1 FIDO acceptance script) for the SP2
# Touch ID backend: dir-custody of the design's primary adversary path, file-custody with
# broker-write-after-touch, the control-path denial, and audit integrity.
#
# Assumes the operator has ALREADY completed the install runbook (packaging/build-signed.sh -> the
# entitled, notarized/dev-signed .app; swift build -c release -> the plain daemon binary; sudo
# install/install.sh; cc-touch-id enroll [SE key + a TOUCH for the enrollment positive-control];
# sudo install/install.sh again to activate) — see plugins/cc-touch-id/skills/install/SKILL.md. This
# script does NOT install/enroll/activate; it only exercises the already-active system.
#
# IMPORTANT — TWO BINARIES, not one (unlike cc-fido): cc-touch-id ships a plain, ad-hoc-signed daemon
# binary at $CODE_DIR/cc-touch-id (verify-only; used by the LaunchDaemon, enroll-file/enroll-dir,
# _verify-audit, _validate-policy, and the control-path-denial canary below — none of those touch the
# Secure Enclave) AND a provisioned/entitled .app bundle at
# $CODE_DIR/cc-touch-id.app/Contents/MacOS/cc-touch-id (required for anything that SIGNS: `write`,
# `enroll`, the PreToolUse hook — a bare CLI binary is amfid-killed the instant it touches the SE key;
# see task0-se/REPORT.md and install/install.sh's own comment block). Using the wrong binary for a
# signing op will crash or hang instead of cleanly prompting — do not "simplify" the two BIN vars below.
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
CODE_DIR=/opt/cc-touch-id-gate
BIN="$CODE_DIR/cc-touch-id"                                   # plain — no Secure Enclave access
BIN_APP="$CODE_DIR/cc-touch-id.app/Contents/MacOS/cc-touch-id"  # entitled — required for `write` (signs)
KEY_DIR=/var/cctouchid
SERVICE_ACCOUNT=_cctouchid
LA="$HOME/Library/LaunchAgents"
BENIGN=/Users/Shared/cctouchid-accept.txt
FAILED=0
pass(){ echo "  PASS: $1"; }; fail(){ echo "  FAIL: $1"; FAILED=1; }

[ -x "$BIN" ] || { echo "ABORT: $BIN not found — run install/install.sh first"; exit 1; }
[ -x "$BIN_APP" ] || { echo "ABORT: $BIN_APP not found — the entitled .app is not installed; re-run install/install.sh with APP=<path to build-signed.sh's output>"; exit 1; }

echo "=== 1. enroll-dir the primary adversary path (~/Library/LaunchAgents) ==="
mkdir -p "$LA"
"$BIN" enroll-dir "$LA" || { echo "  enroll-dir failed — ABORT"; exit 1; }

echo "=== 2. agent-uid CANNOT create a plist in the enrolled dir (dir custody) ==="
touch "$LA/x.plist" 2>/dev/null && fail "created plist in locked dir" || pass "create denied in ~/Library/LaunchAgents"

echo "=== 3. enroll a benign file: direct write EACCES, broker write works after a TOUCH ==="
# Reset to a fresh, unlocked, caller-owned file so a re-run isn't blocked by a leftover uchg lock
# from a prior enroll (chown of a uchg'd file fails with Operation not permitted):
sudo chflags nouchg "$BENIGN" 2>/dev/null; sudo rm -f "$BENIGN"; echo before > "$BENIGN"
"$BIN" enroll-file "$BENIGN" || { echo "  enroll-file failed — ABORT"; exit 1; }
echo hostile > "$BENIGN" 2>/dev/null && fail "direct write succeeded (should be denied)" || pass "direct write denied (uchg/EACCES)"
echo ">>> A native Touch ID sheet will appear — TOUCH the sensor to APPROVE the write via the broker <<<"
printf 'ACCEPTED-VIA-BROKER' | "$BIN_APP" write "$BENIGN"
[ "$(sudo cat "$BENIGN" 2>/dev/null)" = "ACCEPTED-VIA-BROKER" ] && pass "broker write landed after touch" || fail "broker write after touch"

echo "=== 4. control-path write is DENIED with NO Touch ID prompt ==="
# Uses the PLAIN binary deliberately: the broker denies control paths before ever issuing a challenge
# (see Sources/CCGateCore/Broker.swift handleExecuteWrite's isControlPath check), so no signing is
# attempted and there is no risk of the amfid kill that a real signing attempt on the plain binary
# would hit. install/install.sh's own post-activate canary uses the same binary for the same reason.
OUT=$(printf 'x' | "$BIN" write "$KEY_DIR/allowed_signers" 2>&1 || true)
echo "$OUT" | grep -qi 'deny\|not an enrolled' && pass "control-path write denied (no prompt)" || { fail "control-path not denied"; echo "    $OUT"; }

echo "=== 5. audit chain valid AND at least one write_ok present (empty-chain guard) ==="
sudo -u "$SERVICE_ACCOUNT" "$BIN" _verify-audit && pass "audit chain OK" || fail "audit chain broken"
sudo grep -q '"event":"write_ok"' "$KEY_DIR/audit.log" && pass "write_ok event present" || fail "no write_ok event in log"

echo "=== 6. installed policy is portable + substituted (no placeholder, home present) ==="
sudo grep -q __HOME__ "$CODE_DIR/policy.json" && fail "installed policy still contains __HOME__" || pass "no __HOME__ placeholder survived"
sudo grep -q "\"$HOME/\*\*\"" "$CODE_DIR/policy.json" && pass "allow_tier substituted to \$HOME" || fail "allow_tier not substituted to \$HOME"
sudo "$BIN" _validate-policy "$CODE_DIR/policy.json" >/dev/null && pass "installed policy validates" || fail "installed policy does not validate"

echo "=== 7. a broken custom policy is REJECTED by validation (read-only; no install side-effects) ==="
printf '{"allow_tier":["("],"sensitive_globs":[],"locked_paths":[],"bash_advisory":["("],"mcp_allow":[]}' > /tmp/pol-bad.json
"$BIN" _validate-policy /tmp/pol-bad.json >/dev/null 2>&1 && fail "validation accepted a broken policy" || pass "broken policy rejected by _validate-policy"

echo
[ "$FAILED" = 0 ] && echo "RESULT: GREEN" || echo "RESULT: RED"
