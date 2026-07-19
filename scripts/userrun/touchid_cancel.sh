#!/bin/bash
# scripts/userrun/touchid_cancel.sh — cc-touch-id cancellation acceptance (run AFTER install + enroll
# + activate). Mirrors scripts/userrun/task7_cancel.sh (the SP1 FIDO cancel script) for the SP2 Touch
# ID backend: an explicit Cancel on the native Touch ID sheet AND a walk-away give-up must BOTH deny
# the gated write, leave the target byte-for-byte UNCHANGED (content + mtime), and require NO
# successful touch. This is the runtime proof of TouchIdCeremony/TouchIDCanceller — the regression it
# exists to kill is a ceremony that writes (or hangs forever) when the human declines or ignores it.
#
# DESIGN NOTE — read before running: unlike cc-fido's ceremony (an osascript dialog with its own
# ~60s give-up and a ~90s hard backstop, both client-side and code-defined in FidoCeremony.swift),
# the Touch ID ceremony has NO client-side backstop of its own. TouchIdCeremony.confirmAndSign
# (Sources/CCTouchIDBackend/TouchIdCeremony.swift) calls seSign() straight into
# SecKeyCreateSignature — the NATIVE macOS Touch ID sheet IS the presence ceremony; there is no app
# code wrapping it with a timer. Cancellation for the Cancel case is the sheet's own Cancel button
# (returns errSecUserCanceled immediately). For the give-up (walk-away) case, nothing in this
# repo's Touch ID code enforces a timeout — the only CODE-DEFINED numeric backstop anywhere in the
# path is the BROKER's (server-side, shared with cc-fido) wall-clock deadline:
#   Sources/CCGateCore/Broker.swift: `static let ceremonyDeadline: TimeInterval = 90`
# which drops the daemon-side connection ~90s after the challenge was issued if no valid signature
# has arrived. Whether the walked-away sheet resolves sooner than that is governed by macOS's own
# (undocumented-in-this-repo) Touch ID sheet timeout, not by anything this codebase controls. So
# "eventually denies" in the give-up case below is NOT a tight, code-guaranteed bound the way FIDO's
# is — this script MEASURES the elapsed wall-clock time and reports it so the operator can see what
# "eventually" actually means on this machine/OS version, rather than asserting a specific number.
#
# [USER-RUN] Claude cannot run this: it needs sudo + you interacting with (declining, or ignoring)
# the native Touch ID sheet.
set -u
# Run as your LOGIN USER, not sudo: the client `cc-touch-id write` must run as you so it finds your
# enrolled Secure Enclave key (keychain, tag com.seanperkins.cc-touch-id.key) and your enrolled
# custody. Under an outer sudo it runs as root (HOME=/var/root, no key) and would "deny" for the
# wrong reason, invalidating the cancellation test. The script self-escalates internally.
if [ "$(id -u)" = 0 ]; then
  echo "ERROR: run this as your login user, NOT with sudo (it self-escalates internally)." >&2
  exit 2
fi
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
CODE_DIR=/opt/cc-touch-id-gate
BIN="$CODE_DIR/cc-touch-id"                                    # plain — no Secure Enclave access
BIN_APP="$CODE_DIR/cc-touch-id.app/Contents/MacOS/cc-touch-id"   # entitled — required for `write` (signs)
BENIGN=/Users/Shared/cctouchid-cancel.txt
DAEMON_DEADLINE=90   # Broker.ceremonyDeadline (Sources/CCGateCore/Broker.swift) — the only code-defined
                      # backstop in this path; shared with cc-fido, server-side, NOT a client timer.
FAILED=0
pass(){ echo "  PASS: $1"; }; fail(){ echo "  FAIL: $1"; FAILED=1; }

[ -x "$BIN" ] || { echo "ABORT: $BIN not found — install+activate first"; exit 1; }
[ -x "$BIN_APP" ] || { echo "ABORT: $BIN_APP not found — the entitled .app is not installed; re-run install/install.sh with APP=<path>"; exit 1; }

echo "=== 0. reset + enroll a benign file target (no touch) ==="
# Fresh, unlocked, caller-owned file so a re-run isn't blocked by a leftover uchg lock from a prior run
# (chown of a uchg'd file fails with 'Operation not permitted'):
sudo chflags nouchg "$BENIGN" 2>/dev/null; sudo rm -f "$BENIGN"; echo BEFORE > "$BENIGN"
"$BIN" enroll-file "$BENIGN" || { echo "  enroll-file failed — ABORT (is it installed + active?)"; exit 1; }
BEFORE_SUM=$(sudo shasum -a 256 "$BENIGN" | cut -d' ' -f1)
BEFORE_MTIME=$(sudo stat -f %m "$BENIGN")
echo "  target enrolled; baseline sha256=$BEFORE_SUM mtime=$BEFORE_MTIME"

echo
echo "=== 1. CANCEL case — click Cancel / press Escape on the Touch ID sheet, do NOT touch the sensor ==="
echo ">>> A native Touch ID sheet will appear. Click CANCEL (or press Escape) immediately. Do NOT touch the sensor. <<<"
START=$(date +%s)
printf 'HOSTILE-CANCEL' | "$BIN_APP" write "$BENIGN"; RC=$?
ELAPSED=$(( $(date +%s) - START ))
echo "  (write returned rc=$RC after ${ELAPSED}s)"
[ "$RC" -ne 0 ] && pass "Cancel denied the write (rc=$RC != 0)" || fail "write returned 0 on Cancel — NOT denied"
# The native sheet's own Cancel button tears down immediately (errSecUserCanceled); this bound is a
# generous margin for your reaction time, NOT tied to any fixed backstop constant (there isn't one
# client-side for Touch ID — see the design note above).
[ "$ELAPSED" -lt 30 ] && pass "denied promptly (${ELAPSED}s — well under the ${DAEMON_DEADLINE}s broker deadline)" \
    || fail "took ${ELAPSED}s — unexpectedly slow for an explicit Cancel (did the sheet actually cancel?)"
AFTER_SUM=$(sudo shasum -a 256 "$BENIGN" | cut -d' ' -f1)
AFTER_MTIME=$(sudo stat -f %m "$BENIGN")
[ "$AFTER_SUM" = "$BEFORE_SUM" ] && pass "target content UNCHANGED after Cancel (no write leaked)" \
    || fail "target content CHANGED after Cancel — a write leaked through a declined ceremony!"
[ "$AFTER_MTIME" = "$BEFORE_MTIME" ] && pass "target mtime UNCHANGED after Cancel" \
    || fail "target mtime CHANGED after Cancel (was $BEFORE_MTIME, now $AFTER_MTIME) — something touched the file!"

echo
echo "=== 2. GIVE-UP case — walk away, do NOTHING at all: no client-side timer exists for Touch ID ==="
echo ">>> A native Touch ID sheet will appear. Walk away / do NOTHING. Do NOT touch the sensor, do NOT click Cancel. <<<"
echo ">>> This command will NOT return until either the sheet gives up on its own or the broker's <<<"
echo ">>> ${DAEMON_DEADLINE}s ceremony deadline drops the connection — it may take up to roughly that long. <<<"
echo ">>> If it appears to hang well past ~$((DAEMON_DEADLINE * 2))s, Ctrl-C and treat this as a FAIL to investigate <<<"
echo ">>> (that would mean neither the sheet nor the broker deadline ever unblocked it). <<<"
B2_SUM=$(sudo shasum -a 256 "$BENIGN" | cut -d' ' -f1)
B2_MTIME=$(sudo stat -f %m "$BENIGN")
START2=$(date +%s)
printf 'HOSTILE-GIVEUP' | "$BIN_APP" write "$BENIGN"; RC2=$?
ELAPSED2=$(( $(date +%s) - START2 ))
echo "  (write returned rc=$RC2 after ${ELAPSED2}s)"
if [ "$ELAPSED2" -lt "$DAEMON_DEADLINE" ]; then
  echo "  TIMING: resolved in ${ELAPSED2}s, before the ${DAEMON_DEADLINE}s broker deadline — the native Touch ID sheet's own timeout governed."
elif [ "$ELAPSED2" -lt $((DAEMON_DEADLINE + 15)) ]; then
  echo "  TIMING: resolved at ${ELAPSED2}s, right around the ${DAEMON_DEADLINE}s broker deadline — Broker.ceremonyDeadline governed."
else
  echo "  TIMING: resolved at ${ELAPSED2}s, well past the ${DAEMON_DEADLINE}s broker deadline — unexpected; note this for follow-up."
fi
[ "$RC2" -ne 0 ] && pass "give-up denied the write (rc=$RC2 != 0)" || fail "write returned 0 on give-up — NOT denied"
A2_SUM=$(sudo shasum -a 256 "$BENIGN" | cut -d' ' -f1)
A2_MTIME=$(sudo stat -f %m "$BENIGN")
[ "$A2_SUM" = "$B2_SUM" ] && pass "target content UNCHANGED after give-up (no write leaked)" \
    || fail "target content CHANGED after give-up — a write leaked!"
[ "$A2_MTIME" = "$B2_MTIME" ] && pass "target mtime UNCHANGED after give-up" \
    || fail "target mtime CHANGED after give-up (was $B2_MTIME, now $A2_MTIME) — something touched the file!"

echo
if [ "$FAILED" = 0 ]; then
  echo "RESULT: GREEN — Cancel and give-up both deny, no write, no touch. Give-up took ${ELAPSED2}s (see TIMING above)."
else
  echo "RESULT: RED — a cancellation path did not deny cleanly (see FAILs above)."
fi
exit "$FAILED"
