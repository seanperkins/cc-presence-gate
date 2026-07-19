#!/bin/bash
# scripts/userrun/task7_cancel.sh — cancellation acceptance (run AFTER install + enroll + activate).
# Proves the deny paths of the softened WYSIWYS ceremony: an explicit Cancel and a 60s walk-away
# give-up must BOTH deny the gated write, leave the target byte-for-byte UNCHANGED, and require NO
# touch. This is the runtime proof of the Signer/CeremonyCanceller seam — the regression it exists to
# kill is a ceremony that hangs to the 90s backstop (or, worse, writes) when the human declines.
#
# [USER-RUN] Claude cannot run this: it needs sudo + you interacting with (declining) the dialog.
set -u
# Run as your LOGIN USER, not sudo: the client `cc-fido write` must run as you so it finds your
# enrolled key (~/.ccfido). Under an outer sudo it runs as root (HOME=/var/root, no key) and would
# "deny" for the wrong reason, invalidating the cancellation test. The script self-escalates internally.
if [ "$(id -u)" = 0 ]; then
  echo "ERROR: run this as your login user, NOT with sudo (it self-escalates internally)." >&2
  exit 2
fi
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
BIN=/opt/cc-fido-gate/cc-fido
BENIGN=/Users/Shared/ccfido-cancel.txt
BACKSTOP=90          # confirmAndSign's hard backstop (seconds) — the hang we must stay well under
FAILED=0
pass(){ echo "  PASS: $1"; }; fail(){ echo "  FAIL: $1"; FAILED=1; }

command -v "$BIN" >/dev/null 2>&1 || [ -x "$BIN" ] || { echo "ABORT: $BIN not found — install+activate first"; exit 1; }

echo "=== 0. reset + enroll a benign file target (no touch) ==="
# Fresh, unlocked, caller-owned file so a re-run isn't blocked by a leftover uchg lock from a prior run
# (chown of a uchg'd file fails with 'Operation not permitted'):
sudo chflags nouchg "$BENIGN" 2>/dev/null; sudo rm -f "$BENIGN"; echo BEFORE > "$BENIGN"
"$BIN" enroll-file "$BENIGN" || { echo "  enroll-file failed — ABORT (is it installed + active?)"; exit 1; }
BEFORE_SUM=$(sudo shasum -a 256 "$BENIGN" | cut -d' ' -f1)
echo "  target enrolled; baseline sha256=$BEFORE_SUM"

echo
echo "=== 1. CANCEL case — click Cancel, do NOT touch: must deny promptly, no write ==="
echo ">>> When the dialog appears, click CANCEL immediately. Do NOT touch the key. <<<"
START=$(date +%s)
printf 'HOSTILE-CANCEL' | "$BIN" write "$BENIGN"; RC=$?
ELAPSED=$(( $(date +%s) - START ))
echo "  (write returned rc=$RC after ${ELAPSED}s)"
[ "$RC" -ne 0 ] && pass "Cancel denied the write (rc=$RC != 0)" || fail "write returned 0 on Cancel — NOT denied"
# The regression this guards is a hang to the ~90s backstop; a real Cancel tears down in a second or two,
# plus your reaction time. Bar is 'well under the backstop', not a stopwatch on your click.
[ "$ELAPSED" -lt $((BACKSTOP - 30)) ] && pass "denied promptly (${ELAPSED}s, well under the ${BACKSTOP}s backstop)" \
    || fail "took ${ELAPSED}s — too close to the ${BACKSTOP}s backstop (did Cancel not cancel the signer?)"
AFTER_SUM=$(sudo shasum -a 256 "$BENIGN" | cut -d' ' -f1)
[ "$AFTER_SUM" = "$BEFORE_SUM" ] && pass "target UNCHANGED after Cancel (no write leaked)" \
    || fail "target CHANGED after Cancel — a write leaked through a declined ceremony!"

echo
echo "=== 2. GIVE-UP case — walk away, do NOTHING: dialog gives up (~60s), must deny, no write ==="
echo ">>> When the dialog appears, do NOTHING and do NOT touch the key. It gives up after ~60s. <<<"
B2=$(sudo shasum -a 256 "$BENIGN" | cut -d' ' -f1)
START2=$(date +%s)
printf 'HOSTILE-GIVEUP' | "$BIN" write "$BENIGN"; RC2=$?
ELAPSED2=$(( $(date +%s) - START2 ))
echo "  (write returned rc=$RC2 after ${ELAPSED2}s)"
[ "$RC2" -ne 0 ] && pass "give-up denied the write (rc=$RC2 != 0)" || fail "write returned 0 on give-up — NOT denied"
# Give-up fires at ~60s; it must resolve there, not ride the ~90s hard backstop.
[ "$ELAPSED2" -lt "$BACKSTOP" ] && pass "denied at the give-up (~60s: ${ELAPSED2}s), not the ${BACKSTOP}s backstop" \
    || fail "took ${ELAPSED2}s >= ${BACKSTOP}s — rode the hard backstop instead of the give-up"
A2=$(sudo shasum -a 256 "$BENIGN" | cut -d' ' -f1)
[ "$A2" = "$B2" ] && pass "target UNCHANGED after give-up (no write leaked)" \
    || fail "target CHANGED after give-up — a write leaked!"

echo
if [ "$FAILED" = 0 ]; then
  echo "RESULT: GREEN — Cancel and give-up both deny, no write, no touch."
else
  echo "RESULT: RED — a cancellation path did not deny cleanly (see FAILs above)."
fi
exit "$FAILED"
