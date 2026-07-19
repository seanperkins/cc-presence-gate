#!/bin/bash
# scripts/userrun/touchid_notarize_accept.sh — acceptance for the NOTARIZED Developer-ID distribution
# build (packaging/build-distribution.sh). Confirms the INSTALLED cc-touch-id.app is the real
# distributable artifact — Developer ID signed, hardened runtime, get-task-allow ABSENT (TID-5),
# Developer ID profile embedded, notarized + stapled (Gatekeeper-clean offline) — and that a persistent
# Secure Enclave key still enrolls + signs under that signature (the -34018 that a bare Developer ID
# signature hits must be GONE). See docs/superpowers/specs/2026-07-19-*-notarized-distribution-*.md
# and the RESOLVED entry in docs/FOLLOWUPS.md for why each check matters.
#
# [USER-RUN] — needs the installed .app + a real TOUCH; an agent sandbox cannot run it. Prereq: install
# the stapled build from build-distribution.sh to $CODE_DIR (replacing any author-machine build), then
# run this as your LOGIN USER (it self-escalates only for the sudo reads it needs). This script does the
# distribution-signature + enroll/sign acceptance ONLY; run scripts/userrun/touchid_accept.sh afterward
# for the full custody / gated-write / audit suite (it is not duplicated here).
set -u
if [ "$(id -u)" = 0 ]; then
  echo "ERROR: run as your login user, NOT sudo (enroll needs your keychain + a touch)." >&2
  exit 2
fi
CODE_DIR=/opt/cc-touch-id-gate
APP="$CODE_DIR/cc-touch-id.app"
BIN_APP="$APP/Contents/MacOS/cc-touch-id"   # entitled/provisioned binary — required to sign (SE)
FAILED=0
pass(){ echo "  PASS: $1"; }
fail(){ echo "  FAIL: $1"; FAILED=1; }

[ -d "$APP" ] || { echo "ABORT: $APP not found — install the notarized build first (build-distribution.sh output)"; exit 1; }
[ -x "$BIN_APP" ] || { echo "ABORT: $BIN_APP not found"; exit 1; }

echo "=== 1. signature: Developer ID + hardened runtime + embedded profile ==="
SIG="$(codesign -dvvv "$APP" 2>&1 || true)"
case "$SIG" in *"Developer ID Application"*) pass "Developer ID signed" ;; *) fail "NOT Developer ID signed (author-machine build still installed?)" ;; esac
case "$SIG" in *runtime*) pass "hardened runtime enabled" ;; *) fail "hardened runtime missing" ;; esac
[ -f "$APP/Contents/embedded.provisionprofile" ] && pass "provisioning profile embedded" || fail "no embedded provisioning profile"

echo "=== 2. entitlements: access group present, get-task-allow ABSENT (TID-5) ==="
ENT="$(codesign -d --entitlements :- "$APP" 2>/dev/null || true)"
case "$ENT" in *get-task-allow*) fail "get-task-allow PRESENT — same-uid debuggable, not TID-5 clean" ;; *) pass "get-task-allow absent" ;; esac
case "$ENT" in *keychain-access-groups*|*application-identifier*) pass "access-group entitlement present (SE key can persist)" ;; *) fail "no access-group entitlement — SE key would hit -34018" ;; esac

echo "=== 3. notarization: Gatekeeper-clean offline (fresh-Mac simulation) ==="
if spctl -a -vvv -t exec "$APP" 2>&1 | grep -q 'accepted'; then pass "spctl accepted"; else fail "spctl rejected — not notarized/stapled"; fi
if xcrun stapler validate "$APP" 2>&1 | grep -q 'worked'; then pass "stapler ticket valid (stapled)"; else fail "stapler validate failed — ticket not stapled"; fi

echo "=== 4. the DECISIVE runtime proof: persistent SE key enrolls under this signature ==="
echo ">>> A native Touch ID sheet will appear — TOUCH to confirm the enrollment positive-control <<<"
if "$BIN_APP" enroll; then pass "enroll succeeded — SE key created + touch verified (no -34018 under Developer ID)"; else fail "enroll failed — inspect stderr (SE create / register / touch)"; fi

echo "=== 5. presence test: the enrolled key requires a live finger + round-trips the verifier ==="
echo ">>> TOUCH again for the presence test <<<"
if "$BIN_APP" _presence-test; then pass "presence test verified"; else fail "presence test failed"; fi

echo
if [ "$FAILED" = 0 ]; then
  echo "ACCEPT: installed cc-touch-id.app is the notarized Developer-ID distribution build and fully functional."
  echo "NEXT: run scripts/userrun/touchid_accept.sh for the full custody / gated-write / audit acceptance."
  exit 0
else
  echo "REJECT: one or more checks failed above."
  exit 1
fi
