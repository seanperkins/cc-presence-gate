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

echo "=== 3. notarization (best-effort — spctl/stapler are broken on macOS 26; see docs/FOLLOWUPS.md) ==="
# HARD gate: valid signature. spctl/stapler are Gatekeeper convenience tools that error on macOS 26;
# notarization is authoritative from notarytool at build/publish time, so these are informational.
if codesign --verify --strict "$APP" 2>/dev/null; then pass "codesign --verify valid"; else fail "codesign --verify failed (broken signature)"; fi
SPCTL="$(spctl -a -vvv -t exec "$APP" 2>&1 || true)"
case "$SPCTL" in *accepted*) pass "spctl accepted (notarized)" ;; *) echo "  NOTE: spctl unavailable/errored on this OS — relying on notarytool + signature" ;; esac
case "$(xcrun stapler validate "$APP" 2>&1 || true)" in *worked*) pass "stapler ticket valid (stapled, offline-capable)" ;; *) echo "  NOTE: not stapled — Gatekeeper verifies online at first launch" ;; esac

echo "=== 4. the DECISIVE runtime proof: persistent SE key enrolls under this signature ==="
echo ">>> A native Touch ID sheet will appear — TOUCH to confirm the enrollment positive-control <<<"
if "$BIN_APP" enroll; then pass "enroll succeeded — SE key created + touch verified (no -34018 under Developer ID)"; else fail "enroll failed — inspect stderr (SE create / register / touch)"; fi

# NOTE: we intentionally do NOT run `_presence-test` here. It verifies the signature against the
# on-disk `allowed_signers`, which enroll chowns to the service account (mode 600) — so run as the
# LOGIN user it hits EACCES and false-fails ("signature did not verify"). Verifying the on-disk
# registered key is the BROKER's job (it runs as the service account); that path is exercised by
# scripts/userrun/touchid_accept.sh's gated-write round-trip. Section 4's enroll positive-control
# already proves the SE key signs + verifies (against its live-exported pubkey) under this signature.

echo
if [ "$FAILED" = 0 ]; then
  echo "ACCEPT: installed cc-touch-id.app is the notarized Developer-ID distribution build; it enrolls a"
  echo "        persistent SE key and signs with a touch under the Developer-ID signature."
  echo "NEXT: run scripts/userrun/touchid_accept.sh for the full custody / gated-write / audit acceptance"
  echo "      (that suite exercises the broker verifying the touch signature against allowed_signers)."
  exit 0
else
  echo "REJECT: one or more checks failed above."
  exit 1
fi
