#!/bin/bash
# packaging/build-signed.sh — build the AUTHOR-MACHINE cc-touch-id.app.
#
# [USER-RUN] — needs a full Xcode with this Mac registered against team HH3SJBAS42 (for automatic
# provisioning). Hand it to the human on the signing machine; an agent sandbox cannot run it.
#
# WHY THIS IS THE AUTHOR-MACHINE BUILD (not notarized distribution):
#   The Secure Enclave key needs the `keychain-access-groups` entitlement, and on macOS THAT
#   entitlement must be authorized by an embedded PROVISIONING PROFILE — it cannot be self-asserted
#   in a bare Developer ID signature. An entitled binary whose keychain-access-group is not authorized
#   by a profile is amfid-killed at launch (SIGKILL / rc 137 — empirically confirmed on this machine).
#   The only macOS profile available here is the Development wildcard profile, which MANDATES
#   `com.apple.security.get-task-allow`. Xcode automatic signing embeds that profile + the entitlement
#   + get-task-allow, producing a .app that LAUNCHES and can create/use the SE key on THIS machine.
#
#   An earlier version of this script then Developer-ID re-signed the app and stripped get-task-allow
#   (for notarized distribution / TID-5). That BREAKS it: the Development profile no longer matches the
#   signature and no longer has its required get-task-allow -> amfid SIGKILL. So we do NOT re-sign.
#
#   True notarized DISTRIBUTION (get-task-allow stripped, runs on other Macs, Gatekeeper-clean) needs a
#   *Developer ID* provisioning profile that authorizes keychain-access-groups — extra Apple-portal
#   setup. That path is DEFERRED and tracked in docs/FOLLOWUPS.md (see "Developer-ID distribution").
#
# Usage: bash packaging/build-signed.sh   (from anywhere — paths are self-relative)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PACKAGING_DIR="$REPO_ROOT/packaging"

echo "=== packaging/build-signed.sh: author-machine cc-touch-id.app ==="

# --- a. project generation ---------------------------------------------------------------------
echo "--- Step a: xcodegen generate (or use the committed .xcodeproj) ---"
cd "$PACKAGING_DIR"
if command -v xcodegen >/dev/null 2>&1; then
  xcodegen generate
else
  echo "xcodegen not found on PATH — using committed .xcodeproj (packaging/CCTouchIDGate.xcodeproj)"
fi

# --- b. build (Xcode automatic signing: Developer ID cert + Development profile + get-task-allow) ---
echo "--- Step b: xcodebuild (Release, automatic signing, provisioned) ---"
DERIVED_DATA="$PACKAGING_DIR/.dd"
rm -rf "$DERIVED_DATA"
xcodebuild -project "$PACKAGING_DIR/CCTouchIDGate.xcodeproj" -scheme cc-touch-id -configuration Release \
  -derivedDataPath "$DERIVED_DATA" -allowProvisioningUpdates build

APP="$DERIVED_DATA/Build/Products/Release/cc-touch-id.app"
if [ ! -d "$APP" ]; then
  APP="$(find "$DERIVED_DATA" -type d -name 'cc-touch-id.app' -path '*/Release/*' 2>/dev/null | head -1)"
fi
if [ -z "${APP:-}" ] || [ ! -d "$APP" ]; then
  echo "FAIL: could not locate built cc-touch-id.app under $DERIVED_DATA" >&2
  exit 1
fi
echo "built: $APP"

# --- c. sanity-verify the author-machine build (this is the check the earlier script lacked) ------
# NOTE: capture codesign output into a var THEN grep it — a `codesign ... | grep -q` pipeline under
# `set -o pipefail` false-fails, because `grep -q` closes the pipe on first match and codesign then
# dies with SIGPIPE, which pipefail reports as a failed pipeline.
echo "--- Step c: sanity-verify (signed + profile-embedded + entitled + LAUNCHES) ---"
SIG_OUT="$(codesign -dvvv "$APP" 2>&1 || true)"
case "$SIG_OUT" in *Authority=*) : ;; *) echo "FAIL: app is not code-signed" >&2; exit 1 ;; esac
[ -f "$APP/Contents/embedded.provisionprofile" ] \
  || { echo "FAIL: no embedded provisioning profile — the SE keychain-access-group would be unauthorized -> amfid kill" >&2; exit 1; }
ENT_OUT="$(codesign -d --entitlements - "$APP" 2>/dev/null || true)"
case "$ENT_OUT" in *keychain-access-groups*) : ;; *) echo "FAIL: keychain-access-groups entitlement missing from the build" >&2; exit 1 ;; esac
# The decisive check: does the entitled binary survive AMFI at launch? (status = no touch, read-only)
if ! "$APP/Contents/MacOS/cc-touch-id" status --json >/dev/null 2>&1; then
  echo "FAIL: the built app is amfid-killed at launch (rc $?). The provisioning/entitlement combo is wrong;" >&2
  echo "      do NOT install it — it will SIGKILL on 'enroll'. See the header + docs/FOLLOWUPS.md." >&2
  exit 1
fi
echo "PASS: signed + provisioned + entitled + launches"

# --- d. done ------------------------------------------------------------------------------------
echo "=== build-signed.sh complete ==="
echo "author-machine .app: $APP"
echo "NOTE: NOT notarized for distribution (get-task-allow present, Development profile). Runs on THIS"
echo "      Mac only. True Developer-ID distribution is deferred — see docs/FOLLOWUPS.md."
