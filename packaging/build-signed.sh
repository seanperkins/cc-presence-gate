#!/bin/bash
# packaging/build-signed.sh — build, Developer-ID re-sign, and notarize the provisioned cc-touch-id.app.
#
# [USER-RUN] — this script needs things Claude's sandbox cannot provide: the Developer ID Application
# private key in the local keychain, network access to Apple's notary service, and (for xcodegen/
# xcodebuild) a full Xcode install with this Mac registered against team HH3SJBAS42. Do not attempt to
# run this from an agent session — hand it to the human on the signing machine.
#
# What "done" looks like, and why: the SAME binary serves every cc-touch-id role (daemon/hook/write/
# enroll), but only the hook/write/enroll roles ever touch the Secure Enclave key, and SE access needs
# the keychain-access-group entitlement + a real code identity — a bare, ad-hoc-signed CLI is
# amfid-killed the moment it calls SecKeyCreateRandomKey with that entitlement (see
# task0-se/REPORT.md). Xcode's automatic-signing build (step 2) produces a LOCALLY valid, provisioned
# .app that can create/use the SE key on THIS machine. To run on other machines (or survive Gatekeeper
# on a clean install) it additionally needs a Developer ID re-sign + notarization + staple (steps 3-5).
# The Developer-ID+SE+keychain-access-group combination this script produces is validated end-to-end
# on-device by `cc-touch-id enroll` in Task 11 (USER-RUN, needs a real touch) — this script only proves
# the artifact is correctly *signed*, not that the SE key ceremony actually round-trips.
#
# Usage: bash packaging/build-signed.sh   (run from the repo root, or anywhere — paths are self-relative)
set -euo pipefail

DEV_ID_IDENTITY="Developer ID Application: Sean Perkins (HH3SJBAS42)"
NOTARY_PROFILE="cc-touch-id-notary"
TEAM_PREFIXED_GROUP="HH3SJBAS42.com.seanperkins.cc-touch-id"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PACKAGING_DIR="$REPO_ROOT/packaging"
DIST_ENTITLEMENTS="$PACKAGING_DIR/CCTouchID.distribution.entitlements"

echo "=== packaging/build-signed.sh: provisioned + notarized cc-touch-id.app ==="

# --- a. project generation -------------------------------------------------------------------
echo "--- Step a: xcodegen generate (or use the committed .xcodeproj) ---"
cd "$PACKAGING_DIR"
if command -v xcodegen >/dev/null 2>&1; then
  xcodegen generate
else
  echo "xcodegen not found on PATH — using committed .xcodeproj (packaging/CCTouchIDGate.xcodeproj)"
fi

# --- b. build ----------------------------------------------------------------------------------
echo "--- Step b: xcodebuild (Release, automatic signing, provisioned) ---"
DERIVED_DATA="$PACKAGING_DIR/.dd"
rm -rf "$DERIVED_DATA"
xcodebuild -project "$PACKAGING_DIR/CCTouchIDGate.xcodeproj" -scheme cc-touch-id -configuration Release \
  -derivedDataPath "$DERIVED_DATA" -allowProvisioningUpdates build

APP="$DERIVED_DATA/Build/Products/Release/cc-touch-id.app"
if [ ! -d "$APP" ]; then
  # Fall back to a search in case xcodebuild placed it somewhere unexpected under derivedDataPath.
  APP="$(find "$DERIVED_DATA" -type d -name 'cc-touch-id.app' -path '*/Release/*' 2>/dev/null | head -1)"
fi
if [ -z "${APP:-}" ] || [ ! -d "$APP" ]; then
  echo "FAIL: could not locate built cc-touch-id.app under $DERIVED_DATA" >&2
  exit 1
fi
echo "built: $APP"

# --- c. Developer-ID re-sign (deep) -------------------------------------------------------------
echo "--- Step c: Developer-ID re-sign (deep, hardened runtime, timestamp) ---"
codesign --force --deep --options runtime --timestamp \
  --entitlements "$DIST_ENTITLEMENTS" \
  --sign "$DEV_ID_IDENTITY" \
  "$APP"

# --- d. verify -----------------------------------------------------------------------------------
echo "--- Step d: verify signature + entitlements ---"
CODESIGN_DVVV_OUT="$(mktemp -t cc-touch-id-codesign-dvvv)"
trap 'rm -f "$CODESIGN_DVVV_OUT"' EXIT
codesign -dvvv "$APP" 2>&1 | tee "$CODESIGN_DVVV_OUT"
if ! grep -q "Authority=$DEV_ID_IDENTITY" "$CODESIGN_DVVV_OUT"; then
  echo "FAIL: codesign -dvvv did not show Developer ID authority '$DEV_ID_IDENTITY'" >&2
  exit 1
fi
echo "PASS: signed by $DEV_ID_IDENTITY"

ENTITLEMENTS_OUT="$(codesign -d --entitlements - "$APP" 2>/dev/null)"
if ! printf '%s' "$ENTITLEMENTS_OUT" | grep -q "$TEAM_PREFIXED_GROUP"; then
  echo "FAIL: re-signed app entitlements missing keychain-access-group $TEAM_PREFIXED_GROUP" >&2
  echo "$ENTITLEMENTS_OUT" >&2
  exit 1
fi
echo "PASS: keychain-access-group $TEAM_PREFIXED_GROUP present"

if printf '%s' "$ENTITLEMENTS_OUT" | grep -qi "get-task-allow"; then
  echo "FAIL: com.apple.security.get-task-allow is PRESENT in the distribution-signed app — TID-5 violated" >&2
  echo "$ENTITLEMENTS_OUT" >&2
  exit 1
fi
echo "PASS: com.apple.security.get-task-allow absent"

# --- e. notarize + staple --------------------------------------------------------------------
echo "--- Step e: notarize + staple ---"
ZIP_PATH="$PACKAGING_DIR/.dd/cc-touch-id.app.zip"
rm -f "$ZIP_PATH"
ditto -c -k --keepParent "$APP" "$ZIP_PATH"

xcrun notarytool submit "$ZIP_PATH" --keychain-profile "$NOTARY_PROFILE" --wait

xcrun stapler staple "$APP"

# --- f. done ---------------------------------------------------------------------------------
echo "=== build-signed.sh complete ==="
echo "signed + notarized .app: $APP"
