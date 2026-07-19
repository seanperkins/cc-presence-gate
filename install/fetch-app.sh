#!/bin/bash
# install/fetch-app.sh — PATH 2 (download the maintainer's prebuilt binary): fetch + verify the pinned
# notarized cc-touch-id.app from the GitHub release named in plugins/cc-touch-id/install/release.json,
# with NO Xcode and NO signing identity required. Prints the verified .app path on stdout for
# install.sh (APP=). For self-builders with their own Developer ID, DON'T use this — build from source
# (packaging/build-distribution.sh) and pass that .app to install.sh directly.
#
# Fail-closed: verifies ALL of — SHA-256 == the committed pin, spctl notarization accepted, codesign
# team == the pinned team_id, get-task-allow ABSENT, stapler ticket valid. Any mismatch aborts.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
MANIFEST="$REPO_ROOT/plugins/cc-touch-id/install/release.json"
[ -f "$MANIFEST" ] || { echo "fetch-app: no manifest at $MANIFEST" >&2; exit 1; }
command -v jq >/dev/null || { echo "fetch-app: jq required" >&2; exit 1; }

PUBLISHED=$(jq -r '.published' "$MANIFEST")
SHA_PIN=$(jq -r '.sha256' "$MANIFEST")
URL=$(jq -r '.asset_url' "$MANIFEST")
TEAM=$(jq -r '.team_id' "$MANIFEST")
ASSET=$(jq -r '.asset' "$MANIFEST")
if [ "$PUBLISHED" != "true" ] || [ -z "$SHA_PIN" ] || [ "$SHA_PIN" = "null" ] || [ -z "$URL" ] || [ "$URL" = "null" ]; then
  echo "fetch-app: no published release pinned in release.json yet." >&2
  echo "  Either build from source (packaging/build-distribution.sh, needs a Developer ID), or wait" >&2
  echo "  until a machine with the Developer ID identity runs publish-release.sh + commits release.json." >&2
  exit 1
fi

WORK="$(mktemp -d)"; ZIP="$WORK/$ASSET"
echo "fetch-app: downloading $URL" >&2
curl -fsSL "$URL" -o "$ZIP"

echo "fetch-app: verifying SHA-256 against the committed pin" >&2
GOT=$(shasum -a 256 "$ZIP" | awk '{print $1}')
[ "$GOT" = "$SHA_PIN" ] || { echo "fetch-app: SHA-256 MISMATCH (got $GOT, pinned $SHA_PIN) — refusing" >&2; exit 1; }

ditto -x -k "$ZIP" "$WORK/x"
APP="$(/usr/bin/find "$WORK/x" -maxdepth 2 -type d -name 'cc-touch-id.app' | head -1)"
[ -n "$APP" ] && [ -d "$APP" ] || { echo "fetch-app: no cc-touch-id.app inside the asset" >&2; exit 1; }

# capture-then-case (avoids the pipefail/SIGPIPE false-fail with grep -q; see build-signed.sh)
SPCTL="$(spctl -a -vvv -t exec "$APP" 2>&1 || true)"
case "$SPCTL" in *accepted*) : ;; *) echo "fetch-app: spctl rejected — not notarized" >&2; exit 1 ;; esac
GOTTEAM="$(codesign -dvvv "$APP" 2>&1 | sed -n 's/^TeamIdentifier=//p')"
[ "$GOTTEAM" = "$TEAM" ] || { echo "fetch-app: team mismatch (got '$GOTTEAM', pinned '$TEAM')" >&2; exit 1; }
ENT="$(codesign -d --entitlements :- "$APP" 2>/dev/null || true)"
case "$ENT" in *get-task-allow*) echo "fetch-app: get-task-allow present — refusing" >&2; exit 1 ;; esac
# stapler ships with Xcode, not always the CLT; spctl already proved notarization, so this is a
# bonus "is the ticket stapled (offline-valid)" check — skip cleanly if the tool is absent.
if xcrun --find stapler >/dev/null 2>&1; then
  case "$(xcrun stapler validate "$APP" 2>&1 || true)" in *worked*) : ;; *) echo "fetch-app: stapler validate failed" >&2; exit 1 ;; esac
else
  echo "fetch-app: (stapler unavailable — relying on spctl for notarization; install Xcode for the stapled-ticket check)" >&2
fi

echo "fetch-app: verified (sha256 pin + notarized + team $TEAM + no get-task-allow + stapled)" >&2
echo "$APP"   # stdout: the path to hand install.sh as APP=
