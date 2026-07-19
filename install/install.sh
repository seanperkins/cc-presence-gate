#!/bin/bash
# install/install.sh — full privileged cc-touch-id install + canary. Requires sudo.
#
# [USER-RUN]: needs sudo and (for a fresh key) a Touch ID prompt later at `cc-touch-id enroll` time.
# Prefer the guided `/cc-touch-id:install` skill (plugins/cc-touch-id/skills/install/SKILL.md), which
# drives this same sequence one step at a time with explanations. This script is the scriptable
# equivalent for repeat/CI-style installs.
#
# Why this script exists rather than just `sudo cc-touch-id install`: the built-in `install`
# subcommand (Sources/CCGateCore/Install.swift installOrchestration) copies the PLAIN daemon binary
# and writes a generic hook command (codeDir/binaryName). That is correct for the daemon (verify-only,
# no Secure Enclave access needed) but WRONG for the hook: the hook process signs with the Secure
# Enclave key, which requires the keychain-access-group entitlement that only the provisioned/notarized
# `.app` bundle carries (see Sources/CCTouchIDBackend/TouchIdConstants.swift touchIdAppBinary). So this
# script layers the `.app` install and the correct app-binary hook wiring on top of the subcommand.
set -eu -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CODE_DIR=/opt/cc-touch-id-gate
KEY_DIR=/var/cctouchid
RUN_DIR=/var/cctouchid-run
CLAUDE_CODE_DIR="/Library/Application Support/ClaudeCode"
PLIST=/Library/LaunchDaemons/com.cc-touch-id-gate.brokerd.plist
LAUNCHD_LABEL=com.cc-touch-id-gate.brokerd
POLICY="${POLICY:-$REPO_ROOT/plugins/cc-touch-id/install/policy.json}"
# Where packaging/build-signed.sh leaves the signed/notarized .app; APP env var overrides.
APP="${APP:-$REPO_ROOT/packaging/.dd/Build/Products/Release/cc-touch-id.app}"

echo "=== cc-touch-id install ==="

swift build -c release --package-path "$REPO_ROOT"
BIN="$REPO_ROOT/.build/release/cc-touch-id"

echo "--- account ---"
sudo bash "$SCRIPT_DIR/account-setup.sh"

echo "--- dirs ---"
sudo mkdir -p "$CODE_DIR" "$KEY_DIR" "$RUN_DIR" "$CLAUDE_CODE_DIR"

echo "--- plain daemon binary (ad-hoc codesign — verify-only, no SE access needed) ---"
sudo cp "$BIN" "$CODE_DIR/cc-touch-id"
sudo codesign --force --options runtime --sign - "$CODE_DIR/cc-touch-id"

echo "--- entitled .app (hook/write/enroll — needs the Secure Enclave keychain-access-group) ---"
if [ -d "$APP" ]; then
  sudo rm -rf "$CODE_DIR/cc-touch-id.app"
  sudo cp -R "$APP" "$CODE_DIR/cc-touch-id.app"
  echo "installed signer app -> $CODE_DIR/cc-touch-id.app"
else
  echo "WARN: no signed .app found at $APP — run packaging/build-signed.sh first (or set APP=<path>)."
  echo "      Continuing with prereqs only; enroll/hook will fail until the .app is installed."
fi

echo "--- policy (render: substitute __HOME__, validate, lint) ---"
"$BIN" _render-policy "$POLICY" "$HOME" | sudo tee "$CODE_DIR/policy.json" >/dev/null
sudo cp "$POLICY" "$CODE_DIR/policy.json.template"

echo "--- perms ---"
sudo chown -R root:wheel "$CODE_DIR"; sudo chmod 755 "$CODE_DIR"; sudo chmod 644 "$CODE_DIR/policy.json"
sudo chown _cctouchid "$KEY_DIR" "$RUN_DIR"; sudo chmod 700 "$KEY_DIR"; sudo chmod 755 "$RUN_DIR"

echo "--- launchd plist (daemon -> plain binary) + managed-settings (hook -> app binary) ---"
"$BIN" _render-plist | sudo tee "$PLIST" >/dev/null
sudo chown root:wheel "$PLIST"; sudo chmod 644 "$PLIST"
"$BIN" _render-managed | sudo tee "$CLAUDE_CODE_DIR/managed-settings.json" >/dev/null
sudo chown root:wheel "$CLAUDE_CODE_DIR/managed-settings.json"; sudo chmod 644 "$CLAUDE_CODE_DIR/managed-settings.json"

CLAUDE_BIN="${CLAUDE_BIN:-$(command -v claude 2>/dev/null || echo /Users/sean/.local/bin/claude)}"
"$BIN" _cc-version "$CLAUDE_BIN" 2>/dev/null | sudo tee "$KEY_DIR/cc-version" >/dev/null || true

# Prereqs are now installed. Break the install<->enroll circularity: if no key is enrolled yet, STOP
# here with instructions (exit 0, not a hard refusal) — enroll needs the account+dirs we just created;
# the daemon is only activated on a re-run once a key exists.
if ! sudo test -s "$KEY_DIR/enrolled_pubkey" 2>/dev/null; then
  echo "Prereqs installed. Next: run  cc-touch-id enroll  (needs a Touch ID prompt), then re-run this script to activate the daemon."
  exit 0
fi

echo "--- activate (bootout || true -> bootstrap -> kickstart -k for a fresh socket) ---"
sudo launchctl bootout system "$PLIST" 2>/dev/null || true
sudo launchctl bootstrap system "$PLIST"
sudo launchctl kickstart -k "system/$LAUNCHD_LABEL"
sleep 1

echo "=== CANARY: the BROKER must deny an execute-write to a control path (NON-destructive) ==="
# Drives the broker as the agent uid via the plain daemon binary; the daemon denies control paths
# BEFORE any dialog/Touch ID prompt, so the plain (non-SE-entitled) binary is sufficient here.
# Capture separately so pipefail can't misread cc-touch-id's (correct) non-zero deny exit as a failure.
CANARY_OUT=$(printf 'x' | "$CODE_DIR/cc-touch-id" write "$KEY_DIR/enrolled_pubkey" 2>&1 || true)
echo "$CANARY_OUT" | grep -qi 'deny\|not an enrolled' \
  && echo "PASS: broker denied control-path write" \
  || { echo "FAIL: broker did not deny control path — ABORTING"; echo "$CANARY_OUT"; exit 1; }
sudo test -s "$KEY_DIR/enrolled_pubkey" \
  && echo "PASS: enrolled_pubkey intact" \
  || { echo "FAIL: trust store damaged — ABORTING"; exit 1; }

echo "=== install complete ==="
