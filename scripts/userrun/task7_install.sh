# scripts/userrun/task7_install.sh — full privileged install + canary. Requires sudo.
#!/bin/bash
set -eu -o pipefail
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
swift build -c release --package-path "$REPO"; BIN="$REPO/.build/release/cc-fido"
sudo bash "$REPO/task0-broker/probes/account-setup.sh"
sudo mkdir -p /opt/cc-fido-gate /var/ccfido /var/ccfido-run "/Library/Application Support/ClaudeCode"
sudo cp "$BIN" /opt/cc-fido-gate/cc-fido
sudo codesign --force --options runtime --sign - /opt/cc-fido-gate/cc-fido
sudo cp "$REPO/install/policy.json" /opt/cc-fido-gate/policy.json
sudo chown -R root:wheel /opt/cc-fido-gate; sudo chmod 755 /opt/cc-fido-gate; sudo chmod 644 /opt/cc-fido-gate/policy.json
sudo chown _ccfido /var/ccfido /var/ccfido-run; sudo chmod 700 /var/ccfido; sudo chmod 755 /var/ccfido-run
# Prereqs are now installed. Break the install<->enroll circularity: if no key is enrolled yet, STOP here
# with instructions (exit 0, not a hard refusal) — enroll needs the account+dirs we just created; the
# daemon is only activated on a re-run once a key exists.
/opt/cc-fido-gate/cc-fido _render-plist | sudo tee /Library/LaunchDaemons/com.cc-fido-gate.brokerd.plist >/dev/null
/opt/cc-fido-gate/cc-fido _render-managed | sudo tee "/Library/Application Support/ClaudeCode/managed-settings.json" >/dev/null
/opt/cc-fido-gate/cc-fido --version 2>/dev/null | sudo tee /var/ccfido/cc-version >/dev/null || true
if ! sudo test -s /var/ccfido/allowed_signers; then
  echo "Prereqs installed. Next: run  bash scripts/userrun/task7_enroll.sh  to enroll a key, then re-run THIS script to activate the daemon."
  exit 0
fi
sudo launchctl bootstrap system /Library/LaunchDaemons/com.cc-fido-gate.brokerd.plist
sleep 1
echo "=== CANARY: the BROKER must deny an execute-write to a control path (NON-destructive) ==="
# Drives the broker as the agent uid; the daemon denies control paths BEFORE any dialog/write.
# Capture separately so pipefail can't misread cc-fido's (correct) non-zero deny exit as a canary failure.
CANARY_OUT=$(printf 'x' | /opt/cc-fido-gate/cc-fido write /var/ccfido/allowed_signers 2>&1 || true)
echo "$CANARY_OUT" | grep -qi 'deny\|not an enrolled' \
  && echo "PASS: broker denied control-path write" \
  || { echo "FAIL: broker did not deny control path — ABORTING"; echo "$CANARY_OUT"; exit 1; }
sudo test -s /var/ccfido/allowed_signers \
  && echo "PASS: allowed_signers intact" \
  || { echo "FAIL: trust store damaged — ABORTING"; exit 1; }
echo "=== install complete ==="
