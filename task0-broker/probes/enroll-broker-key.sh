#!/bin/bash
# Enroll a dedicated touch-required sk key into a _ccfido-owned keydir.
# Requires sudo + a physical touch. Sign side needs Homebrew openssh.
set -eu
SIGN=/opt/homebrew/opt/openssh/bin/ssh-keygen
KEYDIR=/var/ccfido
NS='cc-fido-gate@example.test'
PRIN=gate-principal
sudo mkdir -p "$KEYDIR"
echo ">>> TOUCH THE KEY WHEN IT BLINKS (enrollment) <<<"
sudo "$SIGN" -t ed25519-sk -O application=ssh:cc-fido-gate \
  -N '' -C 'cc-fido-broker' -f "$KEYDIR/gate_sk"
sudo sh -c "printf '%s %s\n' '$PRIN' \"\$(cat '$KEYDIR/gate_sk.pub')\" > '$KEYDIR/allowed_signers'"
sudo chown -R _ccfido "$KEYDIR"
sudo chmod 700 "$KEYDIR"; sudo chmod 600 "$KEYDIR/gate_sk"
echo "=== perms ==="; sudo ls -le "$KEYDIR"
echo "=== sean can read the handle? (expect: denied) ==="
cat "$KEYDIR/gate_sk" >/dev/null 2>&1 && echo "FAIL: sean READ the handle" || echo "PASS: handle not readable by sean"
