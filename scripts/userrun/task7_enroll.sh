#!/bin/bash
# scripts/userrun/task7_enroll.sh
set -eu
REPO="$(cd "$(dirname "$0")/../.." && pwd)"; SIGN=/opt/homebrew/opt/openssh/bin/ssh-keygen
swift build -c release --package-path "$REPO"; BIN="$REPO/.build/release/cc-fido"
mkdir -p "$HOME/.ccfido"; chmod 700 "$HOME/.ccfido"
for n in 1 2; do
  echo ">>> TOUCH to enroll key #$n <<<"
  "$SIGN" -t ed25519-sk -O application=ssh:cc-fido-gate -N '' -C "cc-fido-key$n" -f "$HOME/.ccfido/gate_sk$n"
  chmod 600 "$HOME/.ccfido/gate_sk$n"
  sudo sh -c "printf 'gate-principal %s\n' \"\$(cat '$HOME/.ccfido/gate_sk$n.pub')\" >> /var/ccfido/allowed_signers"
done
ln -sf "$HOME/.ccfido/gate_sk1" "$HOME/.ccfido/gate_sk"
sudo chown _ccfido /var/ccfido/allowed_signers; sudo chmod 600 /var/ccfido/allowed_signers
echo "=== negative blink-test (key #1) ==="
"$BIN" _blink-test "$HOME/.ccfido/gate_sk1" && echo "PASS: touch-required verified" || echo "FAIL"
