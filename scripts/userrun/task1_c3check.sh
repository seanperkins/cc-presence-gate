#!/bin/bash
# C-3 verification (NO key touch): prove the LIVE daemon DENIES execute-write to a control path
# and to an unenrolled path (both deny before any dialog). Primes sudo in the foreground first so the
# backgrounded daemon (sudo -u _ccfido …) can use the cached credential instead of failing to prompt.
set -u
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="$REPO/.build/release/cc-fido"
[ -x "$BIN" ] || swift build -c release --package-path "$REPO"
sudo -v || { echo "need sudo"; exit 1; }          # foreground prompt → caches credential
sudo -u _ccfido "$BIN" daemon & DPID=$!; sleep 1
echo "--- control path /var/ccfido/allowed_signers (expect: denied (not an enrolled target), NO touch) ---"
printf x | "$BIN" write /var/ccfido/allowed_signers
echo "--- unenrolled path /tmp/not-enrolled (expect: denied (not an enrolled target), NO touch) ---"
printf x | "$BIN" write /tmp/not-enrolled
sudo kill "$DPID" 2>/dev/null
echo "--- audit tail (expect two deny_target lines) ---"
sudo tail -3 /var/ccfido/audit.log
echo "--- allowed_signers still intact (expect a key line, NOT 'x') ---"
sudo head -c 40 /var/ccfido/allowed_signers; echo
