#!/bin/bash
# Task 0.4 (plumbing half) — confirm the ssh-keygen sign/verify path the gate
# relies on works with STOCK /usr/bin/ssh-keygen. Uses a SOFTWARE ed25519 key
# (no hardware needed) to exercise everything except the physical touch:
#   - headless stdin sign, namespaced
#   - verify against allowed_signers with principal + namespace
#   - tamper rejection
#   - wrong-namespace rejection
#   - /dev/fd non-seekable-pipe transport for BOTH signature and message (NEW-8)
# The hardware half (touch blocking, negative blink-test) is in
# probe-0.4-hardware-checklist.md and requires the physical key.
set -u
SK=/usr/bin/ssh-keygen
D=$(mktemp -d "${TMPDIR:-/tmp}/ccfg-crypto.XXXXXX")
KEY="$D/id"
NS="cc-fido-gate@example.test"
PRIN="gate-principal"
pass() { echo "  PASS: $1"; }
fail() { echo "  FAIL: $1"; FAILED=1; }
FAILED=0

echo "=== keygen (software ed25519 stand-in for sk-) ==="
$SK -t ed25519 -N '' -C "$PRIN" -f "$KEY" >/dev/null
PUB=$(cat "$KEY.pub")
printf '%s %s\n' "$PRIN" "$PUB" > "$D/allowed_signers"
echo "  allowed_signers: $(cut -d' ' -f1-2 "$D/allowed_signers")"

MSG="canonical signed_document bytes: {\"tool\":\"Bash\",\"cmd\":\"git push --force\"}"

echo "=== sign (headless stdin, namespaced) ==="
printf '%s' "$MSG" | $SK -Y sign -f "$KEY" -n "$NS" > "$D/sig" 2>"$D/sign.err" \
  && pass "sign produced signature" || { fail "sign failed: $(cat "$D/sign.err")"; }
grep -q 'BEGIN SSH SIGNATURE' "$D/sig" && pass "armored SSH SIGNATURE present" || fail "no armored signature"

echo "=== verify (allowed_signers + principal + namespace) ==="
printf '%s' "$MSG" | $SK -Y verify -f "$D/allowed_signers" -I "$PRIN" -n "$NS" -s "$D/sig" >/dev/null 2>"$D/v.err" \
  && pass "valid signature verifies" || fail "valid verify failed: $(cat "$D/v.err")"

echo "=== tamper rejection ==="
printf '%s' "${MSG}X" | $SK -Y verify -f "$D/allowed_signers" -I "$PRIN" -n "$NS" -s "$D/sig" >/dev/null 2>&1 \
  && fail "tampered message ACCEPTED (bad!)" || pass "tampered message rejected"

echo "=== wrong-namespace rejection ==="
printf '%s' "$MSG" | $SK -Y verify -f "$D/allowed_signers" -I "$PRIN" -n "other@example.test" -s "$D/sig" >/dev/null 2>&1 \
  && fail "wrong namespace ACCEPTED (bad!)" || pass "wrong namespace rejected"

echo "=== wrong-principal rejection ==="
printf '%s' "$MSG" | $SK -Y verify -f "$D/allowed_signers" -I "not-the-principal" -n "$NS" -s "$D/sig" >/dev/null 2>&1 \
  && fail "wrong principal ACCEPTED (bad!)" || pass "wrong principal rejected"

echo "=== /dev/fd non-seekable pipe transport (NEW-8): sig AND message as pipes ==="
# Both -s <sig> and the message stdin are non-seekable process-substitution pipes.
if $SK -Y verify -f "$D/allowed_signers" -I "$PRIN" -n "$NS" \
      -s <(cat "$D/sig") < <(printf '%s' "$MSG") >/dev/null 2>"$D/fd.err"; then
  pass "verify accepts non-seekable /dev/fd for signature + message"
else
  fail "verify REJECTS non-seekable pipe fd (=> must fail CLOSED / use different transport): $(cat "$D/fd.err")"
fi

echo
[ "$FAILED" = 0 ] && echo "RESULT: ALL CRYPTO-PLUMBING CHECKS PASSED" || echo "RESULT: SOME CHECKS FAILED"
echo "workdir=$D"
rm -rf "$D"
