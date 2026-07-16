# Task 0.4 — hardware half (run when the physical FIDO key is plugged in)

The software plumbing is confirmed (`probe-0.4-crypto.sh`, all green). What remains
**cannot** be automated — it needs the physical key and human touches. `sk-` signing
needs an OpenSSH with a FIDO provider; stock macOS `ssh-keygen` (10.2p1) **verifies**
`sk-` keys but has no provider to **sign**, so use Homebrew OpenSSH for the *sign* side:
`SIGN=/opt/homebrew/opt/openssh/bin/ssh-keygen` (verify can stay `/usr/bin/ssh-keygen`).

## 1. Enroll a DEDICATED sk- key (not your SSH-auth key)

```sh
# Touch-required (presence), non-resident handle stored in $KEYDIR:
KEYDIR=~/.cc-fido-gate ; mkdir -p "$KEYDIR"
"$SIGN" -t ed25519-sk -O resident=no -O verify-required=no \
  -N '' -C 'cc-fido-gate' -f "$KEYDIR/gate_sk"
#   -> BLINKS once for the enroll touch. This is the enrollment presence proof.
```

Record the pubkey and build `allowed_signers`:
```sh
PRIN=gate-principal ; NS='cc-fido-gate@<your-domain>'
printf '%s %s\n' "$PRIN" "$(cat "$KEYDIR/gate_sk.pub")" > "$KEYDIR/allowed_signers"
```

## 2. NEGATIVE blink-test (the actual presence guarantee) — MUST hold

A no-touch (`verify-required=no`, and especially a `-O no-touch-required`) key would sign
with **no finger** and still verify — so a positive-only "did you touch?" proves nothing.
The guarantee is the *negative* test, with a positive control so a broken key can't pass
vacuously:

```sh
MSG='task0.4 negative blink-test'
# (a) NEGATIVE: arm the signer, DO NOT TOUCH. It must BLOCK (not complete) within, say, 8s.
printf '%s' "$MSG" | timeout 8 "$SIGN" -Y sign -f "$KEYDIR/gate_sk" -n "$NS" > /tmp/nbt.sig
echo "exit=$? (EXPECT non-zero / timeout, and /tmp/nbt.sig EMPTY) — withheld touch must NOT sign"
test -s /tmp/nbt.sig && echo 'FAIL: signed with NO touch — key is no-touch, REJECT for enrollment' \
                     || echo 'OK: no touch => no signature'
# (b) POSITIVE control: arm again, TOUCH within 8s. Must complete + verify.
printf '%s' "$MSG" | timeout 8 "$SIGN" -Y sign -f "$KEYDIR/gate_sk" -n "$NS" > /tmp/pbt.sig  # <-- TOUCH NOW
printf '%s' "$MSG" | /usr/bin/ssh-keygen -Y verify -f "$KEYDIR/allowed_signers" -I "$PRIN" -n "$NS" -s /tmp/pbt.sig \
  && echo 'OK: touch => signs + verifies (positive control passed)' \
  || echo 'FAIL: touched but did not verify'
rm -f /tmp/nbt.sig /tmp/pbt.sig
```

Enrollment must **refuse** any key that passes (a) — i.e. signs without a touch.

## 3. Sign+block INSIDE the hook env (the real 0.4)

Confirm the key blinks and the ceremony blocks within CC's outer hook timeout, when armed
from the *scrubbed* hook environment (no `SSH_AUTH_SOCK`, no `SSH_ASKPASS*`, forced built-in
provider). Wire `probes/hook-probe.sh`-style logic to actually run step 2(a/b) under
`env -i` (plus only what the built-in FIDO provider needs) and drive it via `claude -p` like
`run-hook-semantics.sh` does. Success = a real touch within the window → `allow`; withheld
touch → watchdog `exit 2` before the outer timeout → deny.

## 4. PIN path (verify-required key) — experimental

For a `-O verify-required` key, PIN entry needs an askpass. Command hooks have **no
controlling terminal** and the scrub drops `SSH_ASKPASS*`, so PIN is unsupported unless a
**root-owned askpass** (or a native PIN path) is provided. Test:
```sh
"$SIGN" -t ed25519-sk -O verify-required -N '' -f "$KEYDIR/gate_sk_pin"
# then attempt a scrubbed sign and see whether PIN can be collected with NO tty.
```
Expected: fails without an explicit root-owned `SSH_ASKPASS`. If so, document PIN as
out-of-scope for v1 (presence-only), matching design.md.
