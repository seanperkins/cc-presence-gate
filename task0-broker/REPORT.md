# Broker feasibility gate — findings

**Date:** 2026-07-16
**Machine:** darwin 25.5.0 (arm64), macOS 26.5.2, CC 2.1.211, YubiKey OTP+FIDO+CCID.
**Plan:** [`docs/superpowers/plans/2026-07-16-broker-feasibility-gate.md`](../docs/superpowers/plans/2026-07-16-broker-feasibility-gate.md)
**Spec:** [`docs/superpowers/specs/2026-07-16-cc-fido-gate-broker-design.md`](../docs/superpowers/specs/2026-07-16-cc-fido-gate-broker-design.md)

Verifies the four Section-4 questions before implementing v2. Probes need one-time `sudo` and
physical key touches; run un-sandboxed. Verdicts: ✅ GREEN / ⛔️ RED / 🟡 PARTIAL.

---

## Q3 — `uchg` file + directory lock enforcement — ✅ GREEN

`probe-q3-uchg.sh`. A root-owned (stand-in for `_ccfido`) `uchg` file placed inside a `sean`-owned
temp dir; then `sean` tries every tampering path:

```
-rw-r--r--@ 1 root  staff  uchg 9 ... /…/secret
  PASS: write -> denied            (Operation not permitted)
  PASS: unlink -> denied (immutable)
  PASS: rename -> denied
  PASS: chflags nouchg -> denied (not owner)
=== DIR LOCK: root-owned dir, mode 0755, sean cannot create ===
  PASS: create-in-dir -> denied
RESULT: GREEN — uchg + dir-ownership lock out the agent uid
```

**Interpretation.** The file-custody guarantee's kernel primitive holds on APFS: a file owned by a
principal the agent isn't, plus `uchg`, cannot be written, deleted, renamed, or unflagged by the
agent uid — *even though the agent owns the parent directory* (immutable blocks unlink/rename). A
directory owned by another principal blocks creation. This is enforced with **no hook and no
runtime root**. The remaining half — that the *owner* (`_ccfido`, non-root) can toggle `uchg` to
perform legitimate writes — is proven in Q1/Task 4.

## Account — `_ccfido` service account — ✅ GREEN

`account-setup.sh` / `account-teardown.sh`. Result:

```
_ccfido (uid 309), gid=20(staff), hidden service-account range
su _ccfido  ->  "su: Sorry"   (sean cannot become _ccfido — no login, /usr/bin/false shell)
```

A dedicated non-login service account exists, can own files and serve as a LaunchDaemon
`UserName`, and the agent uid (`sean`) cannot act as it. (Pre-existed on this machine from an
earlier attempt; removed at the gate's teardown.)

## Key custody — `_ccfido`-owned `sk` handle — ✅ GREEN

`enroll-broker-key.sh`. Enrolled a dedicated `ed25519-sk` (touch-required) key into `/var/ccfido`:

```
-rw-------@ 1 _ccfido wheel  gate_sk          (0600 — private handle)
-rw-r--r--@ 1 _ccfido wheel  gate_sk.pub
-rw-r--r--@ 1 _ccfido wheel  allowed_signers
PASS: handle not readable by sean
```

The signing handle is owned by `_ccfido` at `0600`, so the agent uid can't read it and therefore
**can't even arm the enrolled key** — the precondition for "only the broker ever signs".

## Q1/Q2/Q3-owner — non-console daemon signing (LOAD-BEARING) — ⛔️ RED (as specified) / architecture revision

`run-q1.sh` + `brokerd-probe.sh`. The daemon ran as `_ccfido` (uid 309) under launchd's **system
domain** and:

```
=== (3-owner) uchg toggle on an owned file ===
set uchg OK
write-while-uchg denied OK
clear uchg OK (owner, no root)          <-- Q3-owner ✅
=== (1) sign against USB key — TOUCH EXPECTED ===
Confirm user presence for key ED25519-SK SHA256:bmx2…
Couldn't sign message: device not found
Signing (stdin) failed: device not found
VERDICT: RED daemon could NOT sign (device not found)
```

**Disambiguation (device vs session).** To rule out the transient stuck-helper seen in 0.4, the
same sign was run as **root in the console session** after clearing helpers — it **signed OK (rc=0,
with touch)**. Combined with 0.4 (`sean`-console signs), this localizes the failure precisely:

> **A LaunchDaemon in the system domain cannot reach the USB FIDO device.** USB HID / `ssh-sk-helper`
> access requires the **console/login session**. The device is healthy; the daemon's session context
> is the blocker.

**Consequence (Q3-owner ✅, Q1 as-specified ⛔️).** The privileged half of the broker works as a
daemon (owns files, toggles `uchg`, will verify + write). Only the **arming/signing** step can't
live in the daemon. `ssh-keygen -Y verify` needs **no USB**, so the fix is a split, not a dead end
— the hard guarantee survives.

**Architecture revision adopted (capability-split):** the console-session **client** does USB + GUI
(arm, sign the daemon's challenge, dialog); the **daemon** issues the challenge, **verifies** the
signature (USB-free), owns files, toggles `uchg` + writes, and audits. Q2 (cross-process touch
binding) is thereby **subsumed** — signing is entirely client-side. The spec's Section 1 was updated
accordingly (commit on `main`). The revision's pieces are each independently proven: client-signs
(0.4 `sean`-console + root-console here), verify-USB-free (0.4 crypto), owner `uchg`-toggle + write
(this task). Trade accepted: the handle is readable by the console signer → agent can *arm* (not
sign); single-armed-signer drops to a parked hardening upgrade. See spec §"Consequence of no-root".

## Q4 — unix socket + `LOCAL_PEERCRED` — ✅ GREEN

`run-q4.sh` + `peercred_server.py`:

```
listening on /var/ccfido-run/gate.sock as uid=309
sean connected OK
PEER uid=501
```

`sean` reaches a `_ccfido`-owned socket and the server reads the caller uid via `LOCAL_PEERCRED`
(for audit; authorization stays touch-based). **Design note:** the socket must live in a traversable
`0755` dir — *not* the `0700` keydir `/var/ccfido` (first attempt failed `EPERM` because the keydir
is deliberately unreachable).

---

## Scoreboard

| Q | Question | Verdict |
|---|----------|---------|
| Q1 | daemon (system domain) reaches USB to sign | ⛔️ **RED as specified** → ✅ **resolved by capability-split** (client signs, daemon verifies) |
| Q2 | cross-process touch binding | ✅ **subsumed** (signing is entirely client-side now) |
| Q3 | `uchg` file+dir lock (agent out) + owner toggle | ✅ **GREEN** (Task 1 + daemon owner-toggle) |
| Q4 | socket reachability + `LOCAL_PEERCRED` | ✅ **GREEN** |

**GO / NO-GO: GO — for the revised capability-split architecture.** The load-bearing kernel lock
(Q3) holds; the daemon-can't-sign fact (Q1) is fully accommodated by moving signing to the console
client with the daemon verifying (all sub-pieces proven), and the socket transport (Q4) works. The
*daemon-signs* design is abandoned. Implementation may proceed against the revised Section 1; the
first implementation task should be an end-to-end integration of the split ceremony
(client-sign → socket → daemon-verify → `uchg`-write), which composes only already-proven pieces.
