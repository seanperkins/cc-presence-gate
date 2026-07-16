# Broker Feasibility Gate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Empirically verify the four load-bearing feasibility questions in Section 4 of the v2 spec, producing `task0-broker/REPORT.md` (actual commands + outputs), so we know the broker architecture holds before we build it.

**Architecture:** This is an investigative gate, not TDD feature work — it mirrors the existing `task0/` spike. Each task is a self-contained probe with a concrete script, an exact run command, an expected result, and a green/red verdict recorded in the report. Several probes need a one-time `sudo` (create the `_ccfido` account, install a throwaway LaunchDaemon) and physical key touches; those steps are called out and run by the user.

**Tech Stack:** bash probe scripts, macOS `sysadminctl`/`dscl`, `launchd` (LaunchDaemon), `chflags uchg`, `/opt/homebrew/opt/openssh/bin/ssh-keygen` (sign) + `/usr/bin/ssh-keygen` (verify), unix domain sockets (python for `LOCAL_PEERCRED`).

## Global Constraints

- Platform: macOS (this machine — darwin 25.5.0, CC 2.1.211, YubiKey OTP+FIDO+CCID). Copy exact outputs.
- **No runtime root** is the target; probes may use `sudo` only for one-time setup (account creation, daemon install) and must clean up everything they create (accounts, daemons, temp files).
- Service account name: **`_ccfido`** (leading underscore = macOS hidden service-account convention).
- Signing key: a **dedicated `sk-ssh-ed25519`** key, touch-required (never a no-touch key); non-resident handle owned by `_ccfido`, mode `0600`.
- Sign binary: `/opt/homebrew/opt/openssh/bin/ssh-keygen`. Verify binary: `/usr/bin/ssh-keygen`. Namespace: `cc-fido-gate@<domain>`.
- A probe that needs a hardware touch must be driven by the user (touch prompts are called out verbatim).
- Verdict vocabulary in the report: ✅ GREEN / ⛔️ RED / 🟡 PARTIAL, matching `task0/REPORT.md`.
- Green on **all four** Section-4 questions → proceed to write the implementation plan. Any RED on Q1 (daemon USB signing) or Q3 (`uchg`) → stop and re-spec.

---

### Task 1: `uchg` file-lock + directory-lock enforcement (spec Q3)

Proves the kernel-enforced core: a file owned by another principal + `uchg` cannot be written, deleted, renamed, or unflagged by `sean`; and a dir owned by another principal cannot have files created in it by `sean`. Uses `root` as a stand-in owner here (the *owner-clears-uchg* half is proven in Task 4 with the real `_ccfido`).

**Files:**
- Create: `task0-broker/probes/probe-q3-uchg.sh`
- Create/append: `task0-broker/REPORT.md`

**Interfaces:**
- Produces: the enforcement facts consumed by the report and by the v2 file-custody design.

- [ ] **Step 1: Write the probe script**

Create `task0-broker/probes/probe-q3-uchg.sh`:

```bash
#!/bin/bash
# Q3 — uchg file-lock + directory-lock enforcement against a same-machine agent uid.
# Uses root as a stand-in for the _ccfido owner; the owner-clears-uchg half is Task 4.
# Needs sudo for the privileged setup; cleans up after itself.
set -u
D=$(mktemp -d "${TMPDIR:-/tmp}/ccfg-q3.XXXXXX")
pass(){ echo "  PASS: $1"; }
fail(){ echo "  FAIL: $1"; FAILED=1; }
FAILED=0

echo "=== FILE LOCK: root-owned + uchg file inside a sean-owned dir ==="
echo original > "$D/secret" 2>/dev/null
sudo chown root "$D/secret"
sudo chflags uchg "$D/secret"
ls -leO "$D/secret"

echo hostile > "$D/secret" 2>/dev/null && fail "sean WROTE the locked file" || pass "write -> denied"
rm -f "$D/secret" 2>/dev/null && fail "sean DELETED the locked file" || pass "unlink -> denied (immutable)"
mv "$D/secret" "$D/secret2" 2>/dev/null && fail "sean RENAMED the locked file" || pass "rename -> denied"
chflags nouchg "$D/secret" 2>/dev/null && fail "sean CLEARED uchg" || pass "chflags nouchg -> denied (not owner)"

echo "=== DIR LOCK: root-owned dir, mode 0755, sean cannot create ==="
sudo mkdir "$D/locked_dir"; sudo chown root "$D/locked_dir"; sudo chmod 755 "$D/locked_dir"
touch "$D/locked_dir/newfile" 2>/dev/null && fail "sean CREATED a file in the locked dir" || pass "create-in-dir -> denied"

echo
[ "$FAILED" = 0 ] && echo "RESULT: ✅ GREEN — uchg + dir-ownership lock out the agent uid" \
                  || echo "RESULT: ⛔️ RED — a lock leaked; file-custody guarantee does not hold"
echo "cleanup:"; sudo chflags nouchg "$D/secret" 2>/dev/null; sudo rm -rf "$D" && echo "  removed $D"
```

- [ ] **Step 2: Run it (needs sudo)**

Run: `bash task0-broker/probes/probe-q3-uchg.sh`
Expected: five `PASS` lines and `RESULT: ✅ GREEN`. Any `FAIL` is a RED verdict for Q3.

- [ ] **Step 3: Record the result in the report**

Create `task0-broker/REPORT.md` with a header (mirroring `task0/REPORT.md`) and a `## Q3 — uchg enforcement` section pasting the actual script output and the ✅/⛔️ verdict.

- [ ] **Step 4: Commit**

```bash
git add task0-broker/probes/probe-q3-uchg.sh task0-broker/REPORT.md
git commit -m "test(broker-gate): Q3 uchg file+dir lock enforcement probe"
```

---

### Task 2: `_ccfido` service-account creation + teardown (spec: install mechanics)

Proves we can create a hidden, non-login service account that can own files and be a LaunchDaemon `UserName`, that `sean` cannot act as it, and that it removes cleanly.

**Files:**
- Create: `task0-broker/probes/account-setup.sh` (create), `task0-broker/probes/account-teardown.sh` (remove)
- Append: `task0-broker/REPORT.md`

**Interfaces:**
- Produces: `_ccfido` account (used by Tasks 3–5); `account-teardown.sh` (used at gate end).

- [ ] **Step 1: Write the setup script**

Create `task0-broker/probes/account-setup.sh`:

```bash
#!/bin/bash
# Create a hidden _ccfido service account (uid in the system range, no login).
# Idempotent: exits 0 if it already exists. Requires sudo.
set -eu
USERNAME=_ccfido
if dscl . -read "/Users/$USERNAME" >/dev/null 2>&1; then
  echo "already exists: $USERNAME (uid $(id -u "$USERNAME"))"; exit 0
fi
# Pick a free uid in the 200-400 service range.
UID_NEW=$(sudo dscl . -list /Users UniqueID | awk '$2>=200 && $2<400 {print $2}' | sort -n | tail -1)
UID_NEW=$(( ${UID_NEW:-299} + 1 ))
sudo dscl . -create "/Users/$USERNAME"
sudo dscl . -create "/Users/$USERNAME" UserShell /usr/bin/false
sudo dscl . -create "/Users/$USERNAME" RealName "cc-fido broker"
sudo dscl . -create "/Users/$USERNAME" UniqueID "$UID_NEW"
sudo dscl . -create "/Users/$USERNAME" PrimaryGroupID 20
sudo dscl . -create "/Users/$USERNAME" NFSHomeDirectory /var/empty
sudo dscl . -create "/Users/$USERNAME" IsHidden 1
echo "created: $USERNAME uid=$UID_NEW"
```

- [ ] **Step 2: Write the teardown script**

Create `task0-broker/probes/account-teardown.sh`:

```bash
#!/bin/bash
# Remove the _ccfido account. Requires sudo. Safe to run repeatedly.
set -u
USERNAME=_ccfido
sudo dscl . -delete "/Users/$USERNAME" 2>/dev/null && echo "deleted $USERNAME" || echo "$USERNAME not present"
```

- [ ] **Step 3: Run setup, verify, and prove `sean` can't act as it**

Run:
```bash
bash task0-broker/probes/account-setup.sh
id _ccfido
sudo -u _ccfido /usr/bin/true && echo "root can run as _ccfido"       # via sudo (root) — expected OK
su _ccfido -c true 2>&1 | head -1 || echo "sean cannot su to _ccfido"  # as sean — expected to fail
```
Expected: `id _ccfido` shows the new uid; `sean`'s `su _ccfido` fails (no password / not permitted). Root-via-`sudo -u` works (that's the install context, not runtime).

- [ ] **Step 4: Record in the report**

Append `## Account — _ccfido creation` with the `id` output and the `sean`-cannot-`su` evidence, verdict ✅/⛔️.

- [ ] **Step 5: Commit**

```bash
git add task0-broker/probes/account-setup.sh task0-broker/probes/account-teardown.sh task0-broker/REPORT.md
git commit -m "test(broker-gate): _ccfido service account create/teardown"
```

---

### Task 3: Enroll a dedicated `sk-` key owned by `_ccfido` (spec: key custody)

Enrolls the touch-required key the daemon will use, owned by `_ccfido` mode `0600`, and confirms `sean` cannot read the handle.

**Files:**
- Create: `task0-broker/probes/enroll-broker-key.sh`
- Append: `task0-broker/REPORT.md`

**Interfaces:**
- Consumes: `_ccfido` account (Task 2).
- Produces: `/var/ccfido/gate_sk` (+ `.pub`, `allowed_signers`) owned by `_ccfido` — consumed by Tasks 4–5.

- [ ] **Step 1: Write the enroll script**

Create `task0-broker/probes/enroll-broker-key.sh`:

```bash
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
```

- [ ] **Step 2: Run it (sudo + touch)**

Run: `bash task0-broker/probes/enroll-broker-key.sh`
Expected: key blinks, you touch, enrollment succeeds; final line `PASS: handle not readable by sean`.

- [ ] **Step 3: Record + Commit**

Append `## Key custody — _ccfido-owned sk handle` (perms + the sean-can't-read line). Then:
```bash
git add task0-broker/probes/enroll-broker-key.sh task0-broker/REPORT.md
git commit -m "test(broker-gate): dedicated _ccfido-owned sk key enrollment"
```

---

### Task 4: Non-console daemon USB signing + owner-clears-`uchg` (spec Q1, Q2, Q3-owner) — LOAD-BEARING

The gate's crux. Installs a throwaway LaunchDaemon running as `_ccfido` that (a) signs a message with the enrolled key (proving a non-console daemon reaches the USB device), and (b) toggles `uchg` on a `_ccfido`-owned file (proving the owner can lock/unlock without root). A user-session `sean` process shows a dialog concurrently (Q2 cross-process binding). If the daemon can't reach the key, the architecture needs rework — stop here.

**Files:**
- Create: `task0-broker/probes/brokerd-probe.sh` (the daemon's job), `task0-broker/probes/com.cc-fido-gate.brokerprobe.plist`, `task0-broker/probes/run-q1.sh` (driver)
- Append: `task0-broker/REPORT.md`

**Interfaces:**
- Consumes: `_ccfido` (Task 2), `/var/ccfido/gate_sk` (Task 3).
- Produces: the Q1/Q2 verdict — the go/no-go for the whole broker model.

- [ ] **Step 1: Write the daemon job script**

Create `task0-broker/probes/brokerd-probe.sh`:

```bash
#!/bin/bash
# Runs AS _ccfido under launchd (no GUI session). Proves: (1) reach the USB key
# to sign; (3-owner) toggle uchg on an owned file. Writes results to a log the
# driver reads. Expects to be armed then touched by the human.
set -u
SIGN=/opt/homebrew/opt/openssh/bin/ssh-keygen
VERIFY=/usr/bin/ssh-keygen
KEYDIR=/var/ccfido
NS='cc-fido-gate@example.test'; PRIN=gate-principal
OUT=/var/ccfido/q1.log; MSG='broker-gate Q1 daemon sign'
{
  echo "=== daemon whoami: $(id) ==="
  echo "=== (3-owner) uchg toggle on an owned file ==="
  F=/var/ccfido/ownedfile; echo v > "$F"
  chflags uchg "$F" && echo "set uchg OK" || echo "set uchg FAIL"
  ( echo x > "$F" ) 2>/dev/null && echo "UNEXPECTED: wrote while uchg" || echo "write-while-uchg denied OK"
  chflags nouchg "$F" && echo "clear uchg OK (owner, no root)" || echo "clear uchg FAIL"
  echo "=== (1) sign against USB key — TOUCH EXPECTED ==="
  printf '%s' "$MSG" | "$SIGN" -Y sign -f "$KEYDIR/gate_sk" -n "$NS" > /var/ccfido/q1.sig 2>/var/ccfido/q1.sign.err
  echo "sign rc=$?"; cat /var/ccfido/q1.sign.err
  if grep -q 'BEGIN SSH SIGNATURE' /var/ccfido/q1.sig 2>/dev/null; then
    printf '%s' "$MSG" | "$VERIFY" -Y verify -f "$KEYDIR/allowed_signers" -I "$PRIN" -n "$NS" -s /var/ccfido/q1.sig \
      && echo "VERDICT: GREEN daemon signed+verified" || echo "VERDICT: RED signed but verify failed"
  else
    echo "VERDICT: RED daemon could NOT sign (device not found / TCC denied) — architecture rework"
  fi
} > "$OUT" 2>&1
```

- [ ] **Step 2: Write the LaunchDaemon plist**

Create `task0-broker/probes/com.cc-fido-gate.brokerprobe.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.cc-fido-gate.brokerprobe</string>
  <key>UserName</key><string>_ccfido</string>
  <key>ProgramArguments</key>
    <array><string>/bin/bash</string><string>/var/ccfido/brokerd-probe.sh</string></array>
  <key>RunAtLoad</key><false/>
  <key>StandardErrorPath</key><string>/var/ccfido/brokerprobe.err</string>
</dict></plist>
```

- [ ] **Step 3: Write the driver**

Create `task0-broker/probes/run-q1.sh`:

```bash
#!/bin/bash
# Installs the throwaway LaunchDaemon, kickstarts the _ccfido job, and shows a
# user-session dialog (as sean) concurrently for Q2. Requires sudo + a touch.
set -u
PLIST=/Library/LaunchDaemons/com.cc-fido-gate.brokerprobe.plist
sudo cp task0-broker/probes/brokerd-probe.sh /var/ccfido/brokerd-probe.sh
sudo chown _ccfido /var/ccfido/brokerd-probe.sh; sudo chmod 755 /var/ccfido/brokerd-probe.sh
sudo cp task0-broker/probes/com.cc-fido-gate.brokerprobe.plist "$PLIST"
sudo chown root:wheel "$PLIST"
sudo launchctl bootstrap system "$PLIST" 2>/dev/null || true
echo ">>> TOUCH THE KEY WHEN IT BLINKS (daemon is arming the sign) <<<"
# Q2: user-session dialog as sean, concurrent with the daemon's arm.
( /usr/bin/osascript -l AppleScript -e 'display dialog "broker-gate Q2: daemon is signing; touch the key" giving up after 12' >/dev/null 2>&1 ) &
sudo launchctl kickstart -k system/com.cc-fido-gate.brokerprobe
sleep 12
echo "=== daemon result (/var/ccfido/q1.log) ==="; sudo cat /var/ccfido/q1.log
echo "=== teardown ==="
sudo launchctl bootout system "$PLIST" 2>/dev/null
sudo rm -f "$PLIST"
```

- [ ] **Step 4: Run it (sudo + touch)**

Run: `bash task0-broker/probes/run-q1.sh`
Expected (GREEN): the log ends `VERDICT: GREEN daemon signed+verified`, and the `uchg` lines show `set uchg OK` / `write-while-uchg denied OK` / `clear uchg OK (owner, no root)`.
Expected (RED): `VERDICT: RED daemon could NOT sign …` — **stop the gate; the daemon can't reach the key and the architecture must move signing into the user-session client (re-spec).**

- [ ] **Step 5: Record the verdict prominently in the report**

Append `## Q1/Q2/Q3-owner — non-console daemon signing (LOAD-BEARING)` with the full `q1.log`, and set the top-line gate verdict accordingly.

- [ ] **Step 6: Commit**

```bash
git add task0-broker/probes/brokerd-probe.sh task0-broker/probes/com.cc-fido-gate.brokerprobe.plist task0-broker/probes/run-q1.sh task0-broker/REPORT.md
git commit -m "test(broker-gate): Q1/Q2 non-console daemon USB signing + owner uchg"
```

---

### Task 5: Unix socket reachability + `LOCAL_PEERCRED` (spec Q4)

Proves a `_ccfido`-owned socket is reachable by `sean` and the server can read the caller's uid via `LOCAL_PEERCRED` (for audit; authorization stays touch-based).

**Files:**
- Create: `task0-broker/probes/peercred_server.py`, `task0-broker/probes/run-q4.sh`
- Append: `task0-broker/REPORT.md`

**Interfaces:**
- Consumes: `_ccfido` (Task 2).
- Produces: the Q4 verdict.

- [ ] **Step 1: Write the server**

Create `task0-broker/probes/peercred_server.py`:

```python
#!/usr/bin/env python3
# Bind a unix socket, accept one connection, read the peer uid via LOCAL_PEERCRED.
import socket, struct, sys, os
PATH = "/var/ccfido/gate.sock"
LOCAL_PEERCRED = 0x001  # macOS SO_PEERCRED equivalent option (xucred)
try:
    os.unlink(PATH)
except FileNotFoundError:
    pass
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(PATH)
os.chmod(PATH, 0o666)  # any local caller may connect; auth is by touch, not identity
s.listen(1)
print(f"listening on {PATH} as uid={os.getuid()}", flush=True)
conn, _ = s.accept()
# struct xucred: cr_version(u32), cr_uid(u32), cr_ngroups(short), cr_groups[16](u32)
xucred = conn.getsockopt(0, LOCAL_PEERCRED, 4 + 4 + 2 + 16 * 4)
cr_uid = struct.unpack("i", xucred[4:8])[0]
print(f"PEER uid={cr_uid}", flush=True)
conn.close()
```

- [ ] **Step 2: Write the driver**

Create `task0-broker/probes/run-q4.sh`:

```bash
#!/bin/bash
# Start the server as _ccfido, connect as sean, confirm reachability + peer uid.
set -u
sudo cp task0-broker/probes/peercred_server.py /var/ccfido/peercred_server.py
sudo chown _ccfido /var/ccfido/peercred_server.py
sudo -u _ccfido /usr/bin/python3 /var/ccfido/peercred_server.py & SPID=$!
sleep 1
echo "=== connect as sean (uid $(id -u)) ==="
python3 - <<'PY'
import socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect("/var/ccfido/gate.sock")
print("sean connected OK")
s.close()
PY
sleep 1; kill "$SPID" 2>/dev/null
```

- [ ] **Step 3: Run it**

Run: `bash task0-broker/probes/run-q4.sh`
Expected: server prints `listening … as uid=<ccfido>`, `sean connected OK`, and `PEER uid=501`.

- [ ] **Step 4: Record + Commit**

Append `## Q4 — socket + LOCAL_PEERCRED` with the output. Then:
```bash
git add task0-broker/probes/peercred_server.py task0-broker/probes/run-q4.sh task0-broker/REPORT.md
git commit -m "test(broker-gate): Q4 unix socket + LOCAL_PEERCRED"
```

---

### Task 6: Assemble the gate verdict + clean up all machine state

Finalizes the report with a scoreboard and go/no-go, and removes every artifact the gate created (`_ccfido` account, `/var/ccfido`, any leftover daemon/plist).

**Files:**
- Append: `task0-broker/REPORT.md`
- Uses: `task0-broker/probes/account-teardown.sh` (Task 2)

- [ ] **Step 1: Write the scoreboard**

Append to `task0-broker/REPORT.md` a `## Scoreboard` table (Q1 daemon-USB-sign, Q2 cross-process touch, Q3 uchg file+dir+owner, Q4 socket/peercred) each ✅/⛔️/🟡, and a one-line **GO / NO-GO**: GO only if Q1 and Q3 are ✅.

- [ ] **Step 2: Tear down all machine state (sudo)**

Run:
```bash
sudo launchctl bootout system/com.cc-fido-gate.brokerprobe 2>/dev/null; sudo rm -f /Library/LaunchDaemons/com.cc-fido-gate.brokerprobe.plist
sudo rm -rf /var/ccfido
bash task0-broker/probes/account-teardown.sh
echo "verify gone:"; id _ccfido 2>&1 || echo "_ccfido removed"; ls /var/ccfido 2>&1 || echo "/var/ccfido removed"
```
Expected: `_ccfido removed` and `/var/ccfido removed`.

- [ ] **Step 3: Commit**

```bash
git add task0-broker/REPORT.md
git commit -m "docs(broker-gate): feasibility scoreboard + go/no-go; teardown"
```

---

## Self-Review

**Spec coverage (Section 4 feasibility gate):** Q1 daemon USB signing → Task 4 ✅; Q2 cross-process touch binding → Task 4 (concurrent dialog) ✅; Q3 `uchg` on APFS → Task 1 (sean locked out) + Task 4 (owner toggles) ✅; Q4 socket + `LOCAL_PEERCRED` → Task 5 ✅. Supporting install mechanics (service account, key custody) → Tasks 2–3. Cleanup → Task 6. All four Section-4 questions covered.

**Placeholder scan:** every script is complete and runnable; every run step has an exact command and expected output; no TBD/TODO.

**Type/name consistency:** `_ccfido`, `/var/ccfido`, `/var/ccfido/gate_sk`, `allowed_signers`, namespace `cc-fido-gate@example.test`, principal `gate-principal`, daemon label `com.cc-fido-gate.brokerprobe` used identically across Tasks 2–6.

**Note on downstream plan:** this gate is a prerequisite. Once it reports **GO**, the next step is to write the v2 *implementation* plan (broker daemon, file/dir custody, best-effort hook, install/enroll CLIs) as a separate plan. A **NO-GO** on Q1 or Q3 sends us back to the spec.
