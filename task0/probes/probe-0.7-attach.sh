#!/bin/bash
# Task 0.7 — running-process integrity: can a same-uid debugger attach?
#
# The gate/broker binary must resist a same-uid `lldb -p` / task_for_pid attach
# (else the agent forces exit 0 / allow with zero touches). Characterize the
# platform default here:
#   (1) attach to a NON-hardened same-uid process (a plain `sleep`) -> if this
#       SUCCEEDS, an unhardened gate binary is trivially bypassable.
#   (2) attach to a HARDENED-runtime signed process (the shipped `claude`) ->
#       this should FAIL, showing hardened-runtime is the sufficient mitigation.
# A wall-clock guard prevents a taskgated GUI auth prompt from hanging the probe.
set -u

WALL=20
guard() { "$@" & local p=$!; ( sleep "$WALL"; kill -9 "$p" 2>/dev/null ) & local w=$!; wait "$p"; local rc=$?; kill "$w" 2>/dev/null; return $rc; }

echo "=== lldb present? ==="
command -v lldb || { echo "lldb not installed (Xcode CLT). Skipping attach; task_for_pid unknowable via lldb."; exit 0; }

echo; echo "=== (1) attach to NON-hardened same-uid process (sleep) ==="
/bin/sleep 120 & TARGET=$!
sleep 0.5
echo "target sleep pid=$TARGET (uid=$(id -u))"
guard lldb --batch -o "process attach --pid $TARGET" -o "detach" -o "quit" 2>&1
echo "lldb rc=$?"
kill "$TARGET" 2>/dev/null

echo; echo "=== (2) attach to HARDENED-runtime process (a running claude) ==="
# Spawn a short-lived hardened claude to attach to (its --help stays up briefly);
# simpler: find any running claude pid.
CPID=$(pgrep -x -n -u "$(id -u)" claude 2>/dev/null | head -1)
if [ -z "$CPID" ]; then
  # fall back to the node-based version binary process name
  CPID=$(pgrep -n -u "$(id -u)" -f 'share/claude/versions' 2>/dev/null | head -1)
fi
if [ -n "$CPID" ]; then
  echo "hardened target pid=$CPID"
  guard lldb --batch -o "process attach --pid $CPID" -o "detach" -o "quit" 2>&1
  echo "lldb rc=$?"
else
  echo "no running claude process found to attach to (skip case 2)"
fi
