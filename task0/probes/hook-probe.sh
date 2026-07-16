#!/bin/bash
# Task 0 PreToolUse hook probe.
#
# Usage: hook-probe.sh <mode> <logdir>
#
# Behaves per <mode> so we can characterize how Claude Code treats a hook that
# blocks, denies, times out, is killed, or crashes. Every invocation appends a
# record (mode, pid, ppid, stdin payload, full env) to <logdir>/hook.log so we
# can answer Task 0.6 (what env does CC hand a PreToolUse hook) at the same time.
#
# Decision channels under test (per design.md):
#   exit 0 + no output            -> allow (passthrough)
#   exit 0 + deny JSON on stdout  -> deny
#   exit 2                        -> deny
#   exit 1                        -> non-blocking error (expected: proceeds)
#   killed / timed out / crashed  -> THE load-bearing unknown (0.1b)

mode="$1"
logdir="$2"
[ -z "$logdir" ] && logdir="$(dirname "$0")"

stdin_payload="$(cat)"

{
  echo "===== HOOK INVOCATION ====="
  echo "mode=$mode"
  echo "pid=$$ ppid=$PPID"
  echo "date_epoch=$(date +%s)"
  echo "----- STDIN -----"
  echo "$stdin_payload"
  echo "----- ENV -----"
  env | sort
  echo "===== END INVOCATION ====="
} >> "$logdir/hook.log" 2>&1

# Record the PID so an external killer can target this invocation.
echo "$$" > "$logdir/hook.pid.$mode" 2>/dev/null

deny_json='{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"cc-fido-gate task0 probe: DENY"}}'

case "$mode" in
  allow0)
    # Passthrough: clean exit, no decision.
    exit 0
    ;;
  deny0)
    # Clean exit with an explicit deny on stdout.
    echo "$deny_json"
    exit 0
    ;;
  exit2)
    # Non-zero exit 2 -> documented deny channel.
    echo "cc-fido-gate task0 probe: exit 2 deny" >&2
    exit 2
    ;;
  exit1)
    # Non-zero exit 1 -> documented non-blocking error.
    echo "cc-fido-gate task0 probe: exit 1 (should NOT block)" >&2
    exit 1
    ;;
  watchdog2)
    # Simulate an internal watchdog that fires *before* the outer hook timeout:
    # brief work, then exit 2. Hook config gives this a generous timeout.
    sleep 1
    echo "cc-fido-gate task0 probe: watchdog exit 2" >&2
    exit 2
    ;;
  timeout)
    # Sleep well past the outer hook timeout so CC must kill us. Does the tool
    # get DENIED (fail-closed) or PROCEED (fail-open)? -- the load-bearing Q.
    sleep 60
    # If we somehow reach here, we did NOT get killed; allow so the sentinel
    # distinguishes "killed->?" from "outlived timeout->allowed".
    exit 0
    ;;
  crash)
    # Die by uncatchable signal mid-ceremony (simulates a crash / external -9).
    sleep 1
    kill -9 $$
    ;;
  *)
    echo "hook-probe: unknown mode '$mode'" >&2
    exit 3
    ;;
esac
