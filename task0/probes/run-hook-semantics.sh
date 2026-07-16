#!/bin/bash
# Task 0.1 / 0.2 / 0.6 driver.
#
# For each behavior <mode>, stand up an isolated settings file with a PreToolUse
# hook (Bash matcher) wired to hook-probe.sh, then drive `claude -p` (headless,
# real binary, --dangerously-skip-permissions) to run a Bash command that
# touches a unique ABSOLUTE sentinel path. Sentinel present afterwards => the
# tool PROCEEDED; absent => it was DENIED. That is the fail-open/fail-closed
# observable. Sentinel is absolute, so cwd is irrelevant.
#
# Requires network + credentials, so this must run with the sandbox disabled.
set -u

CLAUDE_BIN="${CLAUDE_BIN:-/Users/sean/.local/bin/claude}"
MODEL="${MODEL:-claude-haiku-4-5-20251001}"
WALL="${WALL:-70}"   # per-invocation wall-clock guard (seconds)
PROBE="$(cd "$(dirname "$0")" && pwd)/hook-probe.sh"
# Root under /tmp/claude so the *inner* claude -p Bash sandbox permits sentinel
# writes (its write-allowlist includes /tmp/claude). Otherwise a sandbox refusal
# masquerades as a hook DENY and poisons the observable.
mkdir -p /tmp/claude/ccfg-task0
RUNROOT="${RUNROOT:-$(mktemp -d /tmp/claude/ccfg-task0/run.XXXXXX)}"
RESULTS="$RUNROOT/results.tsv"
LOGDIR="$RUNROOT/logs"
mkdir -p "$LOGDIR"
chmod +x "$PROBE"

printf 'mode\touter_timeout\texpected\tsentinel\tobserved\tclaude_exit\n' > "$RESULTS"

# mode:outer_hook_timeout(seconds):expected_result
MATRIX=(
  "allow0:30:PROCEED"
  "deny0:30:DENY"
  "exit2:30:DENY"
  "exit1:30:PROCEED"
  "watchdog2:30:DENY"
  "timeout:5:UNKNOWN"
  "crash:30:UNKNOWN"
)

run_with_wall() {  # $1=wall secs; rest=command
  local wall="$1"; shift
  "$@" &
  local pid=$!
  ( sleep "$wall"; kill -TERM "$pid" 2>/dev/null; sleep 3; kill -9 "$pid" 2>/dev/null ) &
  local wpid=$!
  wait "$pid"; local rc=$?
  kill "$wpid" 2>/dev/null
  return $rc
}

for entry in "${MATRIX[@]}"; do
  mode="${entry%%:*}"; rest="${entry#*:}"
  otimeout="${rest%%:*}"; expected="${rest##*:}"

  proj="$RUNROOT/proj_$mode"
  mkdir -p "$proj"
  sentinel="$proj/SENTINEL_$mode"
  settings="$proj/settings.json"

  cat > "$settings" <<JSON
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          { "type": "command", "command": "'$PROBE' $mode '$LOGDIR'", "timeout": $otimeout }
        ]
      }
    ]
  }
}
JSON

  prompt="You are a shell runner. Using the Bash tool, run exactly this one command and then stop, reporting only success or the denial reason: touch $sentinel"

  echo ">>> mode=$mode outer_timeout=${otimeout}s expected=$expected"
  out="$LOGDIR/claude_$mode.out"
  run_claude() { "$CLAUDE_BIN" -p "$prompt" \
      --model "$MODEL" \
      --settings "$settings" \
      --dangerously-skip-permissions \
      --allowedTools Bash < /dev/null > "$out" 2>&1; }
  run_with_wall "$WALL" run_claude
  cexit=$?

  if [ -e "$sentinel" ]; then observed="PROCEED"; else observed="DENY"; fi
  printf '%s\t%ss\t%s\t%s\t%s\t%s\n' "$mode" "$otimeout" "$expected" \
    "$([ -e "$sentinel" ] && echo present || echo absent)" "$observed" "$cexit" >> "$RESULTS"
  echo "    observed=$observed (claude exit $cexit)"
done

echo
echo "===== RESULTS ($RESULTS) ====="
column -t -s $'\t' "$RESULTS"
echo
echo "RUNROOT=$RUNROOT"
