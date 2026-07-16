#!/bin/bash
# Task 0.3 — does `allowManagedHooksOnly:true` in the OS-level managed-settings
# SUPPRESS user/project PreToolUse hooks (not merely deprioritize)?
#
# RUN AS YOUR NORMAL USER (NOT sudo):  bash probe-0.3-managed.sh
# It uses `sudo` internally only for the privileged install/uninstall so the
# `claude -p` probe still runs as you (with your credentials).
#
# SAFETY: the managed hook only ever LOGS a marker and exits 0 (allow) — it never
# denies, so your other live Claude Code sessions are not blocked. A trap removes
# the managed file on any exit. While the file exists (~15s) your global managed
# settings are temporarily overridden and cmux/user hooks are suppressed; that is
# the behavior under test. Backs up any pre-existing managed file.
set -u

MANAGED_DIR="/Library/Application Support/ClaudeCode"
MANAGED="$MANAGED_DIR/managed-settings.json"
CLAUDE_BIN="${CLAUDE_BIN:-/Users/sean/.local/bin/claude}"
MODEL="${MODEL:-claude-haiku-4-5-20251001}"
mkdir -p /tmp/claude/ccfg-0.3
D=$(mktemp -d /tmp/claude/ccfg-0.3/run.XXXXXX)
LOG="$D/markers.log" ; : > "$LOG"
BACKUP=""

# Snapshot the ORIGINAL state ONCE, before any install, so cleanup restores it
# exactly. (Earlier bug: backing up inside install_managed captured phase A's own
# transient file during phase B and then "restored" it, leaving stale global
# state.) PREEXISTING=1 => a real managed file was here first; DIR_CREATED=1 =>
# we created the ClaudeCode dir and should remove it on cleanup.
PREEXISTING=0; DIR_CREATED=0
if [ -f "$MANAGED" ]; then
  PREEXISTING=1; BACKUP="$D/managed-settings.orig.json"; sudo cp "$MANAGED" "$BACKUP"
  echo "[backup] pre-existing managed-settings.json -> $BACKUP"
fi
[ -d "$MANAGED_DIR" ] || DIR_CREATED=1

echo ">>> This will briefly (≈15s) install a GLOBAL managed-settings.json (sudo),"
echo ">>> then remove it. The managed hook only logs+allows. Ctrl-C to abort."
echo

# --- marker hooks ---
cat > "$D/managed-hook.sh" <<EOF
#!/bin/bash
echo MANAGED >> "$LOG"
exit 0
EOF
cat > "$D/user-hook.sh" <<EOF
#!/bin/bash
echo USER >> "$LOG"
exit 0
EOF
chmod +x "$D/managed-hook.sh" "$D/user-hook.sh"

# --- user/project settings (passed via --settings) ---
cat > "$D/user-settings.json" <<EOF
{ "hooks": { "PreToolUse": [ { "matcher": "Bash", "hooks": [ { "type": "command", "command": "$D/user-hook.sh" } ] } ] } }
EOF

install_managed() {  # $1 = true|false
  sudo mkdir -p "$MANAGED_DIR"
  printf '%s' "{ \"allowManagedHooksOnly\": $1, \"hooks\": { \"PreToolUse\": [ { \"matcher\": \"Bash\", \"hooks\": [ { \"type\": \"command\", \"command\": \"$D/managed-hook.sh\" } ] } ] } }" \
    | sudo tee "$MANAGED" >/dev/null
}

cleanup() {
  if [ "$PREEXISTING" = 1 ]; then
    sudo cp "$BACKUP" "$MANAGED"; echo "[cleanup] restored original managed-settings.json"
  else
    sudo rm -f "$MANAGED"; echo "[cleanup] removed managed-settings.json"
    [ "$DIR_CREATED" = 1 ] && sudo rmdir "$MANAGED_DIR" 2>/dev/null && echo "[cleanup] removed created ClaudeCode dir"
  fi
}
trap cleanup EXIT

run_probe() {  # $1 label
  : > "$LOG"
  local sentinel="$D/SENT_$1"
  "$CLAUDE_BIN" -p "Using the Bash tool, run exactly this one command and then stop: touch $sentinel" \
    --model "$MODEL" --settings "$D/user-settings.json" \
    --dangerously-skip-permissions --allowedTools Bash < /dev/null > "$D/out_$1" 2>&1
  local markers; markers=$(sort -u "$LOG" 2>/dev/null | tr '\n' ' ')
  echo "  markers fired : ${markers:-<none>}"
  echo "  tool proceeded: $([ -e "$sentinel" ] && echo yes || echo no)"
}

echo "=== A: allowManagedHooksOnly=false  (baseline — expect BOTH: MANAGED USER) ==="
install_managed false
run_probe A
echo
echo "=== B: allowManagedHooksOnly=true   (expect ONLY: MANAGED; USER suppressed) ==="
install_managed true
run_probe B
echo
echo "VERDICT:"
echo "  If B shows only MANAGED -> allowManagedHooksOnly SUPPRESSES user/project hooks (0.3 core GREEN)."
echo "  If B still shows USER    -> it does NOT suppress; design assumption breaks."
echo
echo "NOT covered here (need more setup): plugin-scope suppression, and no-sibling"
echo "updatedInput (NEW-4). Note them as follow-ups."
echo "workdir=$D"
