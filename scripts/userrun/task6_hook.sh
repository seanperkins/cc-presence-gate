#!/bin/bash
set -eu -o pipefail
REPO="$(cd "$(dirname "$0")/../.." && pwd)"; CLAUDE_BIN="${CLAUDE_BIN:-/Users/sean/.local/bin/claude}"
swift build -c release --package-path "$REPO"; BIN="$REPO/.build/release/cc-fido"
sudo mkdir -p /opt/cc-fido-gate
POLICY_CAND=/opt/cc-fido-gate/policy.json.new
trap 'sudo rm -f "$POLICY_CAND"; [ -n "${DPID:-}" ] && sudo kill "$DPID" 2>/dev/null || true' EXIT
"$BIN" _render-policy "$REPO/install/policy.json" "$HOME" | sudo tee "$POLICY_CAND" >/dev/null
sudo test -s "$POLICY_CAND"
sudo mv "$POLICY_CAND" /opt/cc-fido-gate/policy.json
sudo chown root:wheel /opt/cc-fido-gate/policy.json; sudo chmod 644 /opt/cc-fido-gate/policy.json
mkdir -p /tmp/claude/ccfg-task6; D=$(mktemp -d /tmp/claude/ccfg-task6/run.XXXXXX)
cat > "$D/settings.json" <<JSON
{ "hooks": { "PreToolUse": [ { "matcher": "Write", "hooks": [ { "type": "command", "command": "$BIN hook", "timeout": 90 } ] } ] } }
JSON
sudo -u _ccfido "$BIN" daemon & DPID=$!; sleep 1
echo ">>> APPROVE + TOUCH when the dialog appears <<<"
"$CLAUDE_BIN" -p "Using the Write tool, create $D/.env with contents FOO=bar, then stop." \
  --model claude-haiku-4-5-20251001 --settings "$D/settings.json" --dangerously-skip-permissions --allowedTools Write < /dev/null
# .env lives in the per-run $D (fresh each run) so a stale file can't false-PASS without a new touch:
[ -f "$D/.env" ] && echo "PASS: gated write completed after touch" || echo "note: denied (expected if touch withheld)"
sudo kill "$DPID" 2>/dev/null
