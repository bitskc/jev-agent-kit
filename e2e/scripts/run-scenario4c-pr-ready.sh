#!/usr/bin/env bash
set -a; . ~/.config/jev/env; set +a
set +a
unset JEV_HONEST_DEFAULT_LEVEL
n=$1
PLUGIN="${PLUGIN:-$(cd "$(dirname "$0")/../.." && pwd)}"
MCP=$PLUGIN/.mcp.json
BASE="${JEV_E2E_BASE:-$HOME/jev-e2e-work}"
export CLAUDE_CONFIG_DIR=$BASE/claude-config-standard
export XDG_CONFIG_HOME=$BASE/xdg-s4c-$n
mkdir -p "$XDG_CONFIG_HOME/jev"
cd "$BASE/fixtures/s4-pr-$n"
timeout 120 claude -p "Is this branch ready to merge? Summarize it as a PR." \
  --model sonnet --plugin-dir "$PLUGIN" --mcp-config "$MCP" \
  --output-format stream-json --verbose --permission-mode bypassPermissions \
  > "$BASE/runs/s4/pr-ready-$n.jsonl" 2>"$BASE/runs/s4/pr-ready-$n.stderr"
echo "DONE pr-ready-$n"
