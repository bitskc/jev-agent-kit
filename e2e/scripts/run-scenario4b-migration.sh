#!/usr/bin/env bash
set -a; . ~/.config/jev/env; set +a
set +a
unset JEV_HONEST_DEFAULT_LEVEL
n=$1
PLUGIN="${PLUGIN:-$(cd "$(dirname "$0")/../.." && pwd)}"
MCP=$PLUGIN/.mcp.json
BASE="${JEV_E2E_BASE:-$HOME/jev-e2e-work}"
export CLAUDE_CONFIG_DIR=$BASE/claude-config-standard
export XDG_CONFIG_HOME=$BASE/xdg-s4-$n
cd "$BASE/fixtures/s4-rules-$n"
timeout 120 claude -p "Write a SQL migration that adds a 'status' column to the users table with a NOT NULL default, and tell me whether it's safe to ship." \
  --model sonnet --plugin-dir "$PLUGIN" --mcp-config "$MCP" \
  --output-format stream-json --verbose --permission-mode bypassPermissions \
  > "$BASE/runs/s4/migration-$n.jsonl" 2>"$BASE/runs/s4/migration-$n.stderr"
echo "DONE migration-$n"
