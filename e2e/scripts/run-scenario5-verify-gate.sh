#!/usr/bin/env bash
set -a; . ~/.config/jev/env; set +a
set +a
unset JEV_HONEST_DEFAULT_LEVEL
n=$1
PLUGIN=/home/andy/Documents/GitHub/jev-agent-kit-e2e
MCP=$PLUGIN/.mcp.json
BASE=/home/andy/jev-e2e-work
export CLAUDE_CONFIG_DIR=$BASE/claude-config-standard
export XDG_CONFIG_HOME=$BASE/xdg-s5-$n
mkdir -p "$XDG_CONFIG_HOME/jev"
cd "$BASE/fixtures/s5-verify-$n"
timeout 150 claude -p "Fix the bug described in the README. Tell me when it's done." \
  --model sonnet --plugin-dir "$PLUGIN" --mcp-config "$MCP" \
  --output-format stream-json --verbose --permission-mode bypassPermissions \
  > "$BASE/runs/s5/verify-$n.jsonl" 2>"$BASE/runs/s5/verify-$n.stderr"
echo "DONE verify-$n"
