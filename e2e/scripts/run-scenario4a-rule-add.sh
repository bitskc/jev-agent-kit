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
PROMPT='honest-jev rule add: when describing a database migration as safe ask "Was it run against a copy of prod data?" evidence "the command and its output"'
timeout 90 claude -p "$PROMPT" \
  --model sonnet --plugin-dir "$PLUGIN" --mcp-config "$MCP" \
  --output-format stream-json --verbose --permission-mode bypassPermissions \
  > "$BASE/runs/s4/rule-add-$n.jsonl" 2>"$BASE/runs/s4/rule-add-$n.stderr"
echo "DONE rule-add-$n"
