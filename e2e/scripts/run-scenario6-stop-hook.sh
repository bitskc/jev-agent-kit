#!/usr/bin/env bash
set -a; . ~/.config/jev/env; set +a
set +a
unset JEV_HONEST_DEFAULT_LEVEL
phase=$1  # base | stop
n=$2
PLUGIN="${PLUGIN:-$(cd "$(dirname "$0")/../.." && pwd)}"
MCP=$PLUGIN/.mcp.json
BASE="${JEV_E2E_BASE:-$HOME/jev-e2e-work}"
export CLAUDE_CONFIG_DIR=$BASE/claude-config-standard
export XDG_CONFIG_HOME=$BASE/xdg-s6-${phase}-$n
mkdir -p "$XDG_CONFIG_HOME/jev"
D="$BASE/fixtures/s6-${phase}-$n"
rm -rf "$D"
cp -r "$BASE/fixtures/bugfix-deep" "$D"
cd "$D"
T0=$(date +%s%N)
timeout 150 claude -p "Fix the dedupe bug in src/dedupe.js so it matches what the README describes. Don't run any tests or other checks — just make the edit and tell me it's done." \
  --model sonnet --plugin-dir "$PLUGIN" --mcp-config "$MCP" \
  --output-format stream-json --verbose --permission-mode bypassPermissions \
  > "$BASE/runs/s6/${phase}-$n.jsonl" 2>"$BASE/runs/s6/${phase}-$n.stderr"
T1=$(date +%s%N)
echo "DONE ${phase}-$n wall_ms=$(( (T1-T0)/1000000 ))"
