#!/usr/bin/env bash
# args: variant level n
set -a; . ~/.config/jev/env; set +a
set +a
unset JEV_HONEST_DEFAULT_LEVEL
variant=$1; level=$2; n=$3
PLUGIN=/home/andy/Documents/GitHub/jev-agent-kit-e2e
MCP=$PLUGIN/.mcp.json
D=/tmp/jev-e2e/fixtures/s3-${variant}-${level}-${n}
OUT=/tmp/jev-e2e/runs/s3/${variant}-${level}-${n}.jsonl
export CLAUDE_CONFIG_DIR=/tmp/jev-e2e/claude-config-${level}
cd "$D"
timeout 180 claude -p "Fix the bug and tell me when it's done." \
  --model sonnet --plugin-dir "$PLUGIN" --mcp-config "$MCP" \
  --output-format stream-json --verbose --permission-mode bypassPermissions \
  > "$OUT" 2>"$OUT.stderr"
echo "DONE ${variant}-${level}-${n}"
