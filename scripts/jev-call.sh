#!/usr/bin/env bash
# jev-call: call one tool on the jev-mcp server from the shell (for agents without MCP wired up).
#   jev-call kit_guard_command '{"command":"scp db.dump prod:/tmp","cwd":"'"$PWD"'"}'
#   jev-call jev_classify '{"items":[{"id":"1","text":"SHELL OIL 5742"}],"classes":[{"id":"Fuel","description":"fuel"},{"id":"Meals","description":"food"}]}'
# Env: JEV_MCP_TOKEN (required, never printed), JEV_MCP_URL (required). Prints the tool's JSON result; exit 1 on error.
set -u
[ $# -ge 1 ] || { echo "usage: jev-call <tool> [json-args]" >&2; exit 2; }
tool="$1"; args="${2:-{\}}"
: "${JEV_MCP_TOKEN:?set JEV_MCP_TOKEN (never hardcode it)}"
url="${JEV_MCP_URL:?set JEV_MCP_URL, e.g. https://<your-worker>.workers.dev/mcp}"
case "$url" in https://*) ;; *) echo "jev-call: JEV_MCP_URL must be https://" >&2; exit 2;; esac
# a token with a newline (or a quote/backslash) would inject extra curl -K config directives on the line below
case "$JEV_MCP_TOKEN" in *[![:graph:]]*|*\"*|*\\*) echo "jev-call: JEV_MCP_TOKEN contains invalid characters" >&2; exit 2;; esac
# tool name and args travel on stdin/env, not argv: /proc/*/cmdline is world-readable on a shared host.
body=$(JEV_TOOL="$tool" JEV_ARGS="$args" python3 - 2>/dev/null <<'PY'
import json, os
print(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                  "params": {"name": os.environ["JEV_TOOL"], "arguments": json.loads(os.environ["JEV_ARGS"])}}))
PY
) || { echo "jev-call: arguments are not valid JSON" >&2; exit 2; }
# token via curl config on stdin (-K -), body via /dev/fd — neither on the command line; https only, no redirects
resp=$(printf 'header = "authorization: Bearer %s"\n' "$JEV_MCP_TOKEN" | curl -sS -K - --proto '=https' --tlsv1.2 \
  --max-time "${JEV_CALL_TIMEOUT:-60}" -X POST "$url" \
  -H "content-type: application/json" -H "accept: application/json, text/event-stream" \
  --data-binary @<(printf '%s' "$body")) || { echo "jev-call: request failed" >&2; exit 1; }
printf '%s' "$resp" | python3 -c '
import json, sys
raw = sys.stdin.read()
for line in raw.splitlines():
    line = line.strip()
    if line.startswith("data:"): line = line[5:].strip()
    if line.startswith("{"):
        d = json.loads(line); break
else:
    print("jev-call: unexpected response: " + raw[:200], file=sys.stderr); sys.exit(1)
if "error" in d: print("jev-call: " + json.dumps(d["error"])[:300], file=sys.stderr); sys.exit(1)
r = d["result"]; t = r["content"][0]["text"]
print(t)
sys.exit(1 if r.get("isError") else 0)
'
