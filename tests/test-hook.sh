#!/usr/bin/env bash
# Runs the hook against the live server. Requires JEV_MCP_TOKEN in the environment (never printed).
#   JEV_MCP_URL=https://<your-worker>.workers.dev/mcp JEV_MCP_TOKEN=$(cat token-file) tests/test-hook.sh
set -u
hook="$(cd "$(dirname "$0")/../hooks" && pwd)/jev-guard-hook.sh"
: "${JEV_MCP_TOKEN:?set JEV_MCP_TOKEN}"; : "${JEV_MCP_URL:?set JEV_MCP_URL}"
pass=0; fail=0
run() { # name expect(decision or none) stdin-json [env assignments...]
  local name="$1" expect="$2" input="$3"; shift 3
  local t0=$(date +%s.%N) out rc
  out=$(printf '%s' "$input" | env "$@" "$hook" 2>/dev/null); rc=$?
  local ms=$(python3 -c "print(int(($(date +%s.%N)-$t0)*1000))")
  local got=none
  [ -n "$out" ] && got=$(printf '%s' "$out" | python3 -c 'import json,sys;print(json.load(sys.stdin)["hookSpecificOutput"]["permissionDecision"])')
  if [ "$got" = "$expect" ] && [ $rc -eq 0 ]; then pass=$((pass+1)); s=PASS; else fail=$((fail+1)); s=FAIL; fi
  printf '%-4s %-34s expect=%-5s got=%-5s exit=%s %5sms\n' "$s" "$name" "$expect" "$got" "$rc" "$ms"
  [ -n "$out" ] && printf '       %s\n' "$(printf '%s' "$out" | python3 -c 'import json,sys;print(json.load(sys.stdin)["hookSpecificOutput"]["permissionDecisionReason"][:150])')"
}
ev() { python3 -c 'import json,sys;print(json.dumps({"tool_name":sys.argv[1],"tool_input":json.loads(sys.argv[2]),"cwd":"/tmp","session_id":"t","hook_event_name":"PreToolUse"}))' "$1" "$2"; }

run "ls -> allow"               none  "$(ev Bash '{"command":"ls"}')" X=1
run "cat .env -> deny"          deny  "$(ev Bash '{"command":"cat .env"}')" X=1
run "scp db.dump prod:/tmp -> ask" ask "$(ev Bash '{"command":"scp db.dump prod:/tmp"}')" X=1
run "Read ~/.ssh/id_rsa -> deny" deny "$(ev Read '{"file_path":"/root/.ssh/id_rsa"}')" X=1
run "Edit tool -> ignored"      none  "$(ev Edit '{"file_path":"a.txt"}')" X=1
run "shadow mode never blocks"  none  "$(ev Bash '{"command":"cat .env"}')" JEV_GUARD_MODE=shadow
run "fail-open: no token"       none  "$(ev Bash '{"command":"cat .env"}')" JEV_MCP_TOKEN=
run "fail-open: wrong token"    none  "$(ev Bash '{"command":"cat .env"}')" JEV_MCP_TOKEN=wrong
run "fail-open: timeout (2s cap)" none "$(ev Bash '{"command":"cat .env"}')" JEV_MCP_URL=http://10.255.255.1/mcp
run "fail-open: bad JSON stdin" none  "not json" X=1
echo "pass=$pass fail=$fail"; [ $fail -eq 0 ]
