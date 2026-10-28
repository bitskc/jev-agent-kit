#!/usr/bin/env bash
# Offline tests for the shell pieces: install.sh, update.sh --timer, the statusline badge, jev-call exit codes, and the
# guard hook's local decisions (oversized input, non-https URL). No network: curl is stubbed on PATH.
#   bash tests/test-scripts.sh
set -u
root="$(cd "$(dirname "$0")/.." && pwd)"
pass=0; fail=0
ok() { if [ "$1" = "$2" ]; then pass=$((pass+1)); printf 'PASS %s\n' "$3"; else fail=$((fail+1)); printf 'FAIL %s\n     expected: %s\n     got:      %s\n' "$3" "$2" "$1"; fi; }
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT

# ── statusline badge ────────────────────────────────────────────────────────────
sl="$root/hooks/jev-honest-statusline.sh"
cfg="$tmp/cfg"; mkdir -p "$cfg"
ok "$(CLAUDE_CONFIG_DIR=$cfg bash "$sl")" "" "statusline: no flag -> empty"
for m in off soft standard strict; do printf '%s\n' "$m" > "$cfg/.jev-honest-active"; eval "got_$m=\$(CLAUDE_CONFIG_DIR=$cfg bash \"$sl\")"; done
ok "$got_off" "" "statusline: off -> empty"
ok "$got_soft" $'\033[38;5;130m[HONEST:SOFT]\033[0m' "statusline: soft badge"
ok "$got_standard" $'\033[38;5;130m[HONEST]\033[0m' "statusline: standard badge"
ok "$got_strict" $'\033[38;5;130m[HONEST:STRICT]\033[0m' "statusline: strict badge"
printf 'BOGUS\n' > "$cfg/.jev-honest-active"; ok "$(CLAUDE_CONFIG_DIR=$cfg bash "$sl")" "" "statusline: unrecognised level -> empty, not a bogus badge"

# ── install.sh: both targets, project scope with spaces, hooks + helpers landed ──
H="$tmp/home"; mkdir -p "$H/.omp/agent" "$H/.claude"
HOME=$H bash "$root/install.sh" --both >/dev/null
ok "$(ls "$H/.claude/skills" | tr '\n' ' ')" "$(ls "$H/.omp/agent/skills" | tr '\n' ' ')" "install: same skills in both agent dirs"
ok "$([ -d "$H/.claude/skills/jev-honest" ] && echo yes)" yes "install: jev-honest skill present"
ok "$([ -x "$H/.local/bin/jev-call" ] && [ -x "$H/.local/bin/jev-update" ] && echo yes)" yes "install: jev-call + jev-update executable"
ok "$([ -x "$H/.local/share/jev-agent-skills/hooks/honest/jev-honest-activate.js" ] && [ -f "$H/.local/share/jev-agent-skills/hooks/omp/jev-honest.ts" ] && echo yes)" yes "install: honest hooks shipped"
ok "$([ -f "$H/.local/share/jev-agent-skills/hooks/honest/rules.default.json" ] && echo yes)" yes "install: rules.default.json shipped alongside the honest hooks"
ok "$(node -e "const rt=require('$H/.local/share/jev-agent-skills/hooks/honest/jev-honest-runtime.js'); console.log(rt.rules()[0] && rt.rules()[0].id)")" "pr-gstack-reviewed" "install: default rule resolves from the installed location"
P="$tmp/My Project"; mkdir -p "$P"
HOME=$H bash "$root/install.sh" --project "$P" >/dev/null
ok "$([ -f "$P/.claude/skills/jev-honest/SKILL.md" ] && [ -f "$P/.omp/skills/jev-honest/SKILL.md" ] && echo yes)" yes "install: --project path with spaces"
ok "$([ -f "$H/.local/share/jev-agent-skills/skills/jev-honest/SKILL.md" ] && echo yes)" yes "install: --project also populates \$share/skills for the honest hook's own lookup"
actcfg="$tmp/actcfg"; mkdir -p "$actcfg"; printf 'standard\n' > "$actcfg/.jev-honest-active"
actlen=$(CLAUDE_CONFIG_DIR="$actcfg" node "$H/.local/share/jev-agent-skills/hooks/honest/jev-honest-activate.js" | wc -c)
ok "$([ "$actlen" -gt 3000 ] && echo yes)" yes "install: --project activate output is the real SKILL.md (len=$actlen), not the ~700-char fallback"

# ── update.sh --timer: ExecStart quoting; --check on a missing release ─────────
stub="$tmp/bin"; mkdir -p "$stub"
cat > "$stub/curl" <<'EOF'
#!/usr/bin/env bash
# offline stub: GitHub API lookups answer like a repo with no releases; archive fetch copies the local tree
for a in "$@"; do case "$a" in
  *api.github.com/*releases/latest) echo '{"message":"Not Found"}'; exit 22;;
  *api.github.com/*commits/*) echo '{"sha":"0000000000000000000000000000000000000000"}'; exit 0;;
  *github.com/*/archive/*.tar.gz) out=""; for b in "$@"; do [ "$prev" = -o ] && out="$b"; prev="$b"; done
     tar -czf "$out" -C "$(dirname "$REPO_ROOT")" --transform "s|^$(basename "$REPO_ROOT")|jev-agent-kit-0000|" --exclude=.git --exclude=node_modules "$(basename "$REPO_ROOT")"; exit 0;;
esac; done; exit 1
EOF
chmod +x "$stub/curl"
cat > "$stub/systemctl" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x "$stub/systemctl"
U="$tmp/uhome"; mkdir -p "$U/.omp/agent" "$U/.claude" "$U/.config/systemd/user"
got=$(HOME=$U PATH="$stub:$PATH" REPO_ROOT="$root" bash "$root/update.sh" --check 2>&1); ok "$?" 1 "update: no release -> exit 1"
ok "$got" "no release found for bitskc/jev-agent-kit; set JEV_REF to install an unpinned ref" "update: no release -> one clean line"
HOME=$U PATH="$stub:$PATH" REPO_ROOT="$root" JEV_REF=main bash "$root/update.sh" --timer >/dev/null 2>&1
ok "$(grep ExecStart "$U/.config/systemd/user/jev-skill-sync.service")" "ExecStart=$U/.local/bin/jev-update" "update: --timer with no args -> bare ExecStart"
ok "$(cat "$U/.local/share/jev-agent-skills/installed-ref")" "0000000000000000000000000000000000000000" "update: installed-ref stamp written"
HOME=$U PATH="$stub:$PATH" REPO_ROOT="$root" JEV_REF=main bash "$root/update.sh" --timer --project "$tmp/a\"b c" >/dev/null 2>&1
ok "$(grep ExecStart "$U/.config/systemd/user/jev-skill-sync.service")" "ExecStart=$U/.local/bin/jev-update \"--project\" \"$tmp/a\\\"b c\"" "update: --timer quotes args systemd-style"
ok "$(HOME=$U PATH="$stub:$PATH" REPO_ROOT="$root" JEV_REF=main bash "$root/update.sh" --check 2>&1 | tail -1)" "up to date" "update: --check after install -> up to date"
HOME=$U PATH="$stub:$PATH" REPO_ROOT="$root" JEV_REF=main bash "$root/update.sh" --check >/dev/null 2>&1; ok "$?" 0 "update: --check up to date -> exit 0"
printf 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeef\n' > "$U/.local/share/jev-agent-skills/installed-ref"
HOME=$U PATH="$stub:$PATH" REPO_ROOT="$root" JEV_REF=main bash "$root/update.sh" --check >/dev/null 2>&1; ok "$?" 1 "update: --check update available -> exit 1"
printf '0000000000000000000000000000000000000000\n' > "$U/.local/share/jev-agent-skills/installed-ref"
bash "$root/update.sh" --check --timer >/dev/null 2>&1; ok "$?" 2 "update: --check --timer -> rejected"

# ── jev-call exit codes (offline) ───────────────────────────────────────────────
jc="$root/scripts/jev-call.sh"
JEV_MCP_TOKEN=t JEV_MCP_URL=https://x/mcp bash "$jc" x '{' 2>/dev/null; ok "$?" 2 "jev-call: bad args JSON -> exit 2"
JEV_MCP_TOKEN=t JEV_MCP_URL=http://x/mcp bash "$jc" x '{}' 2>/dev/null; ok "$?" 2 "jev-call: http:// URL -> exit 2"
JEV_MCP_TOKEN=$'abc\ninsecure' JEV_MCP_URL=https://x/mcp bash "$jc" x '{}' 2>/dev/null; ok "$?" 2 "jev-call: token with embedded newline -> exit 2, no curl config injection"
JEV_MCP_TOKEN='abc"def' JEV_MCP_URL=https://x/mcp bash "$jc" x '{}' 2>/dev/null; ok "$?" 2 "jev-call: token with embedded quote -> exit 2"
cat > "$stub/curl" <<'EOF'
#!/usr/bin/env bash
cat >/dev/null; echo 'data: {"jsonrpc":"2.0","id":1,"result":{"isError":true,"content":[{"type":"text","text":"boom"}]}}'
EOF
PATH="$stub:$PATH" JEV_MCP_TOKEN=t JEV_MCP_URL=https://x/mcp bash "$jc" x '{}' 2>/dev/null; ok "$?" 1 "jev-call: isError -> exit 1"
cat > "$stub/curl" <<'EOF'
#!/usr/bin/env bash
cat >/dev/null; echo '{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\"decision\":\"allow\"}"}]}}'
EOF
ok "$(PATH="$stub:$PATH" JEV_MCP_TOKEN=secret-token-value JEV_MCP_URL=https://x/mcp bash "$jc" x '{}' 2>/dev/null | tr -d ' \n')" '{"decision":"allow"}' "jev-call: result printed"

# ── guard hook local decisions (no network needed) ──────────────────────────────
hook="$root/hooks/jev-guard-hook.sh"
ev() { python3 -c 'import json,sys;print(json.dumps({"tool_name":sys.argv[1],"tool_input":json.loads(sys.argv[2]),"cwd":"/tmp"}))' "$1" "$2"; }
dec() { python3 -c 'import json,sys;d=sys.stdin.read();print(json.loads(d)["hookSpecificOutput"]["permissionDecision"] if d.strip() else "none")'; }
big=$(python3 -c 'import json;print(json.dumps({"tool_name":"Bash","tool_input":{"command":"cat ~/.ssh/id_rsa #"+"x"*20001},"cwd":"/tmp"}))')
ok "$(printf '%s' "$big" | JEV_MCP_TOKEN=t JEV_MCP_URL=https://127.0.0.1:9/mcp bash "$hook" 2>/dev/null | dec)" ask "guard: oversized command -> ask, no call"
ok "$(ev Bash '{"command":"cat .env"}' | JEV_MCP_TOKEN=t JEV_MCP_URL=http://127.0.0.1:9/mcp bash "$hook" 2>/dev/null | dec)" none "guard: http:// URL -> fail open, token never sent"
ok "$(ev Bash '{"command":"ls"}' | JEV_MCP_TOKEN=t JEV_MCP_URL=https://127.0.0.1:9/mcp JEV_GUARD_TIMEOUT=0.3 bash "$hook" 2>/dev/null | dec)" none "guard: unreachable server -> fail open"
bigpattern=$(python3 -c 'import json;print(json.dumps({"tool_name":"Grep","tool_input":{"pattern":"x"*20001,"output_mode":"content"},"cwd":"/tmp"}))')
ok "$(printf '%s' "$bigpattern" | JEV_MCP_TOKEN=t JEV_MCP_URL=https://127.0.0.1:9/mcp bash "$hook" 2>/dev/null | dec)" ask "guard: Grep output_mode=content -> judged (oversized pattern asks)"
fwmpattern=$(python3 -c 'import json;print(json.dumps({"tool_name":"Grep","tool_input":{"pattern":"x"*20001,"output_mode":"files_with_matches"},"cwd":"/tmp"}))')
ok "$(printf '%s' "$fwmpattern" | JEV_MCP_TOKEN=t JEV_MCP_URL=https://127.0.0.1:9/mcp bash "$hook" 2>/dev/null | dec)" none "guard: Grep output_mode=files_with_matches -> skipped, no secret-content exposure to judge"
defpattern=$(python3 -c 'import json;print(json.dumps({"tool_name":"Grep","tool_input":{"pattern":"x"*20001},"cwd":"/tmp"}))')
ok "$(printf '%s' "$defpattern" | JEV_MCP_TOKEN=t JEV_MCP_URL=https://127.0.0.1:9/mcp bash "$hook" 2>/dev/null | dec)" none "guard: Grep with no output_mode (defaults to files_with_matches) -> skipped"
redirect_test=$(python3 - "$root" <<'PYEOF'
import sys, io, json, importlib.util, os
root = sys.argv[1]
os.environ["JEV_MCP_URL"] = "https://example.invalid/mcp"
os.environ["JEV_MCP_TOKEN"] = "t"
spec = importlib.util.spec_from_file_location("jev_guard_hook", os.path.join(root, "hooks/jev_guard_hook.py"))
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

# The redirect handler must raise a distinguishable exception, not a bare network-class error.
exc = None
try:
    mod._NoRedirect().redirect_request(None, None, 302, "Found", {}, "http://evil.example/steal")
except Exception as e:
    exc = e
assert exc is not None, "redirect_request did not raise"
assert isinstance(exc, mod.RedirectRefused), "redirect must raise RedirectRefused, got %s" % type(exc).__name__

# main()'s exception routing must treat a redirect refusal as ask, never a silent fail-open allow.
mod.call_guard = lambda args: (_ for _ in ()).throw(mod.RedirectRefused("redirect refused (302 -> http://evil.example/steal)"))
sys.stdin = io.StringIO(json.dumps({"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}, "cwd": "/tmp"}))
out = io.StringIO()
sys.stdout = out
try:
    mod.main()
except SystemExit:
    pass
sys.stdout = sys.__stdout__
printed = out.getvalue().strip()
assert printed, "redirect refusal produced no output (fail-open regression)"
decision = json.loads(printed)["hookSpecificOutput"]["permissionDecision"]
assert decision == "ask", "redirect refusal must ask, got %r" % decision
print("PASS")
PYEOF
)
ok "$redirect_test" "PASS" "guard: redirect refusal -> ask, never silent allow"
http_status_test=$(python3 - "$root" <<'PYEOF'
import sys, io, urllib.error, importlib.util, os
root = sys.argv[1]

os.environ["JEV_MCP_URL"] = "https://example.invalid/mcp"
os.environ["JEV_MCP_TOKEN"] = "t"
spec = importlib.util.spec_from_file_location("jev_guard_hook", os.path.join(root, "hooks/jev_guard_hook.py"))
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

# Exercise call_guard()'s real HTTPError handling: no live server needed, _opener.open is replaced with a
# function that raises the exact exception urllib raises for a non-2xx response, so the rest of call_guard
# (the try/except around _opener.open, inside the actual hook file) runs unmodified.
def classify(status):
    def fake_open(req, timeout=None):
        raise urllib.error.HTTPError(req.full_url, status, "err", {}, io.BytesIO(b""))
    mod._opener.open = fake_open
    try:
        mod.call_guard({"tool": "Bash", "command": "x"})
        return "no-error"
    except mod.ServerRejected:
        return "ServerRejected"
    except urllib.error.HTTPError:
        return "re-raised (fail-open path)"

assert classify(401) == "ServerRejected", "401 must classify as ServerRejected (ask)"
assert classify(503) == "re-raised (fail-open path)", "503 must not be ServerRejected"
print("PASS")
PYEOF
)
ok "$http_status_test" "PASS" "guard: HTTP 4xx -> ServerRejected (ask); 5xx stays fail-open"

# ── PreToolUse matcher must cover every tool jev_guard_hook.py branches on ──────
matcher_has_grep() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print("Grep" in d["hooks"]["PreToolUse"][0]["matcher"])' "$1"; }
ok "$(matcher_has_grep "$root/hooks/claude-plugin-hooks.json")" True "hooks/claude-plugin-hooks.json: PreToolUse matcher includes Grep"
ok "$(matcher_has_grep "$root/config/claude-settings-hook.json")" True "config/claude-settings-hook.json: PreToolUse matcher includes Grep"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
