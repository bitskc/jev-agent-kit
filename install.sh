#!/usr/bin/env bash
# Install the jev skills pack for omp and/or Claude Code on this machine (user scope). Idempotent.
#   ./install.sh                # install for every agent whose config dir exists, else both
#   ./install.sh --omp | --claude | --both
#   ./install.sh --project DIR  # project scope: DIR/.omp/skills and DIR/.claude/skills instead of ~
#   ./install.sh --wire         # ALSO merge the MCP entry (+ guard hook) into the agent config. Backs up first. Token-free
#                               # (writes ${JEV_MCP_URL}/${JEV_MCP_TOKEN} references only).
#   ./install.sh --no-hook      # with --wire: skip the guard hook
#   ./install.sh --save-env     # write JEV_MCP_URL/JEV_MCP_TOKEN from the CURRENT environment to ~/.config/jev/env (0600)
#   ./install.sh --doctor       # check env, /health, auth and tool count (expects 15). Never prints the token.
#   ./install.sh --yes          # accepted for scripted use; the installer never prompts
# Default (no --wire): copies files only; never edits your MCP or settings files and never touches a token.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
target=auto; project=""; wire=0; hook=1; doctor=0; saveenv=0
while [ $# -gt 0 ]; do case "$1" in
  --omp) target=omp;; --claude) target=claude;; --both) target=both;;
  --project) [ $# -ge 2 ] || { echo "--project needs DIR" >&2; exit 2; }; project="$2"; shift;;
  --wire) wire=1;; --no-hook) hook=0;; --doctor) doctor=1;; --save-env) saveenv=1;; -y|--yes|--non-interactive) :;;
  -h|--help) sed -n 2,14p "$0"; exit 0;;
  *) echo "unknown arg $1" >&2; exit 2;; esac; shift; done
envfile="$HOME/.config/jev/env"; bin="$HOME/.local/bin"
if [ "$saveenv" = 1 ]; then
  : "${JEV_MCP_URL:?export JEV_MCP_URL first}"; : "${JEV_MCP_TOKEN:?export JEV_MCP_TOKEN first}"
  mkdir -p "$(dirname "$envfile")"; ( umask 077; printf 'JEV_MCP_URL=%s\nJEV_MCP_TOKEN=%s\n' "$JEV_MCP_URL" "$JEV_MCP_TOKEN" > "$envfile" )
  chmod 600 "$envfile"; echo "saved -> $envfile (0600)"; exit 0
fi
if [ "$doctor" = 1 ]; then
  # shellcheck source=/dev/null
  [ -f "$envfile" ] && [ -z "${JEV_MCP_TOKEN:-}" ] && { set -a; . "$envfile"; set +a; }
  # shellcheck disable=SC2015
  fail=0; ok() { echo "ok   $*"; }; bad() { echo "FAIL $*"; fail=1; }
  [ -n "${JEV_MCP_URL:-}" ] && ok "JEV_MCP_URL set" || bad "JEV_MCP_URL not set"
  [ -n "${JEV_MCP_TOKEN:-}" ] && ok "JEV_MCP_TOKEN set" || bad "JEV_MCP_TOKEN not set"
  if [ -n "${JEV_MCP_URL:-}" ] && [ -n "${JEV_MCP_TOKEN:-}" ]; then
    base="${JEV_MCP_URL%/mcp}"
    [ "$(curl -s -m 10 "$base/health" || true)" = ok ] && ok "/health" || bad "/health did not return ok"
    code=$(curl -s -m 10 -o /dev/null -w '%{http_code}' -X POST "$JEV_MCP_URL" || true)
    [ "$code" = 401 ] && ok "unauthenticated call rejected (401)" || bad "unauthenticated call returned $code (want 401)"
    n=$(curl -s -m 20 -X POST "$JEV_MCP_URL" -H "authorization: Bearer $JEV_MCP_TOKEN" -H 'content-type: application/json' \
      -H 'accept: application/json, text/event-stream' -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' \
      | python3 -c 'import sys,json
for l in sys.stdin.read().splitlines():
    l=l.strip()
    l=l[5:].strip() if l.startswith("data:") else l
    if l.startswith("{"): print(len(json.loads(l)["result"]["tools"])); break' 2>/dev/null || true)
    [ "$n" = 15 ] && ok "tools/list = 15 tools" || bad "tools/list returned '${n:-nothing}' (want 15; bad token?)"
  fi
  for d in "$HOME/.omp/agent/skills" "$HOME/.claude/skills"; do [ -d "$d/jev-classify" ] && ok "skills in $d"; done
  [ -x "$bin/jev-call" ] && ok "jev-call installed" || bad "jev-call not installed (run ./install.sh)"
  exit "$fail"
fi
if [ "$target" = auto ]; then
  if [ -d "$HOME/.omp" ] && [ -d "$HOME/.claude" ]; then target=both
  elif [ -d "$HOME/.omp" ]; then target=omp
  elif [ -d "$HOME/.claude" ]; then target=claude
  else target=both; fi
fi
share="$HOME/.local/share/jev-agent-skills"; bin="$HOME/.local/bin"
mkdir -p "$share" "$bin"
rm -rf "$share/hooks" && cp -r "$here/hooks" "$share/hooks" && chmod +x "$share"/hooks/*.sh "$share"/hooks/*.py
install -m 755 "$here/scripts/jev-call.sh" "$bin/jev-call"
# shellcheck disable=SC2115
copy_skills() { mkdir -p "$1"; for d in "$here"/skills/*/; do n=$(basename "$d"); rm -rf "$1/$n"; cp -r "$d" "$1/$n"; done; echo "skills -> $1"; }
if [ "$target" = omp ] || [ "$target" = both ]; then
  copy_skills "${project:-$HOME}$([ -n "$project" ] && echo /.omp/skills || echo /.omp/agent/skills)"
fi
if [ "$target" = claude ] || [ "$target" = both ]; then
  copy_skills "${project:-$HOME}/.claude/skills"
fi
merge_json() { # merge_json FILE KIND  (kind: mcp | claude-hook). Backs up, merges, keeps everything else.
  python3 - "$1" "$2" "$share" <<'PY'
import json, os, shutil, sys
path, kind, share = sys.argv[1:4]
d = {}
if os.path.exists(path):
    shutil.copy2(path, path + ".jev-bak")
    try: d = json.load(open(path))
    except Exception as e: sys.exit(f"refusing to edit {path}: not plain JSON ({e}); merge by hand")
if kind == "mcp":
    d.setdefault("mcpServers", {})["jev"] = {"type": "http", "url": "${JEV_MCP_URL}",
        "headers": {"Authorization": "Bearer ${JEV_MCP_TOKEN}"}}
else:
    cmd = share + "/hooks/jev-guard-hook.sh"
    arr = d.setdefault("hooks", {}).setdefault("PreToolUse", [])
    if not any(cmd in json.dumps(e) for e in arr):
        arr.append({"matcher": "Bash|Read", "hooks": [{"type": "command", "command": cmd, "timeout": 5}]})
os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
json.dump(d, open(path, "w"), indent=2); open(path, "a").write("\n")
print("wired ->", path)
PY
}
if [ "$wire" = 1 ]; then
  if [ "$target" = omp ] || [ "$target" = both ]; then
    if [ -n "$project" ]; then merge_json "$project/.omp/mcp.json" mcp; hd="$project/.omp/hooks/pre"
    else merge_json "$HOME/.omp/agent/mcp.json" mcp; hd="$HOME/.omp/agent/hooks/pre"; fi
    [ "$hook" = 1 ] && { mkdir -p "$hd"; cp "$share/hooks/omp/jev-guard.ts" "$hd/jev-guard.ts"; echo "hook  -> $hd/jev-guard.ts"; }
  fi
  if [ "$target" = claude ] || [ "$target" = both ]; then
    # user scope: top-level mcpServers in ~/.claude.json (Claude Code expands ${VAR} there); project scope: DIR/.mcp.json
    if [ -n "$project" ]; then merge_json "$project/.mcp.json" mcp; else merge_json "$HOME/.claude.json" mcp; fi
    if [ "$hook" = 1 ]; then
      if [ -n "$project" ]; then merge_json "$project/.claude/settings.json" claude-hook; else merge_json "$HOME/.claude/settings.json" claude-hook; fi
    fi
  fi
  echo "wired. Config holds only \${JEV_MCP_URL}/\${JEV_MCP_TOKEN} references: export them for the agent process (see --save-env)."
fi
echo "hooks  -> $share/hooks   (omp TS hook: $share/hooks/omp/jev-guard.ts)"
echo "helper -> $bin/jev-call  (make sure $bin is on PATH)"
if [ "$wire" = 1 ]; then echo; echo "Remaining: set JEV_MCP_URL/JEV_MCP_TOKEN, restart the agent, run ./install.sh --doctor"; exit 0; fi
cat <<MSG

Next (nothing below was done for you; re-run with --wire to do steps 2-3 automatically):
 1. export JEV_MCP_URL=https://<your-worker>.workers.dev/mcp  and  JEV_MCP_TOKEN=...
    (keep them in a 0600 env file, never in git; deploy your own worker from server/ first)
 2. Add the MCP server: see config/omp-mcp.json (-> ~/.omp/agent/mcp.json or .omp/mcp.json)
    or config/claude-mcp.json (-> .mcp.json), or:
      claude mcp add --transport http jev "\$JEV_MCP_URL" --header "Authorization: Bearer \$JEV_MCP_TOKEN"
 3. Optional guard hook: Claude Code -> merge config/claude-settings-hook.json into ~/.claude/settings.json
                         omp         -> cp $share/hooks/omp/jev-guard.ts ~/.omp/agent/hooks/pre/
 4. Restart the agent (omp: /reload-plugins, then /mcp list, /mcp test jev)
MSG
