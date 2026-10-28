#!/usr/bin/env bash
# Install the jev skills pack for omp and/or Claude Code on this machine (user scope). Idempotent.
#   ./install.sh                # install for every agent whose config dir exists, else both
#   ./install.sh --omp | --claude | --both
#   ./install.sh --project DIR  # project scope: DIR/.omp/skills and DIR/.claude/skills instead of ~
# It copies files only. It never edits your MCP or settings files and never touches a token.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
target=auto; project=""
while [ $# -gt 0 ]; do case "$1" in
  --omp) target=omp;; --claude) target=claude;; --both) target=both;;
  --project) project="$2"; shift;; -h|--help) sed -n 2,7p "$0"; exit 0;;
  *) echo "unknown arg $1" >&2; exit 2;; esac; shift; done
if [ "$target" = auto ]; then
  if [ -d "$HOME/.omp" ] && [ -d "$HOME/.claude" ]; then target=both
  elif [ -d "$HOME/.omp" ]; then target=omp
  elif [ -d "$HOME/.claude" ]; then target=claude
  else target=both; fi
fi
share="$HOME/.local/share/jev-agent-skills"; bin="$HOME/.local/bin"
mkdir -p "$share" "$bin"
rm -rf "$share/hooks" && cp -r "$here/hooks" "$share/hooks" && chmod +x "$share"/hooks/*.sh "$share"/hooks/*.py "$share"/hooks/honest/*.js
# jev-honest-runtime.js resolves SKILL.md relative to its own install location ($share/hooks/honest/.. -> $share/skills)
# first, falling back to ~/.claude/skills only if that's absent. Without this, --omp-only and --project installs
# never populate $share/skills, so the honest hook silently falls back to a ~700-char hardcoded summary instead
# of the real, level-filtered skill body.
rm -rf "$share/skills" && cp -r "$here/skills" "$share/skills"
install -m 755 "$here/scripts/jev-call.sh" "$bin/jev-call"
install -m 755 "$here/update.sh" "$bin/jev-update"
copy_skills() { mkdir -p "$1"; for d in "$here"/skills/*/; do n=$(basename "$d"); rm -rf "$1/$n"; cp -r "$d" "$1/$n"; done; echo "skills -> $1"; }
if [ "$target" = omp ] || [ "$target" = both ]; then
  copy_skills "${project:-$HOME}$([ -n "$project" ] && echo /.omp/skills || echo /.omp/agent/skills)"
fi
if [ "$target" = claude ] || [ "$target" = both ]; then
  copy_skills "${project:-$HOME}/.claude/skills"
fi
echo "hooks  -> $share/hooks   (Claude: honest/*.js + jev-guard-hook.sh; omp: omp/jev-honest.ts + omp/jev-guard.ts)"
echo "helper -> $bin/jev-call  (make sure $bin is on PATH)"
echo "update -> $bin/jev-update  (re-pull the latest release; --check to compare; --timer for weekly auto-sync)"
cat <<MSG

Next (nothing below was done for you):
 1. export JEV_MCP_URL=https://<your-worker>.workers.dev/mcp  and  JEV_MCP_TOKEN=...
    (keep them in a 0600 env file, never in git; deploy your own worker from server/ first)
 2. Add the MCP server: see config/omp-mcp.json (-> ~/.omp/agent/mcp.json or .omp/mcp.json)
    or config/claude-mcp.json (-> .mcp.json), or:
      claude mcp add --transport http jev "\$JEV_MCP_URL" --header "Authorization: Bearer \$JEV_MCP_TOKEN"
 3. Hooks (Honest Jev levels + statusline badge, and the guard):
      Claude Code -> easiest: install as a plugin instead (/plugin marketplace add bitskc/jev-agent-kit), hooks wire themselves;
                     manual: merge config/claude-settings-hook.json into ~/.claude/settings.json
      omp         -> cp $share/hooks/omp/jev-honest.ts $share/hooks/omp/jev-guard.ts ~/.omp/agent/hooks/pre/
 4. Restart the agent (omp: /reload-plugins, then /mcp list, /mcp test jev), then: /honest-jev standard
MSG
