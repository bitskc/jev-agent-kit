#!/usr/bin/env bash
# Claude Code PreToolUse hook: jev-mcp kit_guard_command -> allow / ask / deny. Fails open.
# Needs: python3 (stdlib only) and the env var JEV_MCP_TOKEN. See jev_guard_hook.py for all options.
# Use an ABSOLUTE path to this file in settings.json (hooks do not expand ~).
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if ! command -v python3 >/dev/null 2>&1; then
  [ "${JEV_GUARD_DEBUG:-}" = "1" ] && echo "jev-guard: fail-open: python3 not found" >&2
  exit 0
fi
exec python3 "$here/jev_guard_hook.py"
