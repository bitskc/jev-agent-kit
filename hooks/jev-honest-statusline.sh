#!/usr/bin/env bash
# Honest Jev statusline — prints a beard-mark badge when jev-honest is armed.
# Wire as Claude Code statusLine: { "type":"command", "command":"bash /path/hooks/jev-honest-statusline.sh" }
# or compose it into an existing statusLine script (source + call).
flag="${CLAUDE_CONFIG_DIR:-$HOME/.claude}/.jev-honest-active"
[ -f "$flag" ] || exit 0
mode=$(head -n1 "$flag" | tr -d '[:space:]')
case "$mode" in
  off|"") exit 0;;
  standard) printf '\033[38;5;130m[HONEST]\033[0m';;
  *) printf '\033[38;5;130m[HONEST:%s]\033[0m' "$(printf '%s' "$mode" | tr '[:lower:]' '[:upper:]')";;
esac
