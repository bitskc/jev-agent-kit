#!/usr/bin/env bash
# Pull the latest jev-agent-kit skills from GitHub and (re)install them. Idempotent.
#   ./update.sh                 # skills for every agent whose dir exists, else both
#   ./update.sh --omp|--claude|--both
#   ./update.sh --project DIR   # install into DIR/.omp/skills + DIR/.claude/skills
#   ./update.sh --timer         # also install a systemd user timer that runs this weekly
# It downloads a release tarball, never requires a git checkout, and never touches a token.
set -euo pipefail
repo="${JEV_REPO:-bitskc/jev-agent-kit}"; ref="${JEV_REF:-main}"
args=(); timer=0
while [ $# -gt 0 ]; do case "$1" in
  --omp|--claude|--both|--project) args+=("$1"); [ "$1" = --project ] && { args+=("$2"); shift; };;
  --timer) timer=1;; -h|--help) sed -n 2,7p "$0"; exit 0;;
  *) echo "unknown arg $1" >&2; exit 2;; esac; shift; done

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
curl -fsSL "https://github.com/$repo/archive/refs/heads/$ref.tar.gz" -o "$tmp/kit.tar.gz"
tar -xzf "$tmp/kit.tar.gz" -C "$tmp"
kit="$(find "$tmp" -maxdepth 1 -type d -name 'jev-agent-kit-*' | head -1)"
[ -n "$kit" ] || { echo "unpacked tree not found" >&2; exit 1; }
"$kit/install.sh" ${args[@]+"${args[@]}"}

if [ "$timer" = 1 ]; then
  unit=jev-skill-sync; d="$HOME/.config/systemd/user"; mkdir -p "$d"
  cat > "$d/$unit.service" <<EOF
[Unit]
Description=Sync jev-agent-kit skills from GitHub
[Service]
Type=oneshot
ExecStart=$HOME/.local/bin/jev-update$(if [ ${#args[@]} -gt 0 ]; then printf ' %q' "${args[@]}"; fi)
EOF
  cat > "$d/$unit.timer" <<EOF
[Unit]
Description=Weekly jev-agent-kit skills sync
[Timer]
OnCalendar=weekly
Persistent=true
[Install]
WantedBy=timers.target
EOF
  systemctl --user daemon-reload
  systemctl --user enable --now "$unit.timer" >/dev/null 2>&1 || true
  echo "timer  -> $d/$unit.timer (weekly; systemctl --user status $unit.timer)"
fi
