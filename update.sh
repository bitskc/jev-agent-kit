#!/usr/bin/env bash
# Pull jev-agent-kit skills from GitHub and (re)install them. Idempotent. No git checkout needed.
#   ./update.sh                 # latest release tag -> skills for every agent whose dir exists, else both
#   ./update.sh --omp|--claude|--both
#   ./update.sh --project DIR   # install into DIR/.omp/skills + DIR/.claude/skills
#   ./update.sh --check         # print the latest release and whether it differs from the installed one; change nothing
#   ./update.sh --timer         # also install a systemd user timer that runs this weekly
# Pinning: the release tag is resolved to its commit SHA through the GitHub API and the archive is fetched by SHA,
# so a moved tag or a push to main cannot change what gets installed. JEV_REF=main (or any ref) opts out of pinning.
set -euo pipefail
repo="${JEV_REPO:-bitskc/jev-agent-kit}"; ref="${JEV_REF:-}"
args=(); timer=0; check=0
while [ $# -gt 0 ]; do case "$1" in
  --omp|--claude|--both) args+=("$1");;
  --project) args+=("$1" "$2"); shift;;
  --timer) timer=1;; --check) check=1;; -h|--help) sed -n 2,9p "$0"; exit 0;;
  *) echo "unknown arg $1" >&2; exit 2;; esac; shift; done

api() { curl -fsSL -H 'accept: application/vnd.github+json' -H 'user-agent: jev-update' "https://api.github.com/repos/$repo/$1"; }
json_field() { python3 -c 'import json,sys; d=json.load(sys.stdin); print(d'"$1"')'; }

if [ -z "$ref" ]; then
  tag="$(api releases/latest 2>/dev/null | json_field '["tag_name"]' 2>/dev/null)" || { echo "no release found for $repo; set JEV_REF to install an unpinned ref" >&2; exit 1; }
  tagref="$(api "git/ref/tags/$tag")"
  sha="$(printf '%s' "$tagref" | json_field '["object"]["sha"]')"
  # annotated tags point at a tag object; dereference to the commit
  if [ "$(printf '%s' "$tagref" | json_field '["object"]["type"]')" = tag ]; then sha="$(api "git/tags/$sha" | json_field '["object"]["sha"]')"; fi
  label="$tag ($sha)"
else
  sha="$(api "commits/$ref" | json_field '["sha"]')"; tag="$ref"; label="$ref ($sha)"
fi

stamp="$HOME/.local/share/jev-agent-skills/installed-ref"
installed="$(cat "$stamp" 2>/dev/null || echo none)"
if [ "$check" = 1 ]; then
  echo "latest:    $label"; echo "installed: $installed"
  [ "$installed" = "$sha" ] && echo "up to date" || echo "update available: run jev-update"
  exit 0
fi

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
curl -fsSL "https://github.com/$repo/archive/$sha.tar.gz" -o "$tmp/kit.tar.gz"
tar -xzf "$tmp/kit.tar.gz" -C "$tmp"
kit="$(find "$tmp" -maxdepth 1 -type d -name "$(basename "$repo")-*" | head -1)"
[ -n "$kit" ] || { echo "unpacked tree not found" >&2; exit 1; }
"$kit/install.sh" ${args[@]+"${args[@]}"}
mkdir -p "$(dirname "$stamp")"; printf '%s\n' "$sha" > "$stamp"
echo "installed $label"

if [ "$timer" = 1 ]; then
  unit=jev-skill-sync; d="$HOME/.config/systemd/user"; mkdir -p "$d"
  # systemd.syntax(7) quoting, not bash %q: double-quote each arg, escaping backslash and double-quote.
  sd_args=""; for a in ${args[@]+"${args[@]}"}; do a=${a//\\/\\\\}; a=${a//\"/\\\"}; sd_args+=" \"$a\""; done
  cat > "$d/$unit.service" <<EOF
[Unit]
Description=Sync jev-agent-kit skills from the latest GitHub release
[Service]
Type=oneshot
ExecStart=$HOME/.local/bin/jev-update$sd_args
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
