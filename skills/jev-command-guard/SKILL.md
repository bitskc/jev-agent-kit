---
name: jev-command-guard
description: Before running a risky or ambiguous shell command (deleting or overwriting files, sudo, scp/rsync/ssh to another host, reading .env or key files, printing environment variables, git commit/add that might stage secrets, curl | sh, anything touching prod), ask the jev-mcp kit_guard_command tool for a second opinion, then obey `ask` and `block`.
---

# jev-command-guard

Run the command through `kit_guard_command` first whenever it could be destructive, exfiltrate or print a secret, change something outside the working directory, or touch another machine. Skip it for plainly read-only commands (`ls`, `git status`, `rg`, `cat README.md`, test and build runs).

If a `kit_guard_command` PreToolUse hook is already installed it calls the same tool on every Bash/Read, so you can skip manual calls on commands that pass through it — but it is not equivalent: it fails open on a 2 s Jev timeout, never blocks in `JEV_GUARD_MODE=shadow`, can let `ask` through when `JEV_GUARD_ASK_NO_UI=allow`, and covers Bash/Read only. Keep calling the tool for anything risky outside those shapes or when you can't see the hook's mode.

## Call

Tool: `kit_guard_command` on the `jev` MCP server (Claude Code names it `mcp__jev__kit_guard_command`).
If MCP is not wired up, use the shell helper: `jev-call kit_guard_command '<json>'`.

Arguments (only `command` is required):
```json
{"command": "scp db.dump prod:/tmp", "cwd": "<current dir>", "home": "<$HOME>", "description": "<why, if you know>"}
```
- For a file read use `{"tool":"Read","file_path":"..."}`.
- Optional `user_request`: the user's own words asking for this action. It can only soften an `ask` to `allow`, never a `block`. Quote the user; never invent it.
- Optional `ask_at` (0-1, default 0.65): risk at or above which you get `ask`.

## Act on `decision`

| decision | what you do |
|---|---|
| `allow` | Run it — but read this as "no rule matched, no opinion", not "proven safe". Prefilter misses obfuscated secrets and many dangerous shapes, so keep your own judgment for anything destructive. |
| `ask` | Do not run it yet. Tell the user what the command does and the `reason`, and wait for an explicit yes. If they approve, run it (or re-call with their words in `user_request`). In a host with no UI to ask through (e.g. an omp hook), `ask` resolves to `block`. |
| `block` | Do not run it. Read `rule`, `reason` and `suggestion`, then take the suggested safer route (for example load `.env` into the environment instead of printing it). Never retry the same command reworded, quoted, split up or base64-encoded to get past the guard. |

## Notes
- `decided_by: "prefilter"` means a deterministic rule fired and no model was called (secret reads, `rm -rf ~`, `sudo`, staging secrets). `decided_by: "jev"` means the Jev model scored it; `score` is the risk 0-1.
- If `jev.status` shows Jev is unavailable, the server fails open (`allow` with a note). Treat that as "no opinion", and use normal caution for anything destructive.
- `disable_rules` exists but only the user may decide to use it.
- Never put a secret value in `command` (or `file_path`): the full text is sent to the MCP server and, when Jev is consulted, upstream to the model API. Refer to files, don't paste contents.
- Rules adapted from jonathanavis96/jev-kit (MIT).
