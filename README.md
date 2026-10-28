# jev-agent-kit

## Give this to your agent

Paste this into omp, Claude Code, Codex, Cursor or any coding agent:

```text
Install https://github.com/bitskc/jev-agent-kit by following its AGENTS.md
```

The agent reads [`AGENTS.md`](AGENTS.md), asks you for the server URL and token (or deploys its own server to your Cloudflare account), installs the skills and guard hook for its host, and verifies 15 tools. Nothing secret is committed or echoed.

Give your coding agents (omp / oh-my-pi, Claude Code and compatible agents) a hosted **Jev** toolbox over MCP, plus the skills and hook that make them use it:

- **`server/`**: a Cloudflare Worker serving MCP over streamable HTTP, bearer-protected. 15 tools: the 12 upstream `jev_*` tools from [jkudish/jev-mcp](https://github.com/jkudish/jev-mcp) plus three ported from [jev-kit](https://github.com/jonathanavis96/jev-kit): `kit_guard_command` (is this shell command safe?), `kit_size_dispatch` (is this sub-agent model the right size for the task?), `kit_verify_done` (did the agent verify before saying "done"?).
- **`skills/`**: five agent skills (`SKILL.md`): `jev-command-guard`, `jev-dispatch-sizing`, `jev-verify-before-done`, `fast-file-search`, `jev-classify`.
- **`hooks/`**: a Claude Code `PreToolUse` hook (`jev-guard-hook.sh` + `jev_guard_hook.py`) and an omp TypeScript port (`hooks/omp/jev-guard.ts`). Fails open.
- **`scripts/jev-call.sh`**: `jev-call <tool> '<json>'` for agents with no MCP client.

Jev is a probabilistic decision model (TypeSafe "System One"). Calls are billed to the API key **you** configure on **your** Worker.

## Quick start (manual install)

```sh
git clone https://github.com/bitskc/jev-agent-kit && ./jev-agent-kit/install.sh --omp      # or --claude | --both
```
or, without git: `curl -fsSL https://github.com/bitskc/jev-agent-kit/archive/refs/heads/main.tar.gz | tar xz && ./jev-agent-kit-main/install.sh --omp`

`install.sh` copies the skills to `~/.omp/agent/skills/` and/or `~/.claude/skills/` (`--project DIR` for project scope), the hooks to `~/.local/share/jev-agent-skills/hooks/`, and `jev-call` to `~/.local/bin/`. By default it never edits your config files and never touches a token; `--wire` merges token-free MCP/hook config (with backups), `--save-env` writes a 0600 env file and `--doctor` verifies the setup. See [`AGENTS.md`](AGENTS.md).

You need a deployed server first: see [Deploy your own server](#deploy-your-own-server).

## Configure the client

Set two environment variables for the agent process. Keep them in a `0600` file, never in git:
```sh
mkdir -p ~/.config/jev && umask 077 && cat > ~/.config/jev/env <<'ENV'
JEV_MCP_URL=https://<your-worker>.workers.dev/mcp
JEV_MCP_TOKEN=<the MCP_BEARER_TOKEN you set on the worker>
ENV
set -a; . ~/.config/jev/env; set +a      # in ~/.bashrc or the service that launches the agent
```

### omp (oh-my-pi)
Put this in `~/.omp/agent/mcp.json` (user) or `.omp/mcp.json` (project); `config/omp-mcp.json` is the same file. omp expands `${VAR}` in `url` and `headers` at discovery (unresolved placeholders stay literal, which shows up as a 401).
```json
{
  "mcpServers": {
    "jev": {
      "type": "http",
      "url": "${JEV_MCP_URL}",
      "headers": { "Authorization": "Bearer ${JEV_MCP_TOKEN}" }
    }
  }
}
```
Then `/mcp reload`, `/mcp list`, `/mcp test jev` (expect 15 tools) and `/reload-plugins` for the skills.

### Claude Code
`.mcp.json` in the project (`config/claude-mcp.json`; the same JSON as above), or
`claude mcp add --transport http jev "$JEV_MCP_URL" --header "Authorization: Bearer $JEV_MCP_TOKEN"` (this stores the expanded token in `~/.claude.json`; prefer `.mcp.json` to keep the secret off disk). Tools appear as `mcp__jev__<tool>`; skills live in `~/.claude/skills/`.

## Guard hook (optional, makes `kit_guard_command` unconditional)

**Claude Code**: merge `config/claude-settings-hook.json` into `~/.claude/settings.json`:
```json
{ "hooks": { "PreToolUse": [ { "matcher": "Bash|Read",
  "hooks": [ { "type": "command", "command": "$HOME/.local/share/jev-agent-skills/hooks/jev-guard-hook.sh", "timeout": 5 } ] } ] } }
```
Server `allow` produces no output (normal permission flow), `ask` becomes `permissionDecision: "ask"`, `block` becomes `"deny"` with the reason and suggested fix. It **fails open** on timeout (2 s hard cap), network or HTTP error, bad reply, or missing `JEV_MCP_URL` / `JEV_MCP_TOKEN` / python3.
Knobs: `JEV_GUARD_TIMEOUT` (seconds, 2), `JEV_GUARD_MODE=shadow` (log only), `JEV_GUARD_ASK_AT` (0-1, server default 0.65), `JEV_GUARD_DEBUG=1`.

**omp**: hooks are TypeScript modules, so use the port: `cp hooks/omp/jev-guard.ts ~/.omp/agent/hooks/pre/` (project: `.omp/hooks/pre/`) and start a new session, or try it once with `omp --hook /abs/path/jev-guard.ts`. omp *fails closed* on a throwing or timing-out `tool_call` handler, so the port swallows all errors. With no UI, `ask` becomes a block unless `JEV_GUARD_ASK_NO_UI=allow`.
Confirmed against the omp docs (2026-10-27): MCP file locations and schema, `${VAR}` expansion, skill locations, hook module contract. **Not verified**: that `jev-guard.ts` runs inside omp, `ctx.ui.confirm`'s signature, and the built-in read tool's name (`read`, `input.path`).

## Deploy your own server

Needs Node >= 22, a Cloudflare account (free plan is fine), and an API key for Jev.

```sh
cd server
npm ci
npx wrangler login                      # or: export CLOUDFLARE_API_TOKEN=... (Workers Scripts: Edit)
npm run vendor                          # clones jkudish/jev-mcp at a pinned commit, builds, patches -> vendor/ (not committed)
npm test                                # 21 offline tests of the kit_* tools
npx wrangler deploy                     # prints https://jev-mcp.<your-subdomain>.workers.dev
```
Set the secrets (values are read from stdin so they never land in shell history or files):
```sh
openssl rand -hex 32 | tee /dev/stderr | npx wrangler secret put MCP_BEARER_TOKEN   # this is your JEV_MCP_TOKEN; copy it from the terminal once
printf %s "$AI_GATEWAY_API_KEY" | npx wrangler secret put AI_GATEWAY_API_KEY      # Vercel AI Gateway (routes to typesafe-ai/jev), OR
printf %s "$TYPESAFE_API_KEY"   | npx wrangler secret put TYPESAFE_API_KEY         # direct TypeSafe
```
| Secret | Purpose |
|---|---|
| `MCP_BEARER_TOKEN` | **Required.** Callers send `Authorization: Bearer <it>`. Without it every `/mcp` call is a 401. |
| `AI_GATEWAY_API_KEY` | Jev via Vercel AI Gateway (`https://ai-gateway.vercel.sh/typesafe`, model `typesafe-ai/jev`). Preferred if set. |
| `TYPESAFE_API_KEY` | Jev directly via TypeSafe. Used when no gateway key is set. |
| `JEV_UPSTREAM_API_KEY` (+ optional base URL/model, see `server/src/kit/jev.mjs`) | Override for a custom OpenAI-compatible upstream. |

With **no** Jev key the server still works: the deterministic `kit_guard_command` rules (`cat .env`, `rm -rf ~`, `sudo`, staging secrets...) decide without any model call, and Jev-dependent paths fail open with a clear note.

Verify (replace the URL; the token comes from your env):
```sh
curl -s https://<your-worker>.workers.dev/health                       # ok
curl -s -o /dev/null -w '%{http_code}\n' -X POST https://<your-worker>.workers.dev/mcp    # 401
curl -s -X POST "$JEV_MCP_URL" -H "authorization: Bearer $JEV_MCP_TOKEN" \
  -H 'content-type: application/json' -H 'accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | head -c 400
JEV_MCP_URL=... JEV_MCP_TOKEN=... ./tests/test-hook.sh                 # end-to-end hook test
```
Notes: `wrangler.jsonc` pins `compatibility_date` to `2026-05-01` and enables `nodejs_compat` + `nodejs_compat_populate_process_env` (the upstream tools read `process.env`); `preview_urls` is off. Change the Worker `name` if `jev-mcp` is taken in your account. `/mcp` is stateless, `/health` is unauthenticated and returns `ok`. Some clients get a 403 from Cloudflare when they send Python's default urllib User-Agent; the hook sets its own.

## Tests

- `server/`: `npm test` (offline, mocked Jev).
- `tests/test-hook.sh`: live test of the hook (`ls` allowed, `cat .env` denied, `scp db.dump prod:/tmp` asks, fail-open on bad token / unreachable host / garbage stdin). Requires `JEV_MCP_URL` and `JEV_MCP_TOKEN`.

## Attribution and licence

MIT, Copyright (c) 2026 bitskc / Andy Hayes: see [`LICENSE`](LICENSE). Built on jkudish/jev-mcp, jonathanavis96/jev-kit, valentynkit/jev-belay, valentynkit/jev-commit and leepokai/jev-guard (all MIT; texts in [`licenses/`](licenses/), details in [`NOTICE.md`](NOTICE.md)). The upstream `jev-mcp` build is generated at deploy time, not redistributed in this repo.

## Security

Never commit `.dev.vars`, `.env`, tokens, or your Worker URL if you want it private. `.gitignore` covers the usual files. The endpoint is public on the internet and protected only by the bearer token: use a long random value and rotate with `wrangler secret put MCP_BEARER_TOKEN`.
