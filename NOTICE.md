# NOTICE: third-party code, wording and licences

This repository is MIT-licensed (see `LICENSE`, Copyright (c) 2026 bitskc / Andy Hayes). It builds on the MIT-licensed
projects below. Their licence texts are kept verbatim in `licenses/`. Licence identifiers were checked against the GitHub
API (`gh api repos/<owner>/<repo>/license`) on 2026-10-27.

| Project | Licence | Copyright holder | How it is used here | Text |
|---|---|---|---|---|
| [jkudish/jev-mcp](https://github.com/jkudish/jev-mcp) (v0.14.6, commit `4a9b331`) | MIT | Joey Kudish | The 12 `jev_*` MCP tools. **Not committed**: `server/build-vendor.sh` clones it at the pinned commit, builds it, and patches one Node-only line (`createRequire` of `package.json` replaced by a version constant) so it runs in a Cloudflare Worker. Otherwise unmodified. | `licenses/jev-mcp.LICENSE` |
| [jonathanavis96/jev-kit](https://github.com/jonathanavis96/jev-kit) | MIT | Jonathan Avis | Decision logic and question wording ported to JavaScript in `server/src/kit/` (`kit_guard_command`, `kit_size_dispatch`, `kit_verify_done`): `airlock/rules.py` (rules R1, R5, R7, R7-root-delete, R9, R10 and shell helpers), `airlock/questions.py`, `airlock/policy.py`, `airlock/tiers.py`, `airlock/belt.py`. The hook behaviour and skills follow the same design. | `licenses/jev-kit.LICENSE` |
| [valentynkit/jev-belay](https://github.com/valentynkit/jev-belay) (pin `98f39e0`) | MIT | Valentyn Kit | Ported from `belay.mjs`: check-command belt, runner-summary parsing, transcript evidence pass, the four done-check questions, `decide()`, redaction rules (`server/src/kit/verify.mjs`, `shell.mjs`). | `licenses/jev-belay.LICENSE` |
| [valentynkit/jev-commit](https://github.com/valentynkit/jev-commit) | MIT | Valentyn Kit | Secret-shaped patterns and placeholder suppression, reached through jev-kit's `belt.py` (rule R9). | `licenses/jev-commit.LICENSE` |
| [leepokai/jev-guard](https://github.com/leepokai/jev-guard) | MIT | leepokai | The `user_requested` question wording and the risk-score idea behind R10, via jev-kit. | `licenses/jev-guard.LICENSE` |

## Not included
- [browser-use/browser-use](https://github.com/browser-use/browser-use) (MIT) and jev-kit's `jev-ultrafast` browser agent, file-search component, daemon, tuning loop and installer: **nothing from these is vendored or ported**. They run locally and are only mentioned for context.
- The upstream jev-kit rules not ported: R2, R3, R4, R6, R8, R11.

## Runtime dependencies (installed by npm, not redistributed here)
`@modelcontextprotocol/server`, `@jkudish/jev-agent-tools`, `@typesafe-ai/sdk`, `zod`, `wrangler`: see `server/package.json`; each carries its own licence in `node_modules`.

## Services
Jev is TypeSafe's "System One" decision model (`typesafe-ai/jev`), reached directly through TypeSafe or through Vercel AI Gateway. This project is unaffiliated with TypeSafe, Vercel, Cloudflare or Anthropic. Calls are billed to whoever holds the API key you configure.
