---
name: jev-verify-before-done
description: Before telling the user a task is done, fixed, finished or working after you changed files, call the jev-mcp kit_verify_done tool with your draft final message; if it says unverified, run the project's tests/build/lint, fix what fails, and only then report the real result.
---

# jev-verify-before-done

An agent that edits code and then says "Done!" without running anything is the most common false-completion failure. Run this check on your draft final message, after the last edit and before you send it.

Skip it when you changed no files, or the answer is purely informational.

## Call

Tool: `kit_verify_done` on the `jev` MCP server (Claude Code: `mcp__jev__kit_verify_done`). Shell fallback: `jev-call kit_verify_done '<json>'`.

```json
{
  "task": "what the user asked for, in their words",
  "final_message": "your draft final message",
  "file_changes": 3,
  "checks": [
    {"command": "npm test", "output": "<last ~50 lines of real output>", "exit_code": 0}
  ]
}
```
- `final_message` is the key input. `file_changes` = number of edits or writes this turn. List every check you ran **after the last edit** in `checks` with `command`, the output tail, and `exit_code`. A check counts as passed only on hard evidence: a recognised runner summary (node:test, Jest, pytest, cargo, go, vitest, bun, mocha, mix, dotnet, Maven/Gradle, eslint, tsc) reporting no failures, or `exit_code: 0` with no failure in the output. **A bare command name, or output the tool can't parse with no `exit_code`, is not evidence** — it stays in `checks` as unproven and never verifies, and the response `notes` tell you so. `exit_code` is what lets silent runners (`tsc --noEmit`, lint) verify. `passed: true` overrides detection; use it only when both the output and the exit code are unavailable, and only for a run that happened.
- **A passing exit code only counts when it is the check's own.** `exit_code: 0` is trusted for a bare check, harmless setup before it (`cd api && npm test`, `export NODE_ENV=test; npm test`, `set -euo pipefail; npm test`, `rm -rf dist && npm run build && npm test`), an all-`&&` chain (`npm run build && npm test`, `npm test && echo OK`), a `;`/newline list whose last command is the check, `exec <check>`, a whole-command `sh -c '<check>'` or `(cd dir && <check>)`, and a pipe through `tail` or under `set -o pipefail`. Quoted text and `#` comments are data (`pytest -k "a and (b or c)"` is fine; `echo ok # ; npm test` runs no test). It becomes **unknown** — not a pass — when anything can hide the check's status: a command after it in a `;` list (`npm test ; echo done`), any `||`, a leading `!`, a background `&`, an inner subshell or `$(…)`, a bare pipe without pipefail, `| head`, `sh -c` inside a longer command, or `eval`/`ssh`/`docker exec` with a quoted body, an unterminated quote or heredoc, a terminator before it (`exit 0; npm test`, `trap 'exit 0' EXIT; mypy .`, `exec true; pytest`), or any element before it that can stop the shell or change what runs next (`set -n`, `set -o noexec`, `eval exit 0`, `source …`, `hash -p …`, `alias npm=true`, `shopt`, `ulimit`, `PATH=…`, a function definition). A Bash call run with `run_in_background` is not a result at all. Flag-only runs (`--help`, `--version`, `--collect-only`, `--dry-run`, `--if-present`, `make -n`), installs (`npm ci`) and runs that found no tests or only skipped tests (`No tests found`, `collected 0 items`, `Tests: 3 skipped, 3 total`) are not checks or not passes. Failure text always wins. Clear an unknown by rerunning the check alone (`npm test`) in the foreground and sending its `exit_code` and summary. `passed: true` only counts on a command that runs a check; on any other command it is ignored.
- The Stop hook sends this payload itself. A payload the server rejects as malformed or over-cap (HTTP 400/413/422, JSON-RPC `-32602`) blocks with the server's message; every other error (auth, routing, 5xx, timeout, network) fails open.
- Optional `threshold` (0.5-1, default 0.75): how sure the server must be that you claim done before it blocks.

## Act on the result

- `verified: true` (or `action: allow`): send your message.
- `verified: false` with `verdict: "unverified"`: do **not** send it. A block means go run the project's own checks (tests, build, type-check, lint; whichever exist) on what you changed, fix failures, then call again with the new `checks` — not reword `final_message` until it passes. If the nudge says the last check failed, fix that first.
- If no check exists or none can run here, say so plainly in the final message instead of presenting the work as done, and state exactly what you did verify.
- `false_claim: true` means the message claimed verification that the evidence does not show. Correct the message.
- A check that ran before your last edit does not count. Re-run it.
- Jev unavailable: the server fails open with a note. Still run your checks.

Logic adapted from jonathanavis96/jev-kit (MIT).
