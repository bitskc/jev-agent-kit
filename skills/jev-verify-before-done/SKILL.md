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
    {"command": "npm test", "output": "<last ~50 lines of output>", "passed": true}
  ]
}
```
- `final_message` is the key input. `file_changes` = number of edits or writes this turn. List every check you ran **after the last edit** in `checks` (command and output tail; `passed` is auto-detected from runner summaries if omitted).
- Claude Code users can alternatively pass `transcript_tail` (tail of the session JSONL) and let the server derive the evidence.
- Optional `threshold` (0.5-1, default 0.75): how sure the server must be that you claim done before it blocks.

## Act on the result

- `verified: true` (or `action: allow`): send your message.
- `verified: false` with `verdict: "unverified"`: do **not** send it. Run the project's own checks (tests, build, type-check, lint; whichever exist) on what you changed, fix failures, then call again with the new `checks`. If the nudge says the last check failed, fix that first.
- If no check exists or none can run here, say so plainly in the final message instead of presenting the work as done, and state exactly what you did verify.
- `false_claim: true` means the message claimed verification that the evidence does not show. Correct the message.
- A check that ran before your last edit does not count. Re-run it.
- Jev unavailable: the server fails open with a note. Still run your checks.

Logic adapted from jonathanavis96/jev-kit (MIT).
