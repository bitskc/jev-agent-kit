---
name: jev-dispatch-sizing
description: Before spawning a sub-agent or delegating a task to another model, call the jev-mcp kit_size_dispatch tool to check that the chosen model/tier fits the task (lookups and mechanical edits do not need the biggest model), and downshift or upshift when it reports a mismatch.
---

# jev-dispatch-sizing

Use right before you start a sub-agent, task agent, or background worker. It prevents paying for a top-tier model on a grep, and prevents a small model from being handed an open-ended design problem.

## Call

Tool: `kit_size_dispatch` on the `jev` MCP server (Claude Code: `mcp__jev__kit_size_dispatch`). Shell fallback: `jev-call kit_size_dispatch '<json>'`.

```json
{
  "description": "Find where FOO_TIMEOUT is read",
  "prompt": "<the full brief you are about to send>",
  "model": "opus",
  "ladder": [["haiku", "small", "fast"], ["sonnet", "medium"], ["opus", "large"]]
}
```
- `description` and `model` are required. Passing the full `prompt` makes the judgement more accurate.
- **Pass `ladder`** with the model names you really have, cheapest rung first, each rung a list of equivalent names (the first name is the one you should dispatch). Without it the server uses a built-in ladder (`scout-find, scout, workerS, workerO, director, fable`), and unknown names are treated as a high rung.

## Act on the result

Fields: `task_kind` (lookup, mechanical_edit, scoped_implementation, hard_problem, unclear), `recommended_model`, `mismatch`, `verdict` (`over_tiered` / `under_tiered` / ok), `action`, `reason`.

- `mismatch: false`: dispatch as planned.
- `over_tiered`: re-dispatch with `recommended_model` (cheaper). Only keep the bigger model if you can state a concrete reason the classifier could not see.
- `under_tiered`: use the larger `recommended_model`, or do the thinking yourself and delegate only the mechanical part.
- It only judges when Jev is confident (>= 0.8 with a clear margin). If the answer is unclear, or Jev is unavailable, it returns no mismatch (fails open): proceed with your own judgement.
- Do not call it again with a reworded description to get a different answer.

Logic adapted from jonathanavis96/jev-kit (MIT).
