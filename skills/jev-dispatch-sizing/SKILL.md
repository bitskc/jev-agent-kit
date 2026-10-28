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
  "model": "opus"
}
```
- `description` and `model` are required. Passing the full `prompt` makes the judgement more accurate.
- **Omit `ladder`** unless the tool's built-in ladder genuinely doesn't fit your fleet. The tool only recognises its own tier names (`scout-find, scout, workerS, workerO, director, fable`) plus the aliases in its ladder (`worker`, `haiku`, `sonnet`, `opus`, `claude`, `general-purpose`, `Plan`, `Explore`), matched whole or as a family substring; a *custom* ladder can't be ranked and the check returns `verdict:"unknown"` — it stops protecting you. Full model ids resolve by family with the vendor prefix stripped: `claude-haiku-4-5` → scout, `claude-sonnet-*` → workerS, `claude-opus-*` → director, `claude-fable-*` → fable (so the fable-tier block applies); a bare `claude-3` falls to director. Translate tier → your model: scout-find/scout → cheapest (haiku-class), workerS/workerO → mid (sonnet-class), director → large (opus-class), fable → top tier.

## Act on the result

Fields: `task_kind` (lookup, mechanical_edit, scoped_implementation, judgement, hard_problem, unclear), `recommended_model`, `mismatch`, `verdict` (`over_tiered` / `under_tiered` / `unclear` / `unknown` / ok), `action` (`block` / `warn` / `allow`), `reason`. `block` = 2+ rungs over the task's tier, or a `fable` dispatch with no stated prior failure; `warn` = exactly one rung over, proceed but note it. `unclear` = the brief itself was too vague to size (never acts on it).

- `mismatch: false`: dispatch as planned. `verdict:"unknown"` means Jev was unavailable, gave an unusable answer, or you passed a custom ladder — it does NOT mean the tier is fine, and it is different from an unrecognised model (which is treated as `director`, one rung below the top, and said so in `notes`).
- `over_tiered`: re-dispatch with `recommended_model` (cheaper). Only keep the bigger model if you can state a concrete reason the classifier could not see.
- `under_tiered`: use the larger `recommended_model`, or do the thinking yourself and delegate only the mechanical part.
- The ≥0.8-confidence/≥0.4-margin bar gates **over_tiered flagging only**. `under_tiered` is flagged regardless of confidence, and the fable-without-prior-failure block fires whenever it's true (a missing answer counts as `prior=0` → block).
- Do not call it again with a reworded description to get a different answer.

Logic adapted from jonathanavis96/jev-kit (MIT).
