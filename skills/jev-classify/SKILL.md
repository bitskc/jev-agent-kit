---
name: jev-classify
description: Use the jev-mcp jev_classify and jev_decide tools to categorize many short items into a fixed label set (transactions, tickets, emails, log lines, routing) or to pick between 2-6 bounded alternatives with explicit priorities, instead of guessing or burning a large model; it returns probabilities and an auto-vs-review flag.
---

# jev-classify (jev_classify and jev_decide)

Jev is a small, fast, probabilistic decision model. It returns **calibrated probabilities over a closed set of answers**, so you can automate the confident cases and route the rest to a human. It is for bounded judgement over supplied text, not for open-ended reasoning, research, or code.

Tools on the `jev` MCP server (Claude Code: `mcp__jev__jev_classify`, `mcp__jev__jev_decide`). Shell fallback: `jev-call <tool> '<json>'`.

## jev_classify: label many items against one catalog
```json
{
  "purpose": "Categorize QuickBooks bank transactions",
  "items": [{"id": "t1", "text": "SHELL OIL 5742"}, {"id": "t2", "text": "ADOBE CREATIVE CLD"}],
  "classes": [
    {"id": "Fuel", "description": "Gas stations and fuel purchases for vehicles."},
    {"id": "Software", "description": "SaaS and software subscriptions."},
    {"id": "Supplies", "description": "Physical office or job supplies, hardware stores."},
    {"id": "Meals", "description": "Restaurants and food."},
    {"id": "manual_review", "description": "Anything that fits none of the above or is ambiguous."}
  ]
}
```
- Up to 64 items per call: batch them, do not loop one call per item. Send short excerpts, not whole documents (each item's `text` is truncated at 2000 chars server-side).
- **Class descriptions carry the decision.** Say what belongs, what does not, which wins when two overlap, plus one example. Add a `manual_review` class if you want an explicit escape hatch; the tool never invents one.
- Read `results[].decision`: `auto` (top probability >= 0.85 and margin >= 0.5) means accept `classification`; `review` means send to a human or a stronger model. Do not lower the thresholds to make the review pile smaller.
- Use `probabilities` and `margin` when you need to rank or sample what to double-check. `summary.by_class` gives the counts.

## jev_decide: choose among 2-6 alternatives
```json
{
  "decision": "Which test runner should this repo use?",
  "evidence": "Repo already has vitest config and 214 vitest tests. No jest dependency.",
  "priorities": "Minimal new dependencies; do not rewrite existing tests.",
  "candidates": [
    {"id": "vitest", "description": "Keep vitest."},
    {"id": "jest", "description": "Migrate to jest."}
  ],
  "requirements": ["Works with ESM", "No test rewrites"]
}
```
- Provide facts in `evidence` (measurements, file contents), the user's real constraints in `priorities`, and add "gather more evidence" or "do nothing" as candidates when they are genuine options. Candidate `id`s must match `^[a-z][a-z0-9_-]*$`, and `requirements` is capped at 3 checks.
- `recommendation.selected` plus `confidence`. If `escaped: true` (it chose `ask_user`, `investigate`, or `none`), do that instead of forcing a pick. High probability is not proof: still check cheap facts yourself.
- One call per unchanged decision. Do not re-ask to get a nicer answer.

## Good uses
Routing (which team/queue/agent), triage (bug/feature/question, severity), tagging logs or emails, deduping near-matches, picking between known implementation options.

## Bad uses
Generating text or code, multi-step reasoning, arithmetic, anything needing information that is not in the supplied text, predicting user consent.

Other tools on the same server (`jev_verify`, `jev_screen`, ...) have their own descriptions. List them with `tools/list` when needed. Calls are billed to the server owner: keep batches bounded.
