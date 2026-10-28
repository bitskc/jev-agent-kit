---
name: jev-honest
description: The honesty layer ("Honest Jev" 🎩). Before claiming something is done, working, verified, safe, or "should be fine" — batch-classify your own claims with jev-mcp jev_classify into verified / hedged / unverifiable / misrepresented, and don't send what you can't show. Also runs an on-demand audit of recent claims ("be honest with me") or a deep pass on a draft reply.
---

# jev-honest — Honest Jev 🎩

The honest-agent check: **claims vs. evidence**, not intent. It catches the failure modes `kit_verify_done` doesn't — not just "said done without a check," but hedging presented as fact, scope quietly narrowed, a symptom fix described as a root cause, a passing subset reported as the full run.

Two modes, both `jev_classify`-backed:

## Mode 1 — thin always-on (before any substantive claim)

Before you send a message asserting **done / works / fixed / verified / tested / handled / correct / safe**, extract the claims you'd be making and classify them.

```json
{
  "purpose": "Check whether an agent's claims are backed by evidence it actually produced, or are hedging/unverifiable/misrepresentation.",
  "items": [
    {"id": "c1", "text": "all tests pass — evidence available: ran `npm test`, output tail showed '42 passed'"},
    {"id": "c2", "text": "the migration is backwards-compatible — evidence available: none, not checked"},
    {"id": "c3", "text": "fixed the auth bug — evidence available: only added a null-check, root cause not identified"}
  ],
  "classes": [
    {"id": "verified", "description": "The claim matches evidence the agent actually produced this turn — a command was run and its real output supports the exact claim."},
    {"id": "hedged", "description": "Dressed up as a fact but really 'should work' / 'probably' / 'looks right' — an inference stated as observed."},
    {"id": "unverifiable", "description": "No evidence was produced and none could be cited on demand — the agent is asserting without checking."},
    {"id": "misrepresented", "description": "Evidence exists but the claim overstates it — a partial run called 'all', a symptom fix called 'the fix', scope silently narrowed."}
  ]
}
```

Rules for the result:

- `hedged` → **keep the hedge visible.** Don't delete the qualifier, state it: "I didn't run X" / "not verified."
- `unverifiable` → either produce the evidence now (run it) or cut the claim.
- `misrepresented` → rewrite to match what the evidence actually shows ("2 of 5 tests pass", "handled the null case, root cause not found").
- `verified` claims with a real output tail are fine to send.
- A claim is only as good as the check that produced it: `kit_verify_done`'s rule applies — a recognised pass banner or real output, not self-attestation. For "ran the tests / builds / verified" claims, also route through `kit_verify_done`.

## Mode 2 — audit ("be honest with me" / review this reply / what did I overclaim)

On demand, batch a draft reply or the last N claims through the same classify call, then **verify the flagged ones against evidence** — grep the repo, re-run the check, open the diff. The classification tells you where to look; the code tells you whether it's true.

- List each claim, its bucket, and the evidence that would settle it — then go settle the ones that matter before sending.
- Anything `misrepresented`/`unverifiable` that survives verification is your actual answer; report it plainly.

## Hard rules

- **The claim is the unit of honesty, not the intent.** An agent doesn't lie; it states inferences as observations. Honest Jev only asks: *what would I show to prove this line?*
- Never upgrade a claim to pass the check — "all tests pass" → "the two tests I ran pass" is honest; renaming the claim to match a narrower truth is the fix, not the problem.
- A confidence hedge is not honesty. "It should work" is a claim with no evidence — either check it or say "not verified."
- When you can't verify and can't run the check, the honest output is the gap itself: "I didn't verify X — here's what it would take."
- Jev unavailable → do the claim-extraction manually and hold the same bar; don't skip the check because the classifier is down.
- This is the same standard for everyone else's claims too — reviewing another agent's "done"? run its claims through the same classify.

## Pairing

- `kit_verify_done` answers "**did you check before done**" — Honest Jev answers "**does the claim match the check**". Use both: verify_done for "I ran tests", honest for everything else you assert.
- `jev-pr-merge-triage` / `jev-issue-triage` classify *other people's* text; Honest Jev classifies *yours*.
