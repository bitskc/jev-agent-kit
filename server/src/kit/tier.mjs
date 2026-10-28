// kit_size_dispatch: the sub-agent "tier guard" of jonathanavis96/jev-kit (MIT, Copyright (c) 2026 Jonathan Avis),
// ported from airlock/tiers.py, airlock/questions.py (tier_questions) and airlock/policy.py (evaluate_tier,
// enforce_deny_tier, tier_surface). Question wording and the confidence/margin bars are the kit's.
import { redactCap } from "./shell.mjs";
import { readChoice, readNoul } from "./guard.mjs";

export const CONFIDENCE = 0.8;  // policy.CONFIDENCE_THRESHOLD
export const MARGIN = 0.4;      // policy.MARGIN_THRESHOLD

// Cheapest rung first; the first name is the canonical rung and the name to dispatch.
// kit DEFAULT_LADDER, plus model-family aliases (haiku/sonnet/opus) that the kit does not ship:
// override with the `ladder` input for your own agent or model names.
export const DEFAULT_LADDER = [
  ["scout-find"],
  ["scout", "haiku"],
  ["workerS", "worker", "sonnet"],
  ["workerO"],
  ["director", "claude", "general-purpose", "Plan", "Explore", "opus"],
  ["fable"],
];
export const NON_DISPATCHABLE = new Set(["director"]);
const DIRECTOR_PREFIXES = ["feature-dev:", "code-simplifier:"];
const UNKNOWN_RUNG_FROM_TOP = 2;
export const TASK_KIND_ADEQUATE_RUNG = {
  lookup: "scout-find", mechanical_edit: "scout", scoped_implementation: "workerS",
  judgement: "workerO", hard_problem: "fable",
};

export function validLadder(l) {
  if (!Array.isArray(l) || l.length < 2) return false;
  const seen = new Set();
  for (const rung of l) {
    if (!Array.isArray(rung) || !rung.length) return false;
    for (const n of rung) {
      if (typeof n !== "string" || !n.trim() || seen.has(n)) return false;
      seen.add(n);
    }
  }
  return true;
}

/** Resolve a free-form agent type or model string to a rung. */
export function rungFor(chosen, ladder) {
  const t = (chosen || "").trim();
  for (const rung of ladder) if (rung.includes(t)) return { rung: rung[0], recognised: true };
  const low = t.toLowerCase();
  // family-name containment, e.g. "claude-sonnet-4-5" -> sonnet's rung
  for (const rung of ladder) {
    for (const n of rung.slice(1)) if (n.length >= 4 && low.includes(n.toLowerCase())) return { rung: rung[0], recognised: true, via: "family" };
  }
  if (DIRECTOR_PREFIXES.some((p) => t.startsWith(p))) return { rung: ladder[Math.max(0, ladder.length - UNKNOWN_RUNG_FROM_TOP)][0], recognised: true };
  return { rung: ladder[Math.max(0, ladder.length - UNKNOWN_RUNG_FROM_TOP)][0], recognised: false };
}
export const dispatchNameFor = (rungName, ladder) => {
  for (const rung of ladder) {
    if (rung[0] !== rungName) continue;
    return rung.find((n) => !NON_DISPATCHABLE.has(n)) ?? null;
  }
  return null;
};

export function tierQuestions() {
  const crit = (what, not_for, examples) => ({ what, not_for, examples });
  return {
    task_kind: {
      type: "choice",
      instructions: {
        question: "A director/orchestrator session is about to dispatch an Agent tool call to a sub-agent. Classify what KIND of task the sub-agent is being asked to do, based on the subagent_type, description and prompt given in the state.",
        focus: "Judge the actual work being asked for, not the subagent_type chosen -- the whole point of this question is to check whether the chosen type matches the work. A prompt asking a 'scout' to redesign an architecture is still judgement, not mechanical_edit.",
      },
      criteria: {
        lookup: crit("A fact that already exists somewhere on disk and just needs finding, with no editing and no judgement calls: where is X defined, list every call site of Y, read a file and return specific values, confirm whether a string exists.", "Anything that also asks for a change to be made, however small -- that is mechanical_edit at minimum.", ["Where is the AIRLOCK_DISABLE env var checked?", "List every call site of policy.evaluate_search.", "Read airlock/client.py and tell me the API URL and default timeout."]),
        mechanical_edit: crit("A rename, a formatting pass, boilerplate generated from a clear template, extracting or listing data into a new file, a one-line fix with zero ambiguity about what the right change is.", "A change where more than one reasonable implementation exists, or where the prompt itself is the spec for a new behaviour rather than a mechanical transformation of existing text -- that is scoped_implementation.", ["Rename every use of `foo_bar` to `fooBar` in src/.", "Reformat this JSON file with 2-space indentation.", "Generate a boilerplate test file from tests/template_test.py for module baz."]),
        scoped_implementation: crit("A specified feature, tests for already-defined behaviour, a routine refactor, a bug fix whose root cause is already known and stated in the prompt, docs, or a format conversion.", "A prompt that leaves the requirements ambiguous, asks for an architectural decision to be made, or says the root cause is still unknown -- that is judgement, even if the resulting diff would look similar.", ["Add a --json flag to airlock/report.py that writes the same summary as JSON.", "Write unit tests for policy.evaluate_search covering every branch.", "Fix the off-by-one in _percentile(); the bug is that `hi` can exceed len(values)-1."]),
        judgement: crit("Ambiguous requirements, an architectural decision, a multi-module refactor with real design options to weigh, an unknown root cause still to be diagnosed, or reviewing another agent's work for correctness.", "A task where the prompt already states the root cause and the fix approach, or already names the one acceptable design -- that only needs execution, which is scoped_implementation.", ["The daemon sometimes deadlocks under load; find out why and fix it.", "Decide how the tuning loop should gate a commit and design the mechanism.", "Review this worker's diff for correctness before it merges."]),
        hard_problem: crit("The prompt explicitly states that one or more prior attempts at this exact task were already made and failed, naming what was tried and what broke or was ruled out.", "A task that merely sounds hard, or vaguely asserts difficulty without naming a specific prior attempt -- that is judgement instead.", ["Opus already tried caching the socket and it still leaks fds under load; find the real cause.", "Two attempts to fix the race in daemon.py failed (locking, then a queue); go deeper."]),
        unclear: crit("The prompt does not give enough information to classify confidently into any of the other options.", "Use this only when truly stuck, not as a default.", ["fix it", "look into the thing from earlier"]),
      },
    },
    states_prior_failed_attempts: {
      type: "noul",
      instructions: "Does the prompt explicitly state that one or more prior attempts at this task were already tried and failed, naming what was tried and what went wrong or was ruled out?",
      criteria: {
        true: "The prompt names a specific prior attempt and how it failed, or what approach was ruled out and why.",
        false: "No prior attempt is mentioned, or the only mention is vague (e.g. just asserting 'this is hard').",
      },
    },
    brief_is_self_contained: {
      type: "noul",
      instructions: "Is this brief self-contained: does it name specific file paths or locations to work in, give concrete acceptance criteria for what done looks like, and say how the result should be verified?",
      criteria: {
        true: "Names specific paths/files, states what done looks like, and says how to check the result (a test, a command, a behaviour to confirm).",
        false: "Vague about where to work, what counts as done, or how to verify the outcome.",
      },
    },
  };
}

/**
 * @param input {description, prompt?, model, ladder?}
 * @param deps  {ask?, jevAvailable?}
 */
export async function sizeDispatch(input, deps = {}) {
  const ladder = validLadder(input.ladder) ? input.ladder : DEFAULT_LADDER;
  const names = ladder.map((r) => r[0]);
  const idx = Object.fromEntries(names.map((n, i) => [n, i]));
  const chosen = rungFor(input.model, ladder);
  const out = {
    tool: "kit_size_dispatch",
    chosen: { model: input.model, tier: chosen.rung, tier_index: idx[chosen.rung], recognised: chosen.recognised },
    ladder: names,
    task_kind: null, task_kind_confidence: null, margin: null,
    recommended_tier: null, recommended_model: null,
    mismatch: null, verdict: "unknown", action: "allow",
    reason: "", notes: [], jev: { used: false, status: "not_needed" },
  };
  if (!chosen.recognised) out.notes.push(`"${input.model}" is not in the ladder; treated as the second most expensive rung, as the kit does. Pass \`ladder\` with your own names.`);
  if (!deps.ask || deps.jevAvailable === false) {
    out.jev = { used: false, status: "unavailable", detail: "no Jev credentials configured on this server" };
    out.reason = "Jev unavailable, so the task could not be classified. The guard fails open: no mismatch is claimed.";
    out.notes.push("Only the chosen tier was resolved (deterministic). Set AI_GATEWAY_API_KEY or TYPESAFE_API_KEY on the Worker for a verdict.");
    return out;
  }
  const state = {
    subagent_type: redactCap(input.model || "", 200),
    model_override: "",
    description: redactCap(input.description || "", 600),
    prompt: redactCap(input.prompt || "", 3000),
  };
  let reply;
  try { reply = await deps.ask(state, tierQuestions()); }
  catch (e) {
    out.jev = { used: false, status: "unavailable", detail: `Jev call failed: ${String(e?.message || e).slice(0, 160)}` };
    out.reason = "Jev call failed; the guard fails open: no mismatch is claimed.";
    return out;
  }
  out.jev = { used: true, status: "ok", model: reply.model, usage: reply.usage };
  const a = reply.answers || {};
  const kind = readChoice(a.task_kind, Object.keys(tierQuestions().task_kind.criteria));
  if (!kind) { out.jev.status = "invalid_response"; out.reason = "Jev returned an invalid task_kind answer; failing open."; return out; }
  const prior = readNoul(a.states_prior_failed_attempts) ?? 0;
  const selfContained = readNoul(a.brief_is_self_contained);
  out.task_kind = kind.choice; out.task_kind_confidence = Number(kind.confidence.toFixed(4)); out.margin = kind.margin === null ? null : Number(kind.margin.toFixed(4));
  out.states_prior_failed_attempts = prior; out.brief_is_self_contained = selfContained;

  const adequate = TASK_KIND_ADEQUATE_RUNG[kind.choice];
  const bar = kind.confidence >= CONFIDENCE && (kind.margin ?? 0) >= MARGIN;
  let diff = null;
  if (adequate !== undefined && adequate in idx && chosen.rung in idx) {
    diff = idx[chosen.rung] - idx[adequate];
    out.recommended_tier = adequate;
    out.recommended_model = dispatchNameFor(adequate, ladder);
    out.rung_diff = diff;
  }
  const fableNoFailure = chosen.rung === "fable" && prior < 0.5;
  if (diff !== null && diff > 0 && kind.choice !== "unclear" && bar) {
    out.mismatch = true;
    if (diff >= 2) { out.verdict = "over_tiered"; out.action = "block"; }
    else { out.verdict = "over_tiered"; out.action = "warn"; }
    out.reason = `Dispatched to '${chosen.rung}', but Jev judged this '${kind.choice}' (confidence ${kind.confidence.toFixed(2)}, margin ${(kind.margin ?? 0).toFixed(2)}), which '${adequate}' covers (${diff} rung${diff === 1 ? "" : "s"} over). Use ${out.recommended_model ?? adequate}.`;
  } else if (diff !== null && diff < 0) {
    out.mismatch = true; out.verdict = "under_tiered"; out.action = "allow";
    out.reason = `Jev judged this '${kind.choice}', which needs '${adequate}' or above; '${chosen.rung}' is cheaper. Logged as under-tiered, never blocked (the kit never "corrects" upward).`;
  } else if (diff !== null && diff > 0) {
    out.mismatch = false; out.verdict = "ok"; out.action = "allow";
    out.reason = `Possibly over-tiered ('${kind.choice}' suggests '${adequate}') but below the confidence/margin bar of ${CONFIDENCE}/${MARGIN}, so nothing is flagged.`;
  } else if (diff === null) {
    out.mismatch = null; out.verdict = kind.choice === "unclear" ? "unclear" : "unknown";
    out.reason = kind.choice === "unclear" ? "The brief is too unclear to size; no verdict (the kit never acts on 'unclear')." : "Tier could not be compared against this ladder.";
  } else {
    out.mismatch = false; out.verdict = "ok"; out.action = "allow";
    out.reason = `'${chosen.rung}' matches the task ('${kind.choice}').`;
  }
  if (fableNoFailure) {
    out.mismatch = true; out.verdict = out.verdict === "ok" ? "over_tiered" : out.verdict; out.action = "block";
    out.reason += " Also: the top rung ('fable') was chosen without a stated prior failed attempt, which the kit always blocks.";
  }
  return out;
}
