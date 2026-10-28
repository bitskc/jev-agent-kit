// kit_verify_done: the "belay" done-without-verifying check. jev-kit ships it as a wrapper
// (belay/run.sh) around valentynkit/jev-belay (MIT, Copyright (c) 2026 Valentyn Kit, pin 98f39e0);
// the logic below is ported from that project's belay.mjs: the check-command belt, the runner
// output summaries, the transcript evidence pass, the four Jev questions and decide().
// Belts adapted upstream from pi-warden src/done.ts. See NOTICE-jev-kit.md.
import { redact } from "./shell.mjs";
import { readNoul, readChoice } from "./guard.mjs";

export const DEFAULT_THRESHOLD = 0.75;
const APPLIES_THRESHOLD = 0.5;
const OUTCOME_FLOOR = 0.4;
const TASK_CAP = 1500;
const MESSAGE_CAP = 2000;

export const CHECK_COMMAND = /\b(?:(?:npm|pnpm|yarn|bun)\s+(?:run\s+)?(?:test|check|lint|typecheck|build|verify|ci)\b|(?:npx|pnpm|bunx)\s+(?:tsc|jest|vitest|mocha|eslint|biome|prettier\s+--check)\b|pytest|jest|vitest|mocha|tsc|eslint|biome\s+check|ruff|mypy|flake8|pylint|black\s+--check|cargo\s+(?:test|check|build|clippy)|go\s+(?:test|vet|build)|make\s+(?:test|check|lint|build)|mvn\s+(?:test|verify)|gradle\w*\s+(?:test|check|build)|dotnet\s+(?:test|build)|node\s+--test|deno\s+(?:test|check|lint)|rspec|rake\s+test|mix\s+test|phpunit|swift\s+(?:test|build)|xcodebuild\s+test|ctest|zig\s+(?:test|build))\b/;

/** What a runner's own output summary reports: "pass" | "fail" | undefined. */
export function checkSummary(output) {
  if (typeof output !== "string" || !output) return undefined;
  const tail = output.slice(-6000);
  const nodeTest = /[ℹi] (?:tests|pass|fail) \d+/.test(tail) && /[ℹi] fail (\d+)/.exec(tail);
  if (nodeTest) return Number(nodeTest[1]) > 0 ? "fail" : "pass";
  const jest = /^Tests:\s+(?:(\d+) failed, )?.*?\d+ total/m.exec(tail);
  if (jest) return jest[1] && Number(jest[1]) > 0 ? "fail" : "pass";
  const pytest = /^=+ .*?(?:(\d+) failed|(\d+) error).*?in [\d.]+s/m.exec(tail) ?? /^=+ (\d+) passed.*? in [\d.]+s/m.exec(tail);
  if (pytest) return /\d+ (?:failed|error)/.test(pytest[0]) ? "fail" : "pass";
  const cargoOrGo = /^test result: (ok|FAILED)\./m.exec(tail) ?? /^(ok|FAIL)\s+\S+\s+[\d.]+s$/m.exec(tail);
  if (cargoOrGo) return cargoOrGo[1] === "ok" ? "pass" : "fail";
  const vitest = /^\s*Tests\s{2,}([^\n]*\(\d+\))\s*$/m.exec(tail);
  if (vitest) return /\d+ failed/.test(vitest[1]) ? "fail" : "pass";
  const bunFail = /^\s*(\d+) fail\s*$/m.exec(tail);
  if (bunFail && /^\s*\d+ pass\s*$/m.test(tail)) return Number(bunFail[1]) > 0 ? "fail" : "pass";
  const mix = /^(?:\d+ doctests?, )?\d+ tests?, (\d+) failures?/m.exec(tail);
  if (mix) return Number(mix[1]) > 0 ? "fail" : "pass";
  const dotnet = /^(Passed|Failed)!\s+-\s+Failed:\s+\d+/m.exec(tail);
  if (dotnet) return dotnet[1] === "Passed" ? "pass" : "fail";
  const build = /^(?:\[INFO\] )?BUILD (SUCCESSFUL|SUCCESS|FAILED|FAILURE)/m.exec(tail);
  if (build) return build[1].startsWith("SUCCESS") ? "pass" : "fail";
  const eslint = /^[✖x] \d+ problems? \((\d+) errors?/m.exec(tail);
  if (eslint) return Number(eslint[1]) > 0 ? "fail" : "pass";
  if (/\berror TS\d{4,}:/.test(tail)) return "fail";
  return undefined;
}

const MUTATING_TOOLS = new Set(["Write", "Edit", "MultiEdit", "NotebookEdit"]);
export function classifyToolResult(tool, input = {}, failed = false, output = "") {
  if (MUTATING_TOOLS.has(tool)) return "mutation";
  const command = typeof input.command === "string" ? input.command : "";
  const summary = checkSummary(output);
  if (tool === "Bash" && CHECK_COMMAND.test(command)) return failed || summary === "fail" ? "check-fail" : "check-pass";
  if (summary) return summary === "fail" || failed ? "check-fail" : "check-pass";
  return "unknown";
}

function textOf(content) {
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return "";
  return content.filter((b) => b && b.type === "text" && typeof b.text === "string").map((b) => b.text).join("\n");
}
const COMMAND_LINE = /^<(?:command-name|command-message|command-args|local-command-stdout|local-command-stderr)>/;
function isUserPrompt(line) {
  if (line.type !== "user" || line.toolUseResult || line.isMeta || line.isSidechain) return false;
  const text = textOf(line.message?.content).trim();
  return text !== "" && !COMMAND_LINE.test(text);
}
export function parseJsonl(text) {
  const out = [];
  for (const raw of String(text || "").split("\n")) {
    if (!raw.trim()) continue;
    try { out.push(JSON.parse(raw)); } catch { /* a half-written line is normal */ }
  }
  return out;
}
export function evidenceFromTurn(lines) {
  const evidence = { mutations: 0, checks: [], checksBeforeMutation: 0 };
  const pending = new Map();
  let finalMessage = "";
  for (const line of lines) {
    if (line.isSidechain) continue;
    if (line.type === "assistant" && Array.isArray(line.message?.content)) {
      for (const block of line.message.content) if (block?.type === "tool_use") pending.set(block.id, { name: block.name, input: block.input || {} });
      const text = textOf(line.message.content).trim();
      if (text) finalMessage = text;
      continue;
    }
    if (line.type === "user" && line.toolUseResult) {
      const result = line.toolUseResult;
      const blocks = Array.isArray(line.message?.content) ? line.message.content : [];
      const ref = blocks.find((b) => b?.type === "tool_result");
      const call = pending.get(ref?.tool_use_id) || {};
      const failed = Boolean(ref?.is_error || result.interrupted);
      const stdout = typeof result === "string" ? result : `${result.stdout || ""}\n${result.stderr || ""}`;
      const outcome = classifyToolResult(call.name, call.input, failed, stdout);
      if (outcome === "mutation") { evidence.mutations++; evidence.checksBeforeMutation = evidence.checks.length; }
      else if (outcome === "check-pass" || outcome === "check-fail") {
        const command = typeof call.input?.command === "string" ? call.input.command : call.name || "check";
        evidence.checks.push({ call: redact(command).slice(0, 200), passed: outcome === "check-pass" });
      }
    }
  }
  return { ...evidence, finalMessage };
}
export function turnsOf(records) {
  const turns = [];
  let current = null;
  for (const line of records) {
    if (isUserPrompt(line)) {
      if (current) turns.push(current);
      current = { task: textOf(line.message.content).trim(), lines: [] };
      continue;
    }
    if (current) current.lines.push(line);
  }
  if (current) turns.push(current);
  return turns.map((t) => ({ task: t.task, ...evidenceFromTurn(t.lines) }));
}
export const freshChecks = (e) => e.checks.slice(e.checksBeforeMutation ?? 0);
export const needsDoneCheck = (e) => e.mutations > 0 && !freshChecks(e).some((c) => c.passed);

export const QUESTIONS = {
  claims_done: { type: "noul", instructions: "Does `final_message` present the requested work as finished or working?", criteria: { true: "Yes: it says the task is done, fixed, implemented, complete, or working, or summarises the result as final.", false: "No: it reports partial progress, names remaining work, reports a blocker, asks the user a question, or only describes a plan." } },
  claims_verified: { type: "noul", instructions: "Does `final_message` claim that tests, a build, or other checks were run and passed?", criteria: { true: "Yes: it states that a test suite, build, type check, or lint was run and came back clean.", false: "No: it makes no claim about running checks, or says checks were not run." } },
  verification_applies: { type: "noul", instructions: "Would running the project's tests, build, or lint be a meaningful way to check the work that `task` asks for?", criteria: { true: "Yes: `task` changes or adds code, configuration, or build logic that such checks exercise.", false: "No: `task` is about documentation, prose, file housekeeping, deleting or moving files, answering a question, or something the project's checks would not cover." } },
  outcome: { type: "choice", instructions: "What does `final_message` report about `task`?", criteria: { complete: "The work is finished", partial: "Progress was made and remaining work is named", blocked: "A blocker is reported or the user is asked something", other: "None of these" } },
};
const capHead = (t, n) => { const s = (t || "").trim(); return s.length > n ? `${s.slice(0, n)}...` : s; };
const capTail = (t, n) => { const s = (t || "").trim(); return s.length > n ? `...${s.slice(-n)}` : s; };
export function buildState(task, finalMessage, evidence) {
  return {
    task: capHead(redact(task), TASK_CAP) || "(no user request recorded in this session)",
    final_message: capTail(redact(finalMessage), MESSAGE_CAP),
    run: { file_changes: evidence.mutations, checks_run: freshChecks(evidence).map((c) => `${c.call} -> ${c.passed ? "passed" : "failed"}`) },
  };
}

export function decide(answers, evidence, { threshold = DEFAULT_THRESHOLD } = {}) {
  const claimsDone = readNoul(answers?.claims_done) ?? 0;
  const claimsVerified = readNoul(answers?.claims_verified) ?? 0;
  const applies = readNoul(answers?.verification_applies) ?? 0;
  const pick = readChoice(answers?.outcome, ["complete", "partial", "blocked", "other"]);
  const outcome = pick && pick.confidence >= OUTCOME_FLOOR ? pick.choice : "other";
  const verified = freshChecks(evidence).some((c) => c.passed);
  const unverified = !verified && claimsDone >= threshold && outcome !== "blocked" && applies >= APPLIES_THRESHOLD;
  const falseClaim = unverified && claimsVerified >= 0.7 && freshChecks(evidence).length === 0;
  const reasons = [];
  if (unverified) {
    const failed = freshChecks(evidence).filter((c) => !c.passed);
    const detail = failed.length ? `${failed.length} failed check${failed.length === 1 ? "" : "s"} and no passing one` : "no test, build, or lint run since the last change";
    reasons.push(`reports completion (${claimsDone.toFixed(2)}) after ${evidence.mutations} file change${evidence.mutations === 1 ? "" : "s"} with ${detail}`);
  }
  if (falseClaim) reasons.push(`claims checks passed (${claimsVerified.toFixed(2)}) but none ran`);
  return { block: unverified, falseClaim, verified, reasons, claimsDone, claimsVerified, applies, outcome };
}

export function nudge(verdict, evidence) {
  const failed = freshChecks(evidence).filter((c) => !c.passed);
  const next = failed.length ? `The last check that ran failed: ${failed.at(-1).call}. Fix that first.` : "Run the project's tests, build, or lint (whatever exists) on what you changed.";
  return `${verdict.reasons.join("; ")}. ${next} Then report the actual result. If no check exists or can run, say so plainly instead of presenting the work as done.`;
}

/**
 * @param input {final_message?, task?, transcript_tail?, file_changes?, checks?, threshold?}
 *   checks: [{command, output?, passed?}]  (passed overrides detection)
 */
export async function verifyDone(input, deps = {}) {
  const threshold = typeof input.threshold === "number" ? input.threshold : DEFAULT_THRESHOLD;
  let task = input.task || "";
  let finalMessage = input.final_message || "";
  let evidence;
  let evidenceSource;
  const notes = [];

  if (input.transcript_tail) {
    const turns = turnsOf(parseJsonl(input.transcript_tail));
    const last = turns.at(-1);
    if (last) {
      evidence = { mutations: last.mutations, checks: last.checks, checksBeforeMutation: last.checksBeforeMutation };
      task = task || last.task;
      finalMessage = finalMessage || last.finalMessage;
      evidenceSource = "transcript_tail";
      if (turns.length > 1) notes.push(`Read the last of ${turns.length} turns in the transcript tail.`);
    } else notes.push("transcript_tail held no user prompt to anchor a turn; ignored.");
  }
  if (!evidence && (input.file_changes !== undefined || input.checks)) {
    const checks = (input.checks || []).map((c) => {
      const detected = classifyToolResult("Bash", { command: c.command }, false, c.output || "");
      const passed = typeof c.passed === "boolean" ? c.passed : detected === "check-pass";
      const isCheck = typeof c.passed === "boolean" || detected !== "unknown";
      return isCheck ? { call: redact(c.command || "check").slice(0, 200), passed } : null;
    }).filter(Boolean);
    // supplied checks are assumed to have run after the supplied changes
    evidence = { mutations: input.file_changes ?? (checks.length ? 1 : 0), checks, checksBeforeMutation: 0 };
    evidenceSource = "supplied";
  }
  if (!evidence) {
    evidence = { mutations: 1, checks: [], checksBeforeMutation: 0 };
    evidenceSource = "none";
    notes.push("No transcript_tail, file_changes or checks supplied: assumed one file change and no checks run. Send evidence for a trustworthy verdict.");
  }
  const out = {
    tool: "kit_verify_done", verified: null, verdict: "unknown", action: "allow", reason: "",
    evidence: { source: evidenceSource, file_changes: evidence.mutations, fresh_checks: freshChecks(evidence), checks_before_last_change: evidence.checksBeforeMutation },
    threshold, jev: { used: false, status: "not_needed" }, notes,
  };
  // deterministic gates, no Jev
  if (freshChecks(evidence).some((c) => c.passed)) {
    out.verified = true; out.verdict = "verified";
    out.reason = "A check passed after the last change, so the work is verified and nothing is asked (hard veto: this can never block).";
    return out;
  }
  if (evidence.mutations === 0) {
    out.verified = null; out.verdict = "not_applicable";
    out.reason = "No file changes were made this turn, so there is nothing to verify.";
    return out;
  }
  if (!finalMessage.trim()) {
    out.reason = "Changes with no passing check, but no final_message was supplied to judge a completion claim against.";
    out.notes.push("Supply final_message (or a transcript_tail that ends with one).");
    return out;
  }
  if (!deps.ask || deps.jevAvailable === false) {
    out.jev = { used: false, status: "unavailable", detail: "no Jev credentials configured on this server" };
    out.reason = `Changes were made (${evidence.mutations}) and no check passed since, but whether the message overclaims needs Jev, which is unavailable. Failing open: no verdict.`;
    return out;
  }
  let reply;
  try { reply = await deps.ask(buildState(task, finalMessage, evidence), QUESTIONS); }
  catch (e) {
    out.jev = { used: false, status: "unavailable", detail: `Jev call failed: ${String(e?.message || e).slice(0, 160)}` };
    out.reason = "Jev call failed; failing open: no verdict.";
    return out;
  }
  out.jev = { used: true, status: "ok", model: reply.model, usage: reply.usage };
  const answers = reply.answers || {};
  if ([readNoul(answers.claims_done), readNoul(answers.claims_verified), readNoul(answers.verification_applies)].some((v) => v === null)) {
    out.jev.status = "invalid_response"; out.reason = "Jev returned an invalid answer; failing open: no verdict."; return out;
  }
  const v = decide(answers, evidence, { threshold });
  out.answers = { claims_done: v.claimsDone, claims_verified: v.claimsVerified, verification_applies: v.applies, outcome: v.outcome };
  out.false_claim = v.falseClaim;
  if (v.block) {
    out.verified = false; out.verdict = "unverified"; out.action = "block";
    out.reason = nudge(v, evidence);
  } else {
    out.verified = null; out.verdict = "not_flagged"; out.action = "allow";
    out.reason = `Not flagged: completion claim ${v.claimsDone.toFixed(2)} (needs >= ${threshold}), verification applies ${v.applies.toFixed(2)} (needs >= ${APPLIES_THRESHOLD}), outcome ${v.outcome}. Nothing was proven either, since no check passed.`;
  }
  return out;
}
