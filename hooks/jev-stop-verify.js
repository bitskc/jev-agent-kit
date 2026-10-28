#!/usr/bin/env node
// Claude Code Stop hook — opt-in enforcement for jev-verify-before-done and Honest Jev. Both skills are
// otherwise skill-driven only: nothing stops an agent from sending "done" (or an overclaiming "fixed, all
// tests pass") without ever calling kit_verify_done / jev_classify. This hook reads the Stop hook's own
// transcript, reconstructs the evidence by hand, and calls those same tools itself.
//
// Opt-in: JEV_STOP_GATE env ('off'|'verify'|'honest'|'both') > ~/.config/jev/config.json {"stopGate": ...}
// (see hooks/honest/jev-honest-runtime.js resolveStopGate/userConfigDir for the exact tiering) > off. A
// fresh install never engages this hook until the user opts in.
//
//   verify: kit_verify_done on {task, final_message, file_changes, checks} — the same shape
//           jev-verify-before-done/SKILL.md asks the model to send by hand. Blocks when verdict is
//           "unverified".
//   honest: jev_classify on the final message's own claims, each paired with evidence BUILT FROM THE
//           TRANSCRIPT's real tool calls since the user's last prompt — not the agent's own self-written
//           EVIDENCE text, which is the self-attestation weakness Honest Jev's skill-only form can't close.
//           Blocks when >=1 claim classifies as misrepresented/unverifiable at decision "auto".
//   both:   runs both; honest also auto-engages whenever the current Honest Jev level is "strict", even if
//           JEV_STOP_GATE itself is unset — strict already promises "classify before every substantive
//           reply" in prose, so this is the same promise with a tool call behind it.
//
// Never blocks when file_changes == 0 (nothing to verify or disclose) or when stop_hook_active is set (the
// loop guard: never block the same stop twice). Fails open — allows the stop — on any error: a missing or
// malformed transcript, an unreachable/erroring/slow (>3s hard cap per MCP call) jev-mcp worker, or a
// missing JEV_MCP_URL/JEV_MCP_TOKEN. Needs JEV_MCP_URL + JEV_MCP_TOKEN in the environment (same as the
// guard hook).
//
// Dual-mode: run directly (stdin JSON in, stdout JSON decision out, as Claude Code invokes it) or
// `require()`d as a library — `decide(hookInput, { fetchImpl })` is the pure, process.exit-free entry
// point jev-stop-verify.test.mjs calls in-process with a stub `fetchImpl`, so tests need no real network
// socket at all (this sandbox's child processes cannot reach a server bound by their parent over loopback,
// even though outbound calls to a real external host work fine — confirmed while building this).
'use strict';
const fs = require('fs');
const path = require('path');
const rt = require('./honest/jev-honest-runtime.js');

// Hard cap: 3s per MCP call, regardless of JEV_GUARD_TIMEOUT (which may still set something *lower*, e.g.
// for a CI pipeline that wants to fail open even faster). A malformed JEV_GUARD_TIMEOUT (unset, empty, or
// not a number) falls back to the 3s default rather than NaN, which would otherwise make every call abort
// near-instantly and silently disable the gate.
function timeoutMs() {
  const raw = Number(process.env.JEV_GUARD_TIMEOUT);
  const seconds = Number.isFinite(raw) && raw > 0 ? raw : 3;
  return Math.min(seconds * 1000, 3000);
}

function note(msg) {
  if (process.env.JEV_GUARD_DEBUG === '1') process.stderr.write('jev-stop-verify: ' + msg + '\n');
}

// ── transcript line helpers ──────────────────────────────────────────────
function textOf(content) {
  if (typeof content === 'string') return content;
  if (!Array.isArray(content)) return '';
  return content.filter((c) => c && c.type === 'text' && typeof c.text === 'string').map((c) => c.text).join('\n');
}
function resultTextOf(content) {
  if (typeof content === 'string') return content;
  if (!Array.isArray(content)) return '';
  return content.map((c) => (typeof c === 'string' ? c : c && typeof c.text === 'string' ? c.text : '')).join('\n');
}
// Port of server/src/kit/verify.mjs's own isUserPrompt convention (not imported: the server is a separate
// Cloudflare Worker package with its own deps; a hook here stays zero-dependency Node). COMMAND_LINE
// matches the synthetic <command-name>/<command-message>/<command-args>/<local-command-stdout>/
// <local-command-stderr> lines Claude Code injects whenever a slash command runs (including the plugin's
// own /jev-agent-kit:honest-jev) — without this filter, a mid-session slash command would be misread as
// the "last real prompt" and reset the honest-gate's evidence window past real, nearby tool calls.
const COMMAND_LINE = /^<(?:command-name|command-message|command-args|local-command-stdout|local-command-stderr)>/;
function isRealUserPrompt(d) {
  if (d.type !== 'user' || d.toolUseResult || d.isMeta || d.isSidechain) return false;
  const text = textOf(d.message && d.message.content).trim();
  return text !== '' && !COMMAND_LINE.test(text);
}
function readTranscriptLines(transcriptPath) {
  return fs.readFileSync(transcriptPath, 'utf8').split('\n').map((l) => l.trim()).filter(Boolean)
    .map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
}

// ── verify-gate evidence: file_changes + Bash checks run after the LAST edit, across the whole transcript
// (matches jev-verify-before-done/SKILL.md's own "a check that ran before your last edit does not count").
// Ordered by a running per-tool-call counter, NOT by transcript-line index: Claude Code commonly batches
// several tool_use blocks (e.g. Edit then Bash) into one assistant message/line, so two calls in the same
// turn would otherwise share one line index and a same-turn check could never compare as "after" the edit.
function parseForVerify(lines) {
  let task = null;
  let finalMessage = null;
  let fileChanges = 0;
  let lastEditCall = -1;
  let callSeq = -1;
  const bashCalls = [];
  const resultsById = new Map();
  for (const d of lines) {
    if (d.isSidechain) continue;
    const content = d.message && d.message.content;
    if (d.type === 'user' && task === null && typeof content !== 'undefined') {
      const t = textOf(content);
      if (t) task = t.slice(0, 2000);
    }
    if (d.type === 'assistant' && Array.isArray(content)) {
      for (const c of content) {
        if (!c) continue;
        if (c.type === 'text' && c.text) finalMessage = c.text;
        if (c.type === 'tool_use') {
          callSeq += 1;
          if (c.name === 'Edit' || c.name === 'Write' || c.name === 'NotebookEdit') { fileChanges += 1; lastEditCall = callSeq; }
          if (c.name === 'Bash') bashCalls.push({ seq: callSeq, id: c.id, command: (c.input && c.input.command) || '' });
        }
      }
    }
    if (d.type === 'user' && Array.isArray(content)) {
      for (const c of content) {
        if (c && c.type === 'tool_result' && c.tool_use_id) resultsById.set(c.tool_use_id, { text: resultTextOf(c.content), isError: !!c.is_error });
      }
    }
  }
  const checks = bashCalls.filter((b) => b.seq > lastEditCall).map((b) => {
    const r = resultsById.get(b.id) || { text: '', isError: null };
    return { command: b.command, output: r.text.slice(-4000), exit_code: r.isError === null ? undefined : r.isError ? 1 : 0 };
  });
  return { task: task || '(unknown — no user message found in transcript)', finalMessage, fileChanges, checks };
}

// ── honest-gate evidence: every tool call since the user's LAST prompt (not since the last edit — a
// disclosure like "I did not run X" needs the full since-prompt picture, not just the post-edit tail) ──
function parseForHonest(lines) {
  let lastPromptIdx = -1;
  lines.forEach((d, i) => { if (isRealUserPrompt(d)) lastPromptIdx = i; });
  const since = lines.slice(lastPromptIdx + 1);
  const pending = new Map();
  const edits = [];
  const runs = [];
  for (const d of since) {
    if (d.isSidechain) continue;
    const content = d.message && d.message.content;
    if (d.type === 'assistant' && Array.isArray(content)) {
      for (const c of content) {
        if (!c || c.type !== 'tool_use') continue;
        pending.set(c.id, c);
        if (c.name === 'Edit' || c.name === 'Write' || c.name === 'NotebookEdit') {
          edits.push((c.input && (c.input.file_path || c.input.notebook_path)) || '(unknown file)');
        }
      }
    }
    if (d.type === 'user' && Array.isArray(content)) {
      for (const c of content) {
        if (!c || c.type !== 'tool_result' || !c.tool_use_id) continue;
        const call = pending.get(c.tool_use_id);
        if (call && call.name === 'Bash') {
          runs.push({ command: (call.input && call.input.command) || '', isError: !!c.is_error, output: resultTextOf(c.content).slice(-1500) });
        }
      }
    }
  }
  return { edits, runs };
}
function evidenceText({ edits, runs }) {
  const parts = [edits.length ? `Files edited this turn: ${edits.join(', ')}.` : 'No files were edited this turn.'];
  if (runs.length) {
    parts.push('Commands run after the edits:');
    for (const r of runs) {
      const tail = r.output.replace(/\s+/g, ' ').trim().slice(-300);
      parts.push(`- \`${r.command}\` -> ${r.isError ? 'failed' : 'ok'}${tail ? `, output tail: "${tail}"` : ''}`);
    }
  } else {
    parts.push('No commands were run after the edits.');
  }
  return parts.join('\n');
}

// Splits a final message into claim-candidate lines: bullets first, then sentences within each (bulleted
// or plain) line. Deliberately simple and structural, not content-based: no keyword gating of WHICH lines
// get judged (every assertable line goes through jev_classify; the classifier decides the bucket, not a
// regex here) — the only filters are structural: a markdown-heading-only line has no sentence in it, a
// fragment under 10 chars is too short to be a claim, a line ending in "?" is a question, and anything
// inside a ``` fenced code block is code/output, never a claim (a diff snippet with a trailing "." in a
// comment would otherwise get sliced into bogus claim-shaped fragments).
function splitClaims(message) {
  const claims = [];
  let inFence = false;
  for (const rawLine of String(message || '').split('\n')) {
    const line = rawLine.trim();
    if (/^```/.test(line)) { inFence = !inFence; continue; }
    if (inFence) continue;
    if (!line) continue;
    const bulleted = /^(?:[-*]|\d+[.)])\s+(.*)$/.exec(line);
    const text = bulleted ? bulleted[1] : line;
    if (/^#{1,6}\s/.test(text)) continue;
    for (const sentence of text.split(/(?<=[.!?])\s+(?=[A-Z0-9`"'*])/)) {
      const s = sentence.trim().replace(/^\*\*|\*\*$/g, '').trim();
      if (s.length < 10 || s.endsWith('?')) continue;
      claims.push(s.slice(0, 500));
    }
  }
  return claims.slice(0, 64); // jev_classify's own item cap
}

// jev_classify needs its `classes` on every call (unlike the Honest Jev level table, which the hooks
// inject as skill text and never duplicate) — read them from skills/jev-honest/SKILL.md's own fenced
// example so there is still exactly one place these 4 definitions are written down.
function classifyClasses() {
  const candidates = [
    path.join(__dirname, '..', 'skills', 'jev-honest', 'SKILL.md'),
    path.join(rt.claudeDir(), 'skills', 'jev-honest', 'SKILL.md'),
  ];
  for (const p of candidates) {
    try {
      const m = /```json\n([\s\S]*?)\n```/.exec(fs.readFileSync(p, 'utf8'));
      if (m) {
        const parsed = JSON.parse(m[1]);
        if (Array.isArray(parsed.classes) && parsed.classes.length) return { purpose: parsed.purpose, classes: parsed.classes };
      }
    } catch { /* try next candidate */ }
  }
  note('SKILL.md classes block unreadable; using the built-in fallback');
  return {
    purpose: "Check whether an agent's claims are backed by evidence it produced this turn, or are hedging, unverifiable, or misrepresentation.",
    classes: [
      { id: 'verified', description: "The claim matches evidence the agent produced this turn: a command was run and its real output supports exactly this claim." },
      { id: 'hedged', description: "An inference stated as an observation: 'should work', 'probably', 'looks right', 'I believe'. No run backs it." },
      { id: 'unverifiable', description: 'No evidence was produced and none is cited. The agent is asserting without having checked.' },
      { id: 'misrepresented', description: "Evidence exists but the claim overstates it: a partial run called 'all', a symptom patch called 'the fix', scope silently narrowed, a skipped step described as done." },
    ],
  };
}

async function mcpCall(toolName, args, fetchImpl) {
  const doFetch = fetchImpl || fetch;
  const url = (process.env.JEV_MCP_URL || '').trim();
  const token = (process.env.JEV_MCP_TOKEN || '').trim();
  if (!url.startsWith('https://') || !token) { note('missing JEV_MCP_URL/JEV_MCP_TOKEN'); return null; }
  const body = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: toolName, arguments: args } });
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs());
  try {
    const resp = await doFetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', authorization: 'Bearer ' + token },
      body,
      redirect: 'error',
      signal: ctrl.signal,
    });
    const raw = await resp.text();
    if (!resp.ok) { note(toolName + ' server ' + resp.status + ': ' + raw.slice(0, 200)); return null; }
    let d = null;
    for (const line of raw.split('\n')) {
      const l = line.startsWith('data:') ? line.slice(5).trim() : line.trim();
      if (l.startsWith('{')) { d = JSON.parse(l); break; }
    }
    if (!d || d.error) { note(toolName + ' rpc error: ' + JSON.stringify(d && d.error).slice(0, 200)); return null; }
    const text = d.result && d.result.content && d.result.content[0] && d.result.content[0].text;
    return text ? JSON.parse(text) : null;
  } catch (e) {
    note(toolName + ' fetch failed: ' + e.message);
    return null;
  } finally {
    clearTimeout(timer);
  }
}

// Pure decision function: hookInput is the Stop hook's own JSON (session_id, transcript_path,
// last_assistant_message, stop_hook_active, ...). Returns null (allow) or {decision:"block", reason}.
// Never calls process.exit — the CLI wrapper below does that. Never throws — decideInner can (a malformed
// transcript line can still shape-mismatch past the parsers' own null-guards in a way nothing anticipated),
// so this wrapper is the hook's actual fail-open guarantee, not just the per-step note()+return-null calls
// inside decideInner.
async function decide(hookInput, opts) {
  try {
    return await decideInner(hookInput, opts);
  } catch (e) {
    note('decide() threw, failing open: ' + (e && e.message));
    return null;
  }
}

async function decideInner(hookInput, { fetchImpl } = {}) {
  const hook = hookInput || {};
  if (hook.stop_hook_active) { note('loop guard: stop_hook_active, allowing'); return null; }

  const gate = rt.resolveStopGate();
  const honestLevel = rt.readLevel() || rt.defaultLevel();
  const wantsVerify = gate === 'verify' || gate === 'both';
  const wantsHonest = gate === 'honest' || gate === 'both' || honestLevel === 'strict';
  if (!wantsVerify && !wantsHonest) return null; // opt-in: nothing engaged, don't even read the transcript

  if (!hook.transcript_path || !fs.existsSync(hook.transcript_path)) { note('no transcript'); return null; }
  let lines;
  try { lines = readTranscriptLines(hook.transcript_path); } catch (e) { note('read failed: ' + e.message); return null; }

  const vp = parseForVerify(lines);
  // The transcript file is not guaranteed to be flushed through the final assistant text block yet at the
  // instant Stop fires; Claude Code hands that text to the hook directly, so prefer it.
  const finalMessage = hook.last_assistant_message || vp.finalMessage;
  if (!finalMessage || vp.fileChanges === 0) { note('skip: no final message or no file changes'); return null; }

  const reasons = [];

  if (wantsVerify) {
    const verdict = await mcpCall('kit_verify_done', { task: vp.task, final_message: finalMessage, file_changes: vp.fileChanges, checks: vp.checks }, fetchImpl);
    note('verify verdict=' + JSON.stringify(verdict && { verified: verdict.verified, verdict: verdict.verdict }));
    if (verdict && (verdict.verified === false || verdict.verdict === 'unverified')) {
      reasons.push(
        'VERIFY: kit_verify_done says this is not verified: ' + (verdict.reason || 'no reason given') +
        "\nRun the project's real checks (tests/build/lint) on what changed, fix what fails, then send your real result — do not just reword the previous message."
      );
    }
  }

  if (wantsHonest) {
    const claims = splitClaims(finalMessage);
    if (claims.length) {
      const evidence = evidenceText(parseForHonest(lines));
      const { purpose, classes } = classifyClasses();
      const items = claims.map((c, i) => ({ id: 'c' + i, text: `CLAIM: ${c} EVIDENCE (from the session's tool log): ${evidence}` }));
      const result = await mcpCall('jev_classify', { purpose, items, classes }, fetchImpl);
      note('classify results=' + JSON.stringify(result && result.summary));
      if (result && Array.isArray(result.results)) {
        const offending = result.results.filter((r) => (r.classification === 'misrepresented' || r.classification === 'unverifiable') && r.decision === 'auto');
        const review = result.results.filter((r) => r.decision === 'review' && !offending.includes(r));
        if (offending.length) {
          const byId = Object.fromEntries(claims.map((c, i) => ['c' + i, c]));
          const offendingLines = offending.map((r) => `- "${byId[r.id]}" — classified ${r.classification} (${Math.round((r.top_probability || 0) * 100)}%)`);
          let text = `HONEST: ${offending.length} claim${offending.length === 1 ? '' : 's'} in your message ${offending.length === 1 ? 'does' : 'do'} not match the session's own tool log:\n` +
            offendingLines.join('\n') + `\n\nWhat the tool log actually shows:\n${evidence}` +
            '\n\nRewrite those lines to match the evidence above, or run the check they assert, before sending this message.';
          if (review.length) text += `\n\n(${review.length} more claim${review.length === 1 ? '' : 's'} were a thin margin and could not be confirmed either way; not blocking on those alone.)`;
          reasons.push(text);
        }
      }
    }
  }

  return reasons.length ? { decision: 'block', reason: reasons.join('\n\n') } : null;
}

if (require.main === module) {
  let input = '';
  process.stdin.on('data', (c) => { input += c; });
  process.stdin.on('end', async () => {
    let hook;
    try { hook = JSON.parse(input.replace(/^\uFEFF/, '')); } catch { note('bad hook input'); process.exit(0); return; }
    const result = await decide(hook);
    if (result) process.stdout.write(JSON.stringify(result));
    process.exit(0);
  });
}

module.exports = { decide, parseForVerify, parseForHonest, evidenceText, splitClaims, classifyClasses, mcpCall, isRealUserPrompt, readTranscriptLines };
