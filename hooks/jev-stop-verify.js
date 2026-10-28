#!/usr/bin/env node
// PROTOTYPE — Claude Code Stop hook. Not wired into install.sh or the shipped plugin manifest.
//
// Enforcement-gap experiment (jev-agent-kit e2e eval, scenario 6): jev-verify-before-done is
// skill-driven only — nothing stops the agent from sending "done" without ever calling
// kit_verify_done. This hook reads the session transcript Claude Code hands us at Stop time,
// reconstructs the same {task, final_message, file_changes, checks} shape the skill asks the
// model to send by hand, calls kit_verify_done itself, and blocks the stop (forcing another
// turn) when the server says `unverified`. Loop guard: `stop_hook_active` (Claude Code sets
// this true on the *second* consecutive Stop-hook pass for the same stop) always allows through,
// so a bad transcript read or a persistently-unhappy verdict can only force one extra turn, never
// an infinite loop.
//
// Needs JEV_MCP_URL + JEV_MCP_TOKEN in the environment (same as the guard hook). Fails open on
// any error: a missing transcript, a malformed line, a network error, or a non-2xx/err response
// all fall through to allowing the stop, with a note on stderr when JEV_GUARD_DEBUG=1.
'use strict';
const fs = require('fs');

function note(msg) {
  if (process.env.JEV_GUARD_DEBUG === '1') process.stderr.write('jev-stop-verify: ' + msg + '\n');
}

function allow() { process.exit(0); }

function textOf(content) {
  if (typeof content === 'string') return content;
  if (!Array.isArray(content)) return '';
  return content
    .filter((c) => c && c.type === 'text' && typeof c.text === 'string')
    .map((c) => c.text)
    .join('\n');
}

function resultTextOf(content) {
  if (typeof content === 'string') return content;
  if (!Array.isArray(content)) return '';
  return content
    .map((c) => (typeof c === 'string' ? c : c && typeof c.text === 'string' ? c.text : ''))
    .join('\n');
}

// Parse the transcript JSONL into: first user prompt (best-effort `task`), the last assistant
// text block (the draft `final_message` the agent is about to send by stopping), a count of
// Edit/Write/NotebookEdit tool calls (`file_changes`), and the Bash tool calls that happened
// after the LAST such edit, each paired with its tool_result and an inferred exit code
// (`is_error` on the result content is the only exit-code-shaped signal Claude Code transcripts
// carry for Bash; a prototype treats is_error:false as exit_code 0 and true as 1).
function parseTranscript(path) {
  const lines = fs.readFileSync(path, 'utf8').split('\n');
  let task = null;
  let finalMessage = null;
  let fileChanges = 0;
  let lastEditIdx = -1;
  const bashCalls = []; // {idx, id, command}
  const resultsById = new Map(); // tool_use_id -> {text, isError}

  let idx = 0;
  for (const raw of lines) {
    const line = raw.trim();
    if (!line) continue;
    let d;
    try { d = JSON.parse(line); } catch { continue; }
    idx += 1;
    const role = d.type || (d.message && d.message.role);
    const content = d.message && d.message.content;
    if (role === 'user' && task === null && typeof content !== 'undefined') {
      const t = textOf(content);
      if (t) task = t.slice(0, 2000);
    }
    if (role === 'assistant' && Array.isArray(content)) {
      for (const c of content) {
        if (c.type === 'text' && c.text) finalMessage = c.text; // last one wins
        if (c.type === 'tool_use') {
          if (c.name === 'Edit' || c.name === 'Write' || c.name === 'NotebookEdit') {
            fileChanges += 1;
            lastEditIdx = idx;
          }
          if (c.name === 'Bash') {
            bashCalls.push({ idx, id: c.id, command: (c.input && c.input.command) || '' });
          }
        }
      }
    }
    if (role === 'user' && Array.isArray(content)) {
      for (const c of content) {
        if (c.type === 'tool_result' && c.tool_use_id) {
          resultsById.set(c.tool_use_id, { text: resultTextOf(c.content), isError: !!c.is_error });
        }
      }
    }
  }

  const checks = bashCalls
    .filter((b) => b.idx > lastEditIdx) // only checks run after the last edit count as evidence
    .map((b) => {
      const r = resultsById.get(b.id) || { text: '', isError: null };
      return {
        command: b.command,
        output: r.text.slice(-4000),
        exit_code: r.isError === null ? undefined : r.isError ? 1 : 0,
      };
    });

  return { task: task || '(unknown — no user message found in transcript)', finalMessage, fileChanges, checks };
}

async function callVerify(args) {
  const url = (process.env.JEV_MCP_URL || '').trim();
  const token = (process.env.JEV_MCP_TOKEN || '').trim();
  if (!url.startsWith('https://') || !token) { note('missing JEV_MCP_URL/JEV_MCP_TOKEN'); return null; }
  const body = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'kit_verify_done', arguments: args } });
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), Number(process.env.JEV_GUARD_TIMEOUT || 5) * 1000);
  try {
    const resp = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', authorization: 'Bearer ' + token },
      body,
      redirect: 'error',
      signal: ctrl.signal,
    });
    const raw = await resp.text();
    if (!resp.ok) { note('server ' + resp.status + ': ' + raw.slice(0, 200)); return null; }
    let d = null;
    for (const line of raw.split('\n')) {
      const l = line.startsWith('data:') ? line.slice(5).trim() : line.trim();
      if (l.startsWith('{')) { d = JSON.parse(l); break; }
    }
    if (!d || d.error) { note('rpc error: ' + JSON.stringify(d && d.error).slice(0, 200)); return null; }
    const text = d.result && d.result.content && d.result.content[0] && d.result.content[0].text;
    return text ? JSON.parse(text) : null;
  } catch (e) {
    note('fetch failed: ' + e.message);
    return null;
  } finally {
    clearTimeout(timer);
  }
}

function block(reason) {
  process.stdout.write(JSON.stringify({ decision: 'block', reason }));
  process.exit(0);
}

let input = '';
process.stdin.on('data', (c) => { input += c; });
process.stdin.on('end', async () => {
  const t0 = Date.now();
  let hook;
  try { hook = JSON.parse(input.replace(/^\uFEFF/, '')); } catch { note('bad hook input'); return allow(); }

  if (hook.stop_hook_active) { note('loop guard: stop_hook_active, allowing'); return allow(); } // never block twice
  if (!hook.transcript_path || !fs.existsSync(hook.transcript_path)) { note('no transcript'); return allow(); }

  let parsed;
  try { parsed = parseTranscript(hook.transcript_path); } catch (e) { note('parse failed: ' + e.message); return allow(); }
  // The transcript file on disk is not guaranteed to be flushed through the final assistant text
  // block yet at the instant Stop fires (observed: `file_changes` from earlier tool_use entries
  // parses fine, but the trailing text block is sometimes still missing) — Claude Code hands the
  // Stop hook that exact text directly, so prefer it and only fall back to the transcript's own
  // last text block if the field is absent.
  const finalMessage = hook.last_assistant_message || parsed.finalMessage;
  if (!finalMessage || parsed.fileChanges === 0) { note('skip: finalMessage=' + (finalMessage ? 'yes(' + finalMessage.length + 'ch)' : 'NONE') + ' fileChanges=' + parsed.fileChanges); return allow(); }

  const verdict = await callVerify({
    task: parsed.task,
    final_message: finalMessage,
    file_changes: parsed.fileChanges,
    checks: parsed.checks,
  });
  note('verify took ' + (Date.now() - t0) + 'ms, verdict=' + JSON.stringify(verdict && { verified: verdict.verified, verdict: verdict.verdict }));
  if (!verdict) return allow(); // fail open: Jev unreachable, rejected, or unparseable
  if (verdict.verified === false || verdict.verdict === 'unverified') {
    return block(
      '[jev-stop-verify] kit_verify_done says this is NOT verified: ' + (verdict.reason || 'no reason given') +
      '\n\nRun the project\'s real checks (tests/build/lint) on what changed, fix what fails, then send your real result — do not just reword the previous message.'
    );
  }
  return allow();
});
