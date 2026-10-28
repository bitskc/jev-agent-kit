// node --test "hooks/jev-stop-verify.test.mjs" (also covered by `node --test "hooks/**/*.test.mjs"`)
// Calls the real decide() from hooks/jev-stop-verify.js in-process, with a stub `fetchImpl` standing in
// for the jev-mcp worker (no real HTTP/TLS socket — this sandbox's child processes cannot reach a server
// bound by their parent over loopback, confirmed while building this; outbound calls to a real external
// host, which is all the shipped hook ever does, work fine). The stub honours AbortSignal the same way a
// real fetch would, so the hook's own 3s-cap timeout logic is exercised for real, not faked.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const here = path.dirname(new URL(import.meta.url).pathname);
const stopGate = require("./jev-stop-verify.js");
const rt = require("./honest/jev-honest-runtime.js");

// ── env isolation, same shape as honest.test.mjs's ISOLATED_ENV_KEYS pattern ──────────────────────────
const ISOLATED_ENV_KEYS = [
  "CLAUDE_CONFIG_DIR", "XDG_CONFIG_HOME", "JEV_HONEST_DEFAULT_LEVEL",
  "JEV_STOP_GATE", "JEV_MCP_URL", "JEV_MCP_TOKEN", "JEV_GUARD_TIMEOUT", "JEV_GUARD_DEBUG",
];
let savedEnv;
test.beforeEach(() => { savedEnv = Object.fromEntries(ISOLATED_ENV_KEYS.map((k) => [k, process.env[k]])); });
test.afterEach(() => {
  for (const k of ISOLATED_ENV_KEYS) { if (savedEnv[k] === undefined) delete process.env[k]; else process.env[k] = savedEnv[k]; }
});
const fresh = () => { const d = fs.mkdtempSync(path.join(os.tmpdir(), "cfgdir-")); process.env.CLAUDE_CONFIG_DIR = d; return d; };
function setBaseEnv({ gate, token = "test-token", timeout = "3" } = {}) {
  process.env.JEV_MCP_URL = "https://stub.invalid/mcp"; // never actually dialed: fetchImpl is injected
  process.env.JEV_MCP_TOKEN = token;
  process.env.JEV_GUARD_TIMEOUT = timeout;
  if (gate !== undefined) process.env.JEV_STOP_GATE = gate; else delete process.env.JEV_STOP_GATE;
}

// ── stub fetchImpl: honours AbortSignal like a real fetch; `responder(toolName, args)` returns the tool's
// JSON result, or null to simulate a server error (504) ──────────────────────────────────────────────
function stubFetch(responder, { hang = false } = {}) {
  const calls = [];
  const fetchImpl = (url, opts) => {
    const rpc = JSON.parse(opts.body);
    calls.push(rpc.params);
    return new Promise((resolve, reject) => {
      if (opts.signal) opts.signal.addEventListener("abort", () => reject(new Error("The operation was aborted")));
      if (hang) return; // never resolves on its own; only the abort listener above settles it
      Promise.resolve(responder(rpc.params.name, rpc.params.arguments)).then((result) => {
        if (result === null) { resolve({ ok: false, status: 504, text: async () => "gateway error" }); return; }
        resolve({ ok: true, status: 200, text: async () => JSON.stringify({ jsonrpc: "2.0", id: rpc.id, result: { content: [{ type: "text", text: JSON.stringify(result) }] } }) });
      });
    });
  };
  return { fetchImpl, calls };
}

// ── fixture builders: Claude Code transcript shape (validated against real sessions during the e2e eval) ──
function userPrompt(text) { return { type: "user", message: { role: "user", content: text } }; }
function assistantToolUse(id, name, input) { return { type: "assistant", message: { role: "assistant", content: [{ type: "tool_use", id, name, input }] } }; }
function toolResult(id, content, isError = false) {
  return { type: "user", toolUseResult: { stdout: typeof content === "string" ? content : "" }, message: { role: "user", content: [{ type: "tool_result", tool_use_id: id, content, is_error: isError }] } };
}
function writeTranscript(lines) {
  const p = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "transcript-")), "session.jsonl");
  fs.writeFileSync(p, lines.map((l) => JSON.stringify(l)).join("\n") + "\n");
  return p;
}
const editedOneFile = () => [userPrompt("Fix the bug."), assistantToolUse("t1", "Edit", { file_path: "x.js" }), toolResult("t1", "ok")];

test("no file changes: allow without ever calling the stub", async () => {
  fresh(); setBaseEnv({ gate: "both" });
  const { fetchImpl, calls } = stubFetch(() => { throw new Error("must not be called"); });
  const transcript = writeTranscript([userPrompt("What does this function do?")]);
  const out = await stopGate.decide({ transcript_path: transcript, last_assistant_message: "It adds two numbers." }, { fetchImpl });
  assert.equal(out, null);
  assert.equal(calls.length, 0);
});

test("gate off (default): never calls the stub even with edits and an overclaiming message", async () => {
  fresh(); setBaseEnv(); // no gate set, no config.json -> off
  const { fetchImpl, calls } = stubFetch(() => { throw new Error("must not be called"); });
  const transcript = writeTranscript(editedOneFile());
  const out = await stopGate.decide({ transcript_path: transcript, last_assistant_message: "Fixed, all tests pass." }, { fetchImpl });
  assert.equal(out, null);
  assert.equal(calls.length, 0);
});

test("verify gate: false completion claim -> block", async () => {
  fresh(); setBaseEnv({ gate: "verify" });
  const { fetchImpl, calls } = stubFetch((name) => {
    assert.equal(name, "kit_verify_done");
    return { verified: false, verdict: "unverified", action: "block", reason: "reports completion after 1 file change with no check run." };
  });
  const transcript = writeTranscript(editedOneFile());
  const out = await stopGate.decide({ transcript_path: transcript, last_assistant_message: "Fixed, all tests pass." }, { fetchImpl });
  assert.ok(out);
  assert.equal(out.decision, "block");
  assert.match(out.reason, /VERIFY:.*not verified/s);
  assert.equal(calls.length, 1);
});

test("verify gate: an honest disclosure is allowed through once the server itself doesn't flag it (e.g. a disclosed_unverified verdict)", async () => {
  fresh(); setBaseEnv({ gate: "verify" });
  // Stands in for verify.mjs's own disclosure handling: an honest "not run" message is not `verified:false`
  // / `verdict:"unverified"`, so this hook's existing block condition already passes it through untouched —
  // no change needed here once that server-side field ships.
  const { fetchImpl } = stubFetch((name) => {
    assert.equal(name, "kit_verify_done");
    return { verified: null, verdict: "disclosed_unverified", action: "allow", reason: "the message itself discloses that nothing was verified." };
  });
  const transcript = writeTranscript(editedOneFile());
  const out = await stopGate.decide({ transcript_path: transcript, last_assistant_message: "Edited the file. Not run or tested, as you asked." }, { fetchImpl });
  assert.equal(out, null);
});

test("loop guard: stop_hook_active never blocks and never calls the stub", async () => {
  fresh(); setBaseEnv({ gate: "both" });
  const { fetchImpl, calls } = stubFetch(() => { throw new Error("must not be called"); });
  const transcript = writeTranscript(editedOneFile());
  const out = await stopGate.decide({ transcript_path: transcript, last_assistant_message: "Fixed, all tests pass.", stop_hook_active: true }, { fetchImpl });
  assert.equal(out, null);
  assert.equal(calls.length, 0);
});

test("timeout: the server never responds, hook fails open within its own (overridden, short) cap", async () => {
  fresh(); setBaseEnv({ gate: "verify", timeout: "0.2" });
  const { fetchImpl } = stubFetch(() => {}, { hang: true });
  const transcript = writeTranscript(editedOneFile());
  const t0 = Date.now();
  const out = await stopGate.decide({ transcript_path: transcript, last_assistant_message: "Fixed, all tests pass." }, { fetchImpl });
  assert.equal(out, null); // fail open
  assert.ok(Date.now() - t0 < 2000, "should fail open near the overridden ~0.2s cap, not hang");
});

test("malformed transcript: unreadable file -> allow, stub never called", async () => {
  fresh(); setBaseEnv({ gate: "both" });
  const { fetchImpl, calls } = stubFetch(() => { throw new Error("must not be called"); });
  const bad = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "transcript-")), "session.jsonl");
  fs.writeFileSync(bad, "{not json\nalso not json{{{\n");
  const out = await stopGate.decide({ transcript_path: bad, last_assistant_message: "Fixed, all tests pass." }, { fetchImpl });
  assert.equal(out, null);
  assert.equal(calls.length, 0);
});

test("missing transcript file: allow, stub never called", async () => {
  fresh(); setBaseEnv({ gate: "both" });
  const { fetchImpl, calls } = stubFetch(() => { throw new Error("must not be called"); });
  const out = await stopGate.decide({ transcript_path: "/nonexistent/path/session.jsonl", last_assistant_message: "Fixed, all tests pass." }, { fetchImpl });
  assert.equal(out, null);
  assert.equal(calls.length, 0);
});

test("honest gate: a claim classified misrepresented at decision auto -> block, quoting the evidence", async () => {
  fresh(); setBaseEnv({ gate: "honest" });
  const { fetchImpl } = stubFetch((name, args) => {
    assert.equal(name, "jev_classify");
    return { results: args.items.map((item, i) => ({ id: item.id, classification: i === 0 ? "misrepresented" : "verified", top_probability: i === 0 ? 0.81 : 0.95, decision: "auto" })) };
  });
  const transcript = writeTranscript([
    userPrompt("Fix the bug."), assistantToolUse("t1", "Edit", { file_path: "src/dedupe.js" }), toolResult("t1", "ok"),
    assistantToolUse("t2", "Bash", { command: "npm test" }), toolResult("t2", "1 passed, 2 failed", false),
  ]);
  const out = await stopGate.decide({ transcript_path: transcript, last_assistant_message: "All tests pass now." }, { fetchImpl });
  assert.ok(out);
  assert.equal(out.decision, "block");
  assert.match(out.reason, /HONEST:.*misrepresented/s);
  assert.match(out.reason, /npm test/); // the real tool-log evidence is quoted back, not the agent's own claim
});

test("honest gate: only review-decision items -> allow (never blocks on review alone)", async () => {
  fresh(); setBaseEnv({ gate: "honest" });
  const { fetchImpl } = stubFetch((name, args) => ({ results: args.items.map((item) => ({ id: item.id, classification: "unverifiable", top_probability: 0.55, decision: "review" })) }));
  const transcript = writeTranscript(editedOneFile());
  const out = await stopGate.decide({ transcript_path: transcript, last_assistant_message: "Updated the file." }, { fetchImpl });
  assert.equal(out, null);
});

test("honest gate auto-engages at Honest Jev level strict even with JEV_STOP_GATE unset", async () => {
  const d = fresh(); setBaseEnv(); // JEV_STOP_GATE unset entirely
  fs.writeFileSync(path.join(d, ".jev-honest-active"), "strict");
  const { fetchImpl } = stubFetch((name, args) => ({ results: args.items.map((item) => ({ id: item.id, classification: "unverifiable", top_probability: 0.9, decision: "auto" })) }));
  const transcript = writeTranscript(editedOneFile());
  const out = await stopGate.decide({ transcript_path: transcript, last_assistant_message: "Done, works great." }, { fetchImpl });
  assert.ok(out);
  assert.equal(out.decision, "block");
});

test("honest gate at non-strict level does not auto-engage when JEV_STOP_GATE is unset", async () => {
  const d = fresh(); setBaseEnv();
  fs.writeFileSync(path.join(d, ".jev-honest-active"), "standard");
  const { fetchImpl, calls } = stubFetch(() => { throw new Error("must not be called"); });
  const transcript = writeTranscript(editedOneFile());
  const out = await stopGate.decide({ transcript_path: transcript, last_assistant_message: "Done, works great." }, { fetchImpl });
  assert.equal(out, null);
  assert.equal(calls.length, 0);
});

test("gate both: runs verify and honest; either alone can block", async () => {
  fresh(); setBaseEnv({ gate: "both" });
  const { fetchImpl, calls } = stubFetch((name, args) => {
    if (name === "kit_verify_done") return { verified: true, verdict: "verified", action: "allow", reason: "a check passed" };
    return { results: args.items.map((item) => ({ id: item.id, classification: "misrepresented", top_probability: 0.9, decision: "auto" })) };
  });
  const transcript = writeTranscript([
    userPrompt("Fix the bug."), assistantToolUse("t1", "Edit", { file_path: "x.js" }), toolResult("t1", "ok"),
    assistantToolUse("t2", "Bash", { command: "npm test" }), toolResult("t2", "3 passed, 0 failed"),
  ]);
  const out = await stopGate.decide({ transcript_path: transcript, last_assistant_message: "All tests pass." }, { fetchImpl });
  assert.ok(out);
  assert.equal(out.decision, "block");
  assert.match(out.reason, /HONEST:/); // verify passed (no VERIFY: section); honest still blocks
  assert.doesNotMatch(out.reason, /VERIFY:/);
  assert.equal(calls.length, 2);
});

test("server error (504) on verify: fails open, allow", async () => {
  fresh(); setBaseEnv({ gate: "verify" });
  const { fetchImpl } = stubFetch(() => null); // responder returning null -> stub answers 504
  const transcript = writeTranscript(editedOneFile());
  const out = await stopGate.decide({ transcript_path: transcript, last_assistant_message: "Fixed, all tests pass." }, { fetchImpl });
  assert.equal(out, null);
});

test("missing JEV_MCP_TOKEN: fails open without attempting a call", async () => {
  fresh(); setBaseEnv({ gate: "verify" });
  delete process.env.JEV_MCP_TOKEN;
  const { fetchImpl, calls } = stubFetch(() => { throw new Error("must not be called"); });
  const transcript = writeTranscript(editedOneFile());
  const out = await stopGate.decide({ transcript_path: transcript, last_assistant_message: "Fixed, all tests pass." }, { fetchImpl });
  assert.equal(out, null);
  assert.equal(calls.length, 0);
});

test("splitClaims: bullets and sentences, structural filters only (no keyword gating)", () => {
  const msg = "## Header: not a claim\n- Fixed the bug in src/x.js. It now works correctly.\n- Not committed yet.\nIs that okay?\n## Another heading\nShort.";
  const claims = stopGate.splitClaims(msg);
  assert.ok(claims.some((c) => c.includes("Fixed the bug")));
  assert.ok(claims.some((c) => c.includes("works correctly")));
  assert.ok(claims.some((c) => c.includes("Not committed yet")));
  assert.ok(!claims.some((c) => c.includes("Header"))); // heading-only line dropped
  assert.ok(!claims.some((c) => c.includes("Is that okay"))); // a question is not a claim
  assert.ok(!claims.some((c) => c === "Short.")); // under the 10-char floor
});

test("parseForVerify: checks only count after the last edit", () => {
  const lines = [
    userPrompt("Fix it."),
    assistantToolUse("t0", "Bash", { command: "npm test" }), toolResult("t0", "1 passed, 1 failed"),
    assistantToolUse("t1", "Edit", { file_path: "x.js" }), toolResult("t1", "ok"),
    assistantToolUse("t2", "Bash", { command: "npm test" }), toolResult("t2", "2 passed, 0 failed"),
  ];
  const vp = stopGate.parseForVerify(lines);
  assert.equal(vp.fileChanges, 1);
  assert.equal(vp.checks.length, 1); // the pre-edit npm test run does not count
  assert.match(vp.checks[0].output, /2 passed/);
});

test("parseForHonest: scoped to tool calls since the LAST user prompt, not the whole session", () => {
  const lines = [
    userPrompt("First ask."),
    assistantToolUse("t1", "Edit", { file_path: "old.js" }), toolResult("t1", "ok"),
    userPrompt("Second ask."),
    assistantToolUse("t2", "Edit", { file_path: "new.js" }), toolResult("t2", "ok"),
    assistantToolUse("t3", "Bash", { command: "npm test" }), toolResult("t3", "3 passed"),
  ];
  const ev = stopGate.parseForHonest(lines);
  assert.deepEqual(ev.edits, ["new.js"]); // old.js, from before the last prompt, is excluded
  assert.equal(ev.runs.length, 1);
  assert.equal(ev.runs[0].command, "npm test");
});
