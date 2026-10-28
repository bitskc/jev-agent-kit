// node --test hooks/honest/
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const here = path.dirname(new URL(import.meta.url).pathname);
const rt = require("./jev-honest-runtime.js");

const fresh = () => { const d = fs.mkdtempSync(path.join(os.tmpdir(), "honest-")); process.env.CLAUDE_CONFIG_DIR = d; return d; };
const freshXdg = () => { const d = fs.mkdtempSync(path.join(os.tmpdir(), "xdg-")); process.env.XDG_CONFIG_HOME = d; return d; };
const freshRepo = () => fs.mkdtempSync(path.join(os.tmpdir(), "repo-"));
const run = (script, stdin = "", env = {}) =>
  execFileSync("node", [path.join(here, script)], { input: stdin, env: { ...process.env, ...env }, encoding: "utf8" });
const inRepo = (repo, fn) => {
  const prev = process.cwd();
  process.chdir(repo);
  try { return fn(); } finally { process.chdir(prev); }
};

test("rules: the default PR rule is present with no user or repo files", () => {
  freshXdg();
  inRepo(freshRepo(), () => {
    const list = rt.rules();
    assert.equal(list.length, 1);
    assert.equal(list[0].id, "pr-gstack-reviewed");
  });
  delete process.env.XDG_CONFIG_HOME;
});

test("rules: layer merge order — user global beats built-in, repo beats user global, on the same id", () => {
  const xdg = freshXdg();
  inRepo(freshRepo(), (repo = process.cwd()) => {
    fs.mkdirSync(path.join(xdg, "jev"), { recursive: true });
    fs.writeFileSync(path.join(xdg, "jev", "rules.json"), JSON.stringify([{ id: "pr-gstack-reviewed", when: "user override", ask: "user ask", evidence: "user" }]));
    assert.equal(rt.rules().find((r) => r.id === "pr-gstack-reviewed").when, "user override");
    fs.mkdirSync(path.join(repo, ".jev"), { recursive: true });
    fs.writeFileSync(path.join(repo, ".jev", "rules.json"), JSON.stringify([{ id: "pr-gstack-reviewed", when: "repo override", ask: "repo ask", evidence: "repo" }]));
    assert.equal(rt.rules().find((r) => r.id === "pr-gstack-reviewed").when, "repo override");
  });
  delete process.env.XDG_CONFIG_HOME;
});

test("rules: a disabled entry at a later layer removes an earlier layer's same-id rule", () => {
  freshXdg();
  inRepo(freshRepo(), (repo = process.cwd()) => {
    fs.mkdirSync(path.join(repo, ".jev"), { recursive: true });
    fs.writeFileSync(path.join(repo, ".jev", "rules.json"), JSON.stringify([{ id: "pr-gstack-reviewed", disabled: true }]));
    assert.equal(rt.rules().find((r) => r.id === "pr-gstack-reviewed"), undefined);
  });
  delete process.env.XDG_CONFIG_HOME;
});

test("rules: malformed entries and an unparsable file are skipped, never crash", () => {
  const xdg = freshXdg();
  fs.mkdirSync(path.join(xdg, "jev"), { recursive: true });
  fs.writeFileSync(path.join(xdg, "jev", "rules.json"), JSON.stringify([
    { id: "bad id with spaces", when: "x", ask: "y" },
    { id: "no-ask", when: "x" },
    { when: "x", ask: "y" },
    { id: "good-one", when: "a real situation", ask: "a real question", evidence: "proof" },
  ]));
  const list = rt.rules();
  assert.ok(list.some((r) => r.id === "good-one"));
  assert.equal(list.length, 2); // the built-in default + good-one; every malformed entry skipped
  fs.writeFileSync(path.join(xdg, "jev", "rules.json"), "not json at all");
  assert.doesNotThrow(() => rt.rules());
  assert.equal(rt.rules().length, 1); // falls back to just the built-in default
  delete process.env.XDG_CONFIG_HOME;
});

test("parseRuleCommand: quoted, natural-language, list, remove, disable, and repo-scope forms", () => {
  assert.deepEqual(rt.parseRuleCommand('honest-jev rule add "deploying to prod" -> "did migrations run?"'),
    { action: "add", when: "deploying to prod", ask: "did migrations run?", evidence: "", repo: false });
  assert.deepEqual(rt.parseRuleCommand('/honest-jev rule add "x" -> "y" evidence: "z"'),
    { action: "add", when: "x", ask: "y", evidence: "z", repo: false });
  assert.deepEqual(rt.parseRuleCommand("honest-jev rule add: when touching the repo ask is CI green evidence CI link"),
    { action: "add", when: "touching the repo", ask: "is CI green", evidence: "CI link", repo: true });
  assert.deepEqual(rt.parseRuleCommand("honest-jev rule list"), { action: "list" });
  assert.deepEqual(rt.parseRuleCommand("honest-jev rule remove some-id"), { action: "remove", id: "some-id", repo: false });
  assert.deepEqual(rt.parseRuleCommand("honest-jev rule disable some-id"), { action: "disable", id: "some-id", repo: false });
  assert.equal(rt.parseRuleCommand("talk about honest-jev rule stuff"), null);
  assert.equal(rt.parseRuleCommand("just a normal prompt"), null);
});

test("hooks end to end: rule add via mode-tracker writes the file and emits the rule; rule remove masks it", () => {
  fresh(); const xdg = freshXdg();
  const added = run("jev-honest-mode-tracker.js", JSON.stringify({ prompt: 'honest-jev rule add "shipping a release" -> "did CI run?" evidence: "CI link"' }));
  assert.match(added, /^HONEST JEV RULE ADDED: \[shipping-a-release\]/);
  const file = JSON.parse(fs.readFileSync(path.join(xdg, "jev", "rules.json"), "utf8"));
  assert.equal(file.length, 1);
  assert.equal(file[0].id, "shipping-a-release");
  const removed = run("jev-honest-mode-tracker.js", JSON.stringify({ prompt: "honest-jev rule remove shipping-a-release" }));
  assert.equal(removed, "HONEST JEV RULE REMOVED: shipping-a-release");
  assert.ok(!rt.rules().some((r) => r.id === "shipping-a-release"));
  delete process.env.XDG_CONFIG_HOME;
});

test("instructions: no Rules section (or anything else) at level off", () => {
  assert.equal(rt.instructions("off"), "HONEST JEV ACTIVE — level: off\n\n");
});

test("parseCommand: whole-message switch only, aliases and namespaced forms", () => {
  const cases = {
    "/honest-jev strict": "strict", "honest-jev soft": "soft", "/jev-honest standard": "standard",
    "/jev-agent-kit:honest-jev strict": "strict", "@honest-jev off": "off", "/honest-jev": "standard",
    "/honest-jev lite": "soft", "/honest-jev full": "standard", "/honest-jev on": "standard",
    "Normal mode.": "off", "stop honest-jev": "off",
    "/honest-jev bogus": null, "please set honest-jev strict later": null, "add a normal mode toggle": null, "": null,
  };
  for (const [prompt, want] of Object.entries(cases)) assert.equal(rt.parseCommand(prompt), want, JSON.stringify(prompt));
});

test("filterSkillBody: only the active level's table row survives, everything else verbatim", () => {
  const body = "---\nname: x\n---\n# T\n| Level | What |\n|---|---|\n| **soft** | a |\n| **standard** | b |\n| **strict** | c |\n- rule stays\n| **Other** | not a level |";
  const out = rt.filterSkillBody(body, "strict");
  assert.ok(out.includes("| **strict** | c |") && !out.includes("**soft**") && !out.includes("**standard**"));
  assert.ok(out.includes("- rule stays") && out.includes("| **Other** |") && !out.includes("name: x"));
});

test("instructions: real SKILL.md is injected with exactly one level row", () => {
  fresh(); const xdg = fs.mkdtempSync(path.join(os.tmpdir(), "xdg-")); process.env.XDG_CONFIG_HOME = xdg;
  for (const level of ["soft", "standard", "strict"]) {
    const text = rt.instructions(level);
    assert.ok(text.startsWith(`HONEST JEV ACTIVE — level: ${level}`));
    assert.equal((text.match(/^\| \*\*/gm) || []).length, 1, level);
  }
  delete process.env.XDG_CONFIG_HOME;
});

test("defaultLevel: env beats config file beats off", () => {
  const d = fresh();
  const xdg = fs.mkdtempSync(path.join(os.tmpdir(), "xdg-"));
  process.env.XDG_CONFIG_HOME = xdg; delete process.env.JEV_HONEST_DEFAULT_LEVEL;
  assert.equal(rt.defaultLevel(), "off");
  fs.mkdirSync(path.join(xdg, "jev")); fs.writeFileSync(path.join(xdg, "jev", "config.json"), '{"honestLevel":"soft"}');
  assert.equal(rt.defaultLevel(), "soft");
  process.env.JEV_HONEST_DEFAULT_LEVEL = "strict";
  assert.equal(rt.defaultLevel(), "strict");
  delete process.env.JEV_HONEST_DEFAULT_LEVEL; delete process.env.XDG_CONFIG_HOME;
  assert.equal(fs.existsSync(path.join(d, ".jev-honest-active")), false);
});

test("hooks end to end: fresh install is silent; prompt switch writes flag and injects; subagent mirrors; off persists", () => {
  const d = fresh(); delete process.env.JEV_HONEST_DEFAULT_LEVEL;
  assert.equal(run("jev-honest-activate.js"), "");
  assert.equal(run("jev-honest-subagent.js"), "");
  const changed = run("jev-honest-mode-tracker.js", JSON.stringify({ prompt: "/honest-jev strict" }));
  assert.match(changed, /^HONEST JEV LEVEL CHANGED — level: strict/);
  assert.equal(fs.readFileSync(path.join(d, ".jev-honest-active"), "utf8"), "strict\n");
  assert.match(run("jev-honest-activate.js"), /^HONEST JEV ACTIVE — level: strict/);
  const sub = JSON.parse(run("jev-honest-subagent.js"));
  assert.equal(sub.hookSpecificOutput.hookEventName, "SubagentStart");
  assert.match(sub.hookSpecificOutput.additionalContext, /level: strict/);
  assert.equal(run("jev-honest-mode-tracker.js", JSON.stringify({ prompt: "talk about honest-jev strict mode" })), "");
  assert.match(run("jev-honest-mode-tracker.js", JSON.stringify({ prompt: "honest-jev off" })), /^HONEST JEV OFF/);
  assert.equal(fs.readFileSync(path.join(d, ".jev-honest-active"), "utf8"), "off\n");
  assert.equal(run("jev-honest-mode-tracker.js", "not json"), "");
});
test("off persists across resume even with a configured default: activate never re-arms a turned-off flag", () => {
  // P2: clearLevel() instead of writing "off" let an absent flag fall through to defaultLevel() on the
  // very next SessionStart, silently re-arming a configured non-off default one or two activations later.
  const d = fresh();
  const xdg = fs.mkdtempSync(path.join(os.tmpdir(), "xdg-"));
  process.env.XDG_CONFIG_HOME = xdg; delete process.env.JEV_HONEST_DEFAULT_LEVEL;
  fs.mkdirSync(path.join(xdg, "jev")); fs.writeFileSync(path.join(xdg, "jev", "config.json"), '{"honestLevel":"strict"}');
  assert.match(run("jev-honest-mode-tracker.js", JSON.stringify({ prompt: "/honest-jev off" })), /^HONEST JEV OFF/);
  assert.equal(fs.readFileSync(path.join(d, ".jev-honest-active"), "utf8"), "off\n");
  // first activate (e.g. resume): must stay silent and must not touch the flag
  assert.equal(run("jev-honest-activate.js"), "");
  assert.equal(fs.readFileSync(path.join(d, ".jev-honest-active"), "utf8"), "off\n");
  // second activate (e.g. a later compact/resume): still silent, still off, despite the configured default
  assert.equal(run("jev-honest-activate.js"), "");
  assert.equal(fs.readFileSync(path.join(d, ".jev-honest-active"), "utf8"), "off\n");
  delete process.env.XDG_CONFIG_HOME;
});

test("activate: statusline nudge composes with an existing command and is skipped once wired", () => {
  const d = fresh();
  fs.writeFileSync(path.join(d, ".jev-honest-active"), "standard\n");
  fs.writeFileSync(path.join(d, "settings.json"), JSON.stringify({ statusLine: { type: "command", command: "bash /x/ponytail-statusline.sh" } }));
  const out = run("jev-honest-activate.js");
  assert.match(out, /STATUSLINE SETUP NEEDED/);
  assert.match(out, /"command":"bash \/x\/ponytail-statusline\.sh; bash \\"[^"]*jev-honest-statusline\.sh\\""/);
  fs.writeFileSync(path.join(d, "settings.json"), JSON.stringify({ statusLine: { type: "command", command: "bash /x/jev-honest-statusline.sh" } }));
  assert.doesNotMatch(run("jev-honest-activate.js"), /STATUSLINE SETUP NEEDED/);
});
