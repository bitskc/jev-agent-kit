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
const run = (script, stdin = "", env = {}) =>
  execFileSync("node", [path.join(here, script)], { input: stdin, env: { ...process.env, ...env }, encoding: "utf8" });

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
  for (const level of ["soft", "standard", "strict"]) {
    const text = rt.instructions(level);
    assert.ok(text.startsWith(`HONEST JEV ACTIVE — level: ${level}`));
    assert.equal((text.match(/^\| \*\*/gm) || []).length, 1, level);
  }
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
