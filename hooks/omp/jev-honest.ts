// omp (oh-my-pi) hook: Honest Jev level — slash command, per-turn rule injection, native status badge.
// Install:  cp jev-honest.ts ~/.omp/agent/hooks/pre/jev-honest.ts   (user)   or   .omp/hooks/pre/   (project)
// Flag file: ~/.omp/agent/.jev-honest-active (absent = off). Same levels/semantics as the Claude Code hooks.
// CONFIRMED from omp docs (hooks.md): pi.registerCommand, pi.on("before_agent_start") may return { message },
// ctx.ui.setStatus(key, text). Not yet run inside a live omp session; everything is wrapped to fail open.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { ExtensionAPI } from "@oh-my-pi/pi-coding-agent";

const LEVELS = ["off", "soft", "standard", "strict"] as const;
type Level = (typeof LEVELS)[number];
const AGENT_DIR = process.env.PI_CODING_AGENT_DIR ?? path.join(os.homedir(), ".omp", "agent");
const FLAG = path.join(AGENT_DIR, ".jev-honest-active");
const SKILL = path.join(AGENT_DIR, "skills", "jev-honest", "SKILL.md");

function normalize(v: unknown): Level | null {
  const n = String(v ?? "").trim().toLowerCase();
  if (n === "on" || n === "full") return "standard";
  if (n === "lite") return "soft";
  return (LEVELS as readonly string[]).includes(n) ? (n as Level) : null;
}

// ── rules (user-authored standing checks) ──────────────────────────────────
// Three layers merge in id order, later wins: built-in examples (embedded below, since this file is installed
// standalone with no sibling rules.default.json) -> user global (rules.json in userConfigDir(): PI_CODING_AGENT_DIR/jev
// if set, else XDG_CONFIG_HOME/jev, else ~/.config/jev) -> repo
// (.jev/rules.json in the cwd). A {"id":...,"disabled":true} entry at a later layer removes an earlier layer's
// same-id rule. Malformed entries are skipped individually; never crashes the hook.
type Rule = { id: string; when: string; ask: string; evidence: string };
const DEFAULT_RULES: Rule[] = [
  {
    id: "pr-gstack-reviewed",
    when: "presenting a pull request as ready to merge or calling it reviewed/clean/mergeable",
    ask: "Has a real gstack /review run on THIS PR and is it clean?",
    evidence: "review record or Automated Code Review comment on this PR number with a CLEAN verdict and 0 unresolved threads; Auto-review bot comments, Devin checks, reviews on other PRs, or a self-review do not count",
  },
];
const ID_RE = /^[a-z0-9-]{2,48}$/;
// Isolation note (mirrors the Claude Code side's userConfigDir() fix): AGENT_DIR above already follows
// PI_CODING_AGENT_DIR, so a sandboxed omp session expects rules.json/config.json to follow it too — before
// this fix neither did, so a sandboxed session's rule-add/honestLevel default silently landed in the real
// operator's ~/.config/jev regardless of PI_CODING_AGENT_DIR. Tiering: PI_CODING_AGENT_DIR (if set) >
// XDG_CONFIG_HOME (if set) > ~/.config.
function userConfigDir(): string {
  if (process.env.PI_CODING_AGENT_DIR) return path.join(process.env.PI_CODING_AGENT_DIR, "jev");
  const base = process.env.XDG_CONFIG_HOME || path.join(os.homedir(), ".config");
  return path.join(base, "jev");
}
function userRulesPath(): string {
  return path.join(userConfigDir(), "rules.json");
}
function repoRulesPath(): string {
  return path.join(process.cwd(), ".jev", "rules.json");
}
function validRule(r: unknown): r is Rule {
  if (!r || typeof r !== "object") return false;
  const o = r as Record<string, unknown>;
  return typeof o.id === "string" && ID_RE.test(o.id) &&
    typeof o.when === "string" && o.when.trim() !== "" &&
    typeof o.ask === "string" && o.ask.trim() !== "" &&
    (o.evidence === undefined || typeof o.evidence === "string");
}
function validDisable(r: unknown): r is { id: string; disabled: true } {
  if (!r || typeof r !== "object") return false;
  const o = r as Record<string, unknown>;
  return o.disabled === true && typeof o.id === "string" && ID_RE.test(o.id);
}
function readRulesFile(p: string): unknown[] {
  try {
    const raw = JSON.parse(fs.readFileSync(p, "utf8").replace(/^\uFEFF/, ""));
    return Array.isArray(raw) ? raw : [];
  } catch {
    return [];
  }
}
function rules(): Rule[] {
  const merged = new Map<string, Rule>();
  for (const r of DEFAULT_RULES) merged.set(r.id, r);
  for (const file of [userRulesPath(), repoRulesPath()]) {
    for (const entry of readRulesFile(file)) {
      if (validDisable(entry)) { merged.delete(entry.id); continue; }
      if (validRule(entry)) merged.set(entry.id, { id: entry.id, when: entry.when, ask: entry.ask, evidence: entry.evidence ?? "" });
    }
  }
  return [...merged.values()];
}
function slugify(text: string): string {
  const s = String(text ?? "").toLowerCase().trim().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 48);
  return ID_RE.test(s) ? s : "rule";
}
type RuleCmd =
  | { action: "list" }
  | { action: "remove" | "disable"; id: string; repo: boolean }
  | { action: "add"; when: string; ask: string; evidence: string; repo: boolean };
// Parses the args already stripped of the leading "/honest-jev " — expects to start with "rule ". Repo scope is
// explicit only: a trailing " --repo" or " (repo)" on the whole command, or a leading "repo " / "repo: " right
// after add/remove/disable — never a loose "repo" substring inside when/ask/evidence.
const TRAILING_REPO = /^(.*?)\s+(?:--repo|\(repo\))\s*$/i;
const LEADING_REPO = /^repo:?\s+(.*)$/i;
function parseRuleArgs(a: string): RuleCmd | null {
  const m = a.match(/^rule\s+(.+)$/is);
  if (!m) return null;
  let rest = m[1].trim();
  let repo = false;
  const trail = rest.match(TRAILING_REPO);
  if (trail) { rest = trail[1].trim(); repo = true; }
  if (/^list\b/i.test(rest)) return { action: "list" };
  let mm: RegExpMatchArray | null;
  if ((mm = rest.match(/^(remove|disable)\s+(.+)$/i))) {
    const action = mm[1].toLowerCase();
    let body = mm[2].trim();
    const lead = body.match(LEADING_REPO);
    if (lead) { body = lead[1].trim(); repo = true; }
    const idm = body.match(/^([a-z0-9-]{2,48})\b/i);
    if (!idm || (action !== "remove" && action !== "disable")) return null;
    return { action, id: idm[1].toLowerCase(), repo };
  }
  if (/^add\b/i.test(rest)) {
    let body = rest.replace(/^add:?\s*/i, "");
    const lead = body.match(LEADING_REPO);
    if (lead) { body = lead[1].trim(); repo = true; }
    let m2 = body.match(/^"([^"]+)"\s*->\s*"([^"]+)"(?:\s*evidence:\s*"([^"]+)")?/i);
    if (m2) return { action: "add", when: m2[1].trim(), ask: m2[2].trim(), evidence: (m2[3] ?? "").trim(), repo };
    m2 = body.match(/^when\s+(.+?)\s+ask\s+(.+?)(?:\s+evidence\s+(.+))?$/i);
    if (m2) return { action: "add", when: m2[1].trim(), ask: m2[2].trim(), evidence: (m2[3] ?? "").trim(), repo };
    return null;
  }
  return null;
}
function writeRulesFile(file: string, list: unknown[]): void {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(list, null, 2) + "\n");
}
function maskRuleEntry(file: string, id: string): void {
  const list = readRulesFile(file).filter((e) => !(e && typeof e === "object" && (e as Record<string, unknown>).id === id));
  list.push({ id, disabled: true });
  writeRulesFile(file, list);
}
function ruleLine(r: Rule): string {
  return `- [${r.id}] When ${r.when}: ${r.ask}${r.evidence ? ` — Evidence: ${r.evidence}` : ""}`;
}
function applyRuleCommand(cmd: RuleCmd): string {
  if (cmd.action === "list") {
    const all = rules();
    return all.length ? `HONEST JEV RULES:\n${all.map(ruleLine).join("\n")}` : "HONEST JEV RULES: none configured.";
  }
  const file = cmd.repo ? repoRulesPath() : userRulesPath();
  if (cmd.action === "remove" || cmd.action === "disable") {
    maskRuleEntry(file, cmd.id);
    return `HONEST JEV RULE ${cmd.action === "remove" ? "REMOVED" : "DISABLED"}: ${cmd.id}`;
  }
  const id = slugify(cmd.when);
  const list = readRulesFile(file).filter((e) => !(e && typeof e === "object" && (e as Record<string, unknown>).id === id));
  const entry: Rule = { id, when: cmd.when, ask: cmd.ask, evidence: cmd.evidence };
  list.push(entry);
  writeRulesFile(file, list);
  return `HONEST JEV RULE ADDED: ${ruleLine(entry)}\n\nApply this rule from this reply on.`;
}
function rulesSection(): string {
  const list = rules();
  if (!list.length) return "";
  return `\n\n## Rules\n\nBefore you say any of the following, answer the question with evidence in the same message; if you cannot, say so instead of presenting the outcome:\n\n${list.map(ruleLine).join("\n")}`;
}
// Default level: JEV_HONEST_DEFAULT_LEVEL env > config.json {"honestLevel": ...} in userConfigDir() > off
// (same resolution as the Claude Code hooks, so the README's "same levels/semantics" promise actually holds).
function configPath(): string {
  return path.join(userConfigDir(), "config.json");
}
function defaultLevel(): Level {
  const env = normalize(process.env.JEV_HONEST_DEFAULT_LEVEL);
  if (env) return env;
  try {
    const cfg = JSON.parse(fs.readFileSync(configPath(), "utf8").replace(/^\uFEFF/, ""));
    return normalize(cfg.honestLevel) ?? "off";
  } catch {
    return "off";
  }
}
function readLevel(): Level {
  try {
    const fromFlag = normalize(fs.readFileSync(FLAG, "utf8"));
    if (fromFlag) return fromFlag;
  } catch { /* flag absent: fall through to the configured default */ }
  return defaultLevel();
}
function writeLevel(level: Level): void {
  // "off" is written explicitly, never unlinked: an absent flag falls through to defaultLevel(), so deleting
  // the flag on an explicit /honest-jev off would silently re-arm a configured non-off default next session.
  fs.mkdirSync(path.dirname(FLAG), { recursive: true });
  fs.writeFileSync(FLAG, level + "\n");
}
function instructions(level: Level): string {
  const head = `HONEST JEV ACTIVE — level: ${level}\n\n`;
  if (level === "off") return head; // defensive: no caller passes "off", but never inject rules if one does
  let body: string;
  try {
    body = fs.readFileSync(SKILL, "utf8").replace(/^---[\s\S]*?---\s*/, "").split(/\r?\n/).filter((line) => {
      const row = line.match(/^\|\s*\*\*(.+?)\*\*\s*\|/);
      const rowLevel = row ? normalize(row[1]) : null;
      return rowLevel ? rowLevel === level : true;
    }).join("\n");
  } catch {
    body = 'Before claiming done, fixed, works, verified or safe: for every claim ask "what would I show to prove this line?" ' +
      "Send only claims backed by output you produced this turn; keep hedges visible; rewrite overclaims to what the evidence shows.";
  }
  return head + body + rulesSection();
}
function badge(level: Level): string {
  return level === "off" ? "" : level === "standard" ? "[HONEST]" : `[HONEST:${level.toUpperCase()}]`;
}
// Only the ctx surface this hook touches; everything is optional so a UI-less context is a no-op.
type HookCtx = { ui?: { setStatus?: (key: string, text: string) => void; notify?: (message: string, level?: string) => void } };

export default function jevHonest(pi: ExtensionAPI) {
  const setStatus = (ctx: HookCtx | undefined) => { try { ctx?.ui?.setStatus?.("jev-honest", badge(readLevel())); } catch { /* no UI */ } };

  pi.registerCommand("honest-jev", {
    description: "Honest Jev level: soft | standard | strict | off",
    handler: async (args: string, ctx: HookCtx) => {
      const a = String(args ?? "").trim();
      if (/^rule\b/i.test(a)) {
        const cmd = parseRuleArgs(a);
        if (!cmd) {
          try { ctx?.ui?.notify?.('usage: /honest-jev rule add "<when>" -> "<ask>" [evidence: "<evidence>"] | rule list | rule remove <id> | rule disable <id>', "warning"); } catch { /* */ }
          return;
        }
        pi.sendMessage?.({ customType: "jev-honest", content: applyRuleCommand(cmd), display: true });
        return;
      }
      const level = normalize(a || "standard");
      if (!level) { try { ctx?.ui?.notify?.("usage: /honest-jev soft|standard|strict|off", "warning"); } catch { /* */ } return; }
      writeLevel(level);
      setStatus(ctx);
      pi.sendMessage?.({
        customType: "jev-honest",
        content: level === "off" ? "HONEST JEV OFF — confirm in one line." : `HONEST JEV LEVEL CHANGED — level: ${level}. Confirm in one line and apply it from this reply on.\n\n${instructions(level)}`,
        display: true,
      });
    },
  });

  pi.on("session_start", async (_e: unknown, ctx: HookCtx) => { setStatus(ctx); });

  // Inject the current level's rules ahead of each agent run. before_agent_start keeps the first returned message,
  // so this hook must load before any other that also injects; harmless if it loses, the skill file is still loaded.
  pi.on("before_agent_start", async (_e: unknown, ctx: HookCtx) => {
    try {
      const level = readLevel();
      setStatus(ctx);
      if (level === "off") return;
      return { message: { customType: "jev-honest", content: instructions(level), display: false } };
    } catch { return; }
  });
}
