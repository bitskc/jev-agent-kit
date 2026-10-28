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
function readLevel(): Level {
  try { return normalize(fs.readFileSync(FLAG, "utf8")) ?? "off"; } catch { return "off"; }
}
function writeLevel(level: Level): void {
  if (level === "off") { try { fs.unlinkSync(FLAG); } catch { /* absent */ } return; }
  fs.mkdirSync(path.dirname(FLAG), { recursive: true });
  fs.writeFileSync(FLAG, level + "\n");
}
function instructions(level: Level): string {
  const head = `HONEST JEV ACTIVE — level: ${level}\n\n`;
  try {
    const body = fs.readFileSync(SKILL, "utf8").replace(/^---[\s\S]*?---\s*/, "");
    return head + body.split(/\r?\n/).filter((line) => {
      const row = line.match(/^\|\s*\*\*(.+?)\*\*\s*\|/);
      const rowLevel = row ? normalize(row[1]) : null;
      return rowLevel ? rowLevel === level : true;
    }).join("\n");
  } catch {
    return head + 'Before claiming done, fixed, works, verified or safe: for every claim ask "what would I show to prove this line?" ' +
      "Send only claims backed by output you produced this turn; keep hedges visible; rewrite overclaims to what the evidence shows.";
  }
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
      const level = normalize(String(args ?? "").trim() || "standard");
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
