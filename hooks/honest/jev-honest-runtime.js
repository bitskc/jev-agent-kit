#!/usr/bin/env node
// Honest Jev — shared runtime for the Claude Code hooks (SessionStart / UserPromptSubmit / SubagentStart).
// Zero dependencies. Flag file: $CLAUDE_CONFIG_DIR/.jev-honest-active (default ~/.claude). Absent flag = off.
const fs = require('fs');
const os = require('os');
const path = require('path');

const LEVELS = ['off', 'soft', 'standard', 'strict'];
const DEFAULT_LEVEL = 'off'; // opt-in: a fresh install never injects until the user turns it on
const STATE_FILE = '.jev-honest-active';
// Plugin layout: <root>/hooks/honest -> <root>/skills; install.sh layout: fall back to the agent's installed skills dir.
const SKILL_CANDIDATES = () => [
  path.join(__dirname, '..', '..', 'skills', 'jev-honest', 'SKILL.md'),
  path.join(claudeDir(), 'skills', 'jev-honest', 'SKILL.md'),
];

function claudeDir() {
  return process.env.CLAUDE_CONFIG_DIR || path.join(os.homedir(), '.claude');
}
function configPath() {
  const base = process.env.XDG_CONFIG_HOME || path.join(os.homedir(), '.config');
  return path.join(base, 'jev', 'config.json');
}
function statePath() {
  return path.join(claudeDir(), STATE_FILE);
}

function normalizeLevel(v) {
  if (typeof v !== 'string') return null;
  const n = v.trim().toLowerCase();
  if (n === 'on' || n === 'full') return 'standard';
  if (n === 'lite') return 'soft';
  return LEVELS.includes(n) ? n : null;
}

// Default level: JEV_HONEST_DEFAULT_LEVEL env > ~/.config/jev/config.json {"honestLevel": ...} > off.
function defaultLevel() {
  const env = normalizeLevel(process.env.JEV_HONEST_DEFAULT_LEVEL);
  if (env) return env;
  try {
    const cfg = JSON.parse(fs.readFileSync(configPath(), 'utf8').replace(/^\uFEFF/, ''));
    return normalizeLevel(cfg.honestLevel) || DEFAULT_LEVEL;
  } catch {
    return DEFAULT_LEVEL;
  }
}

function readLevel() {
  try {
    return normalizeLevel(fs.readFileSync(statePath(), 'utf8')) || null;
  } catch {
    return null;
  }
}
function setLevel(level) {
  const p = statePath();
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, level + '\n');
}
function clearLevel() {
  try { fs.unlinkSync(statePath()); } catch { /* absent is fine */ }
}

// "/honest-jev strict", "honest-jev off", "/jev-agent-kit:honest-jev soft" (plugin-namespaced), "stop honest-jev",
// "normal mode" -> level | null. Whole-message match only: a prompt that merely mentions it never switches.
function parseCommand(prompt) {
  const t = String(prompt || '').trim().toLowerCase().replace(/[.!?\s]+$/, '');
  if (t === 'stop honest-jev' || t === 'stop honest jev' || t === 'normal mode') return 'off';
  const m = t.match(/^[/@$]?(?:[a-z0-9-]+:)?(?:honest-jev|jev-honest)(?:\s+([a-z]+))?$/);
  if (!m) return null;
  return m[1] === undefined ? 'standard' : normalizeLevel(m[1]);
}

// Inject the SKILL.md body with the level table filtered to the active level — the skill file is the single
// source of truth; the hook never carries a second copy of the rules.
function filterSkillBody(body, level) {
  const noFrontmatter = String(body || '').replace(/^---[\s\S]*?---\s*/, '');
  return noFrontmatter.split(/\r?\n/).filter((line) => {
    const row = line.match(/^\|\s*\*\*(.+?)\*\*\s*\|/);
    if (!row) return true;
    const rowLevel = normalizeLevel(row[1]);
    return rowLevel ? rowLevel === level : true;
  }).join('\n');
}

function instructions(level) {
  const head = 'HONEST JEV ACTIVE — level: ' + level + '\n\n';
  for (const p of SKILL_CANDIDATES()) {
    try { return head + filterSkillBody(fs.readFileSync(p, 'utf8'), level); } catch { /* try next */ }
  }
  return head + 'Before claiming done, fixed, works, verified or safe: for every claim ask "what would I show to prove this line?" ' +
    'Send only claims backed by output you produced this turn; keep hedges visible; rewrite overclaims to what the evidence shows. ' +
    'Switch: /honest-jev soft|standard|strict|off.';
}

// Claude Code: SessionStart and UserPromptSubmit take raw stdout as context; SubagentStart needs the JSON form.
function emit(event, context) {
  if (!context) return;
  if (event === 'SubagentStart') {
    process.stdout.write(JSON.stringify({ hookSpecificOutput: { hookEventName: event, additionalContext: context } }));
    return;
  }
  process.stdout.write(context);
}

module.exports = { LEVELS, DEFAULT_LEVEL, claudeDir, statePath, normalizeLevel, defaultLevel, readLevel, setLevel, clearLevel, parseCommand, filterSkillBody, instructions, emit };
