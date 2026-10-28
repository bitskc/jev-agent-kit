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
// ── rules (user-authored standing checks) ────────────────────────────────────
// Three layers merge in id order, later wins: built-in examples (rules.default.json, shipped with the plugin)
// -> user global (~/.config/jev/rules.json) -> repo (.jev/rules.json in the cwd, so teams can commit rules). A
// {"id":"...","disabled":true} entry at a later layer removes an earlier layer's same-id rule. Malformed
// entries are skipped individually; a hook path never crashes on a bad rules file (JEV_HONEST_DEBUG=1 explains
// why on stderr).
const ID_RE = /^[a-z0-9-]{2,48}$/;

function defaultRulesPath() {
  return path.join(__dirname, 'rules.default.json');
}
function userRulesPath() {
  const base = process.env.XDG_CONFIG_HOME || path.join(os.homedir(), '.config');
  return path.join(base, 'jev', 'rules.json');
}
function repoRulesPath() {
  return path.join(process.cwd(), '.jev', 'rules.json');
}
function debug(msg) {
  if (process.env.JEV_HONEST_DEBUG === '1') process.stderr.write('jev-honest: ' + msg + '\n');
}

function validRule(r) {
  return !!r && typeof r === 'object' && typeof r.id === 'string' && ID_RE.test(r.id) &&
    typeof r.when === 'string' && r.when.trim() !== '' &&
    typeof r.ask === 'string' && r.ask.trim() !== '' &&
    (r.evidence === undefined || typeof r.evidence === 'string');
}
function validDisable(r) {
  return !!r && typeof r === 'object' && r.disabled === true && typeof r.id === 'string' && ID_RE.test(r.id);
}
function readRulesFile(p) {
  try {
    const raw = JSON.parse(fs.readFileSync(p, 'utf8').replace(/^\uFEFF/, ''));
    return Array.isArray(raw) ? raw : [];
  } catch (e) {
    if (fs.existsSync(p)) debug('rules file unreadable: ' + p + ': ' + (e && e.message));
    return [];
  }
}

function rules() {
  const merged = new Map();
  for (const file of [defaultRulesPath(), userRulesPath(), repoRulesPath()]) {
    for (const entry of readRulesFile(file)) {
      if (validDisable(entry)) { merged.delete(entry.id); continue; }
      if (validRule(entry)) merged.set(entry.id, { id: entry.id, when: entry.when, ask: entry.ask, evidence: entry.evidence || '' });
      else debug('skipped malformed rule entry in ' + file);
    }
  }
  return [...merged.values()];
}

function slugify(text) {
  const s = String(text || '').toLowerCase().trim().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 48);
  return ID_RE.test(s) ? s : 'rule';
}

// "honest-jev rule add \"<when>\" -> \"<ask>\" [evidence: \"<evidence>\"]" (quoted form) or
// "honest-jev rule add: when <when> ask <ask> [evidence <evidence>]" (natural-language form) ->
// {action:'add', when, ask, evidence, repo} | {action:'list'} | {action:'remove'|'disable', id, repo} | null.
// "repo" anywhere in the command text targets .jev/rules.json instead of the user-global file.
const RULE_CMD = /^[/@$]?(?:[a-z0-9-]+:)?honest-jev\s+rule\s+(.+)$/is;
function parseRuleCommand(prompt) {
  const raw = String(prompt || '').trim();
  const m = raw.match(RULE_CMD);
  if (!m) return null;
  const rest = m[1].trim();
  if (/^list\b/i.test(rest)) return { action: 'list' };
  let mm;
  if ((mm = rest.match(/^remove\s+([a-z0-9-]{2,48})\b/i))) return { action: 'remove', id: mm[1].toLowerCase(), repo: /\brepo\b/i.test(rest) };
  if ((mm = rest.match(/^disable\s+([a-z0-9-]{2,48})\b/i))) return { action: 'disable', id: mm[1].toLowerCase(), repo: /\brepo\b/i.test(rest) };
  if (/^add\b/i.test(rest)) {
    const body = rest.replace(/^add:?\s*/i, '');
    const repo = /\brepo\b/i.test(body);
    let m2 = body.match(/^"([^"]+)"\s*->\s*"([^"]+)"(?:\s*evidence:\s*"([^"]+)")?/i);
    if (m2) return { action: 'add', when: m2[1].trim(), ask: m2[2].trim(), evidence: (m2[3] || '').trim(), repo };
    m2 = body.match(/^when\s+(.+?)\s+ask\s+(.+?)(?:\s+evidence\s+(.+))?$/i);
    if (m2) return { action: 'add', when: m2[1].trim(), ask: m2[2].trim(), evidence: (m2[3] || '').trim(), repo };
    return null;
  }
  return null;
}

function writeRulesFile(file, list) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(list, null, 2) + '\n');
}
function maskRuleEntry(file, id) {
  const list = readRulesFile(file).filter((e) => !(e && e.id === id));
  list.push({ id, disabled: true });
  writeRulesFile(file, list);
}

// Applies a parsed rule command, persisting to the chosen layer file, and returns the one-line confirmation
// (plus the rule as context for 'add', so the model applies it from this reply on).
function applyRuleCommand(cmd) {
  if (cmd.action === 'list') {
    const all = rules();
    if (!all.length) return 'HONEST JEV RULES: none configured.';
    return 'HONEST JEV RULES:\n' + all.map((r) => `- [${r.id}] When ${r.when}: ${r.ask}${r.evidence ? ' — Evidence: ' + r.evidence : ''}`).join('\n');
  }
  const file = cmd.repo ? repoRulesPath() : userRulesPath();
  if (cmd.action === 'remove' || cmd.action === 'disable') {
    maskRuleEntry(file, cmd.id);
    return 'HONEST JEV RULE ' + (cmd.action === 'remove' ? 'REMOVED' : 'DISABLED') + ': ' + cmd.id;
  }
  if (cmd.action === 'add') {
    const id = slugify(cmd.when);
    const list = readRulesFile(file).filter((e) => !(e && e.id === id));
    list.push({ id, when: cmd.when, ask: cmd.ask, evidence: cmd.evidence || '' });
    writeRulesFile(file, list);
    return `HONEST JEV RULE ADDED: [${id}] When ${cmd.when}: ${cmd.ask}${cmd.evidence ? ' — Evidence: ' + cmd.evidence : ''}\n\nApply this rule from this reply on.`;
  }
  return '';
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

function rulesSection() {
  const list = rules();
  if (!list.length) return '';
  const lines = list.map((r) => `- [${r.id}] When ${r.when}: ${r.ask}${r.evidence ? ' — Evidence: ' + r.evidence : ''}`);
  return '\n\n## Rules\n\nBefore you say any of the following, answer the question with evidence in the same message; if you cannot, say so instead of presenting the outcome:\n\n' + lines.join('\n');
}

function instructions(level) {
  const head = 'HONEST JEV ACTIVE — level: ' + level + '\n\n';
  if (level === 'off') return head; // defensive: no caller passes 'off', but never inject rules if one does
  let body;
  for (const p of SKILL_CANDIDATES()) {
    try { body = filterSkillBody(fs.readFileSync(p, 'utf8'), level); break; } catch { /* try next */ }
  }
  if (body === undefined) {
    body = 'Before claiming done, fixed, works, verified or safe: for every claim ask "what would I show to prove this line?" ' +
      'Send only claims backed by output you produced this turn; keep hedges visible; rewrite overclaims to what the evidence shows. ' +
      'Switch: /honest-jev soft|standard|strict|off.';
  }
  return head + body + rulesSection();
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

module.exports = {
  LEVELS, DEFAULT_LEVEL, claudeDir, statePath, normalizeLevel, defaultLevel, readLevel, setLevel, clearLevel,
  parseCommand, filterSkillBody, instructions, emit,
  rules, parseRuleCommand, applyRuleCommand, slugify, defaultRulesPath, userRulesPath, repoRulesPath,
};
