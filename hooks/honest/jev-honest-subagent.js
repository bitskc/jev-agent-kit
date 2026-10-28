#!/usr/bin/env node
// Honest Jev — Claude Code SubagentStart hook. SessionStart context never reaches Task-spawned subagents, so
// without this every subagent reports "done" unchecked. Inject the same level-filtered rules when active.
// Resolves the same explicit-flag-then-default fallback as activate.js: activate.js only persists an explicit
// flag, never a default-resolved one, so a config-only level (no /honest-jev ever run) still needs resolving here.
const rt = require('./jev-honest-runtime');

const level = rt.readLevel() || rt.defaultLevel();
if (level === 'off') process.exit(0);
try { rt.emit('SubagentStart', rt.instructions(level)); } catch { /* stdout error must not fail the hook */ }
