#!/usr/bin/env node
// Honest Jev — Claude Code SubagentStart hook. SessionStart context never reaches Task-spawned subagents, so
// without this every subagent reports "done" unchecked. Inject the same level-filtered rules when active.
const rt = require('./jev-honest-runtime');

const level = rt.readLevel();
if (!level || level === 'off') process.exit(0);
try { rt.emit('SubagentStart', rt.instructions(level)); } catch { /* stdout error must not fail the hook */ }
