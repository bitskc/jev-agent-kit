#!/usr/bin/env node
// Honest Jev — Claude Code UserPromptSubmit hook. Watches for "/honest-jev <level>" (also "honest-jev strict",
// "stop honest-jev", "normal mode"), writes the flag, and tells the model the level changed. Any other prompt: no-op.
const rt = require('./jev-honest-runtime');

let input = '';
process.stdin.on('data', (c) => { input += c; });
process.stdin.on('end', () => {
  try {
    const data = JSON.parse(input.replace(/^\uFEFF/, ''));
    const level = rt.parseCommand(data.prompt);
    if (level === null) return;
    if (level === 'off') {
      rt.clearLevel();
      rt.emit('UserPromptSubmit', 'HONEST JEV OFF — the claims-vs-evidence check is no longer required. Confirm in one line.');
      return;
    }
    rt.setLevel(level);
    rt.emit('UserPromptSubmit', 'HONEST JEV LEVEL CHANGED — level: ' + level + '. Confirm in one line ("Honest Jev → ' + level + '") and apply it from this reply on.\n\n' + rt.instructions(level));
  } catch { /* malformed stdin: silent */ }
});
