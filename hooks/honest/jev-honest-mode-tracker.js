#!/usr/bin/env node
// Honest Jev — Claude Code UserPromptSubmit hook. Watches for "/honest-jev <level>" (also "honest-jev strict",
// "stop honest-jev", "normal mode"), "honest-jev rule add|list|remove|disable ...", writes the flag or rules
// file, and tells the model what changed. Any other prompt: no-op.
const rt = require('./jev-honest-runtime');

let input = '';
process.stdin.on('data', (c) => { input += c; });
process.stdin.on('end', () => {
  try {
    const data = JSON.parse(input.replace(/^\uFEFF/, ''));
    const ruleCmd = rt.parseRuleCommand(data.prompt);
    if (ruleCmd) { rt.emit('UserPromptSubmit', rt.applyRuleCommand(ruleCmd)); return; }
    const level = rt.parseCommand(data.prompt);
    if (level === null) return;
    if (level === 'off') {
      rt.setLevel('off'); // explicit off, never cleared: an absent flag would fall through to the configured
      // default (JEV_HONEST_DEFAULT_LEVEL / config.json honestLevel) and silently re-arm on the next session
      rt.emit('UserPromptSubmit', 'HONEST JEV OFF — the claims-vs-evidence check is no longer required. Confirm in one line.');
      return;
    }
    rt.setLevel(level);
    rt.emit('UserPromptSubmit', 'HONEST JEV LEVEL CHANGED — level: ' + level + '. Confirm in one line ("Honest Jev → ' + level + '") and apply it from this reply on.\n\n' + rt.instructions(level));
  } catch { /* malformed stdin: silent */ }
});
