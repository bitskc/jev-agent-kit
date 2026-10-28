#!/usr/bin/env node
// Honest Jev — Claude Code SessionStart hook (startup|resume|clear|compact).
// 1. Resolves the level (flag file written earlier in this install > configured default > off).
// 2. Writes the flag so the statusline badge and SubagentStart see it.
// 3. Emits the level-filtered skill body as session context.
// 4. If settings.json has no statusLine mentioning jev-honest, nudges the agent to offer wiring it — composed
//    with any existing statusLine command (ponytail etc.), never replacing it.
const fs = require('fs');
const path = require('path');
const rt = require('./jev-honest-runtime');

const level = rt.readLevel() || rt.defaultLevel();
if (level === 'off') { rt.clearLevel(); process.exit(0); }

try { rt.setLevel(level); } catch { /* flag is best-effort */ }

let out = rt.instructions(level);

try {
  const settingsPath = path.join(rt.claudeDir(), 'settings.json');
  let current = null;
  if (fs.existsSync(settingsPath)) {
    const s = JSON.parse(fs.readFileSync(settingsPath, 'utf8').replace(/^\uFEFF/, ''));
    current = s.statusLine && s.statusLine.command ? String(s.statusLine.command) : null;
  }
  if (!current || !current.includes('jev-honest-statusline')) {
    const script = path.join(__dirname, '..', 'jev-honest-statusline.sh');
    if (/^[A-Za-z0-9 _.\-:/~]+$/.test(script)) {
      const composed = current ? `${current}; bash "${script}"` : `bash "${script}"`;
      out += '\n\nSTATUSLINE SETUP NEEDED: Honest Jev shows its level as a badge ([HONEST], [HONEST:STRICT]) under the input box. ' +
        'It is not wired yet. Offer once to set "statusLine" in ' + settingsPath + ' to ' +
        JSON.stringify({ type: 'command', command: composed }) +
        (current ? ' — this keeps the existing statusline command and appends the badge.' : '.') +
        ' Only do it with the user\'s yes.';
    }
  }
} catch { /* settings unreadable: skip the nudge */ }

rt.emit('SessionStart', out);
