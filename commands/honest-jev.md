---
description: Switch Honest Jev level (soft | standard | strict | off). Registered as /jev-agent-kit:honest-jev (Claude Code namespaces every plugin command); typing plain "honest-jev <level>" with no slash works from any session too.
argument-hint: "[soft|standard|strict|off]"
---
Switch Honest Jev to level `$ARGUMENTS` (no argument = standard). The plugin's UserPromptSubmit hook has already written the level flag and injected the rules for this level; confirm the switch in one line ("Honest Jev → <level>") and apply the claims-vs-evidence check from this reply on. If the level is `off`, confirm that it is off.
