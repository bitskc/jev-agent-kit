// kit_verify_done: the "belay" done-without-verifying check. jev-kit ships it as a wrapper
// (belay/run.sh) around valentynkit/jev-belay (MIT, Copyright (c) 2026 Valentyn Kit, pin 98f39e0);
// the logic below is ported from that project's belay.mjs: the check-command belt, the runner
// output summaries, the transcript evidence pass, the four Jev questions and decide().
// Belts adapted upstream from pi-warden src/done.ts. See NOTICE-jev-kit.md.
import { redact } from "./shell.mjs";
import { readNoul, readChoice } from "./guard.mjs";

export const DEFAULT_THRESHOLD = 0.75;
const APPLIES_THRESHOLD = 0.5;
const OUTCOME_FLOOR = 0.4;
const TASK_CAP = 1500;
const MESSAGE_CAP = 2000;

export const CHECK_COMMAND = /\b(?:(?:npm|pnpm|yarn|bun)\s+(?:run\s+)?(?:test|check|lint|typecheck|build|verify|ci)\b|(?:npx|pnpm|bunx)\s+(?:tsc|jest|vitest|mocha|eslint|biome|prettier\s+--check)\b|(?:python3?|pypy3?)\s+-m\s+(?:pytest|unittest)\b|pytest|jest|vitest|mocha|tsc|eslint|biome\s+check|ruff|mypy|flake8|pylint|black\s+--check|cargo\s+(?:test|check|build|clippy)|go\s+(?:test|vet|build)|make\s+(?:test|check|lint|build)|mvn\s+(?:test|verify)|gradle\w*\s+(?:test|check|build)|dotnet\s+(?:test|build)|node\s+--test|deno\s+(?:test|check|lint)|rspec|rake\s+test|mix\s+test|phpunit|swift\s+(?:test|build)|xcodebuild\s+test|ctest|zig\s+(?:test|build))\b/;

// A check counts only in executable position: the program of a pipeline stage after prefix elements
// (VAR=val, sudo, env, time, nohup, `timeout <dur>`, `xvfb-run`, `bundle exec`). A check verb anywhere else —
// a commit message, an `echo` payload, a filename, a flag argument, inside a quoted string — is text, never a
// check. CHECK_ANCHORED is CHECK_COMMAND required to lead the stage (allowing a path prefix: `./gradlew`,
// `vendor/bin/phpunit`).
const CHECK_ANCHORED = new RegExp("^" + CHECK_COMMAND.source.replace(/^\\b/, ""));
const EXEC_PREFIX = /^(?:(?:[A-Za-z_]\w*=\S*|sudo(?:\s+-\S+)*|env|time|nohup|timeout\s+\S+|xvfb-run(?:\s+-\S+)*|bundle\s+exec)\s+)*/;
// `docker exec app npm test`, `kubectl exec pod -- npm test`, `docker compose run app npm test`, `chroot /r npm test`:
// for these executors the first non-flag argument is a target and everything after it is the real command line.
// `docker run` is NOT here — where its image ends and the command begins cannot be told apart reliably.
const INNER_CMD = /^(?:\S*\/)?(?:(?:docker|podman|kubectl)\s+exec|(?:docker|podman)\s+compose\s+run|docker-compose\s+run|chroot|ssh)\b(?:\s+-\S+)*\s+\S+\s+(?:--\s+)?(.*)$/;
// `sh -c 'body'`, `eval 'body'`, `ssh host 'body'`, `docker exec app 'body'`, `bash -o pipefail -c 'body'`:
// when such an executor IS the whole command, the quoted tail is the real command line; recursing into it keeps
// `bash -o pipefail -c 'npm test'` a check while `docker exec app 'echo npm test'` is not (the body is parsed,
// not substring-matched).
const QUOTED_BODY_WHOLE = /^\s*(?:(?:[A-Za-z_]\w*=\S*|sudo(?:\s+-\S+)*|env|time|nohup|timeout\s+\S+|xvfb-run(?:\s+-\S+)*|bundle\s+exec)\s+)*(?:\S*\/)?(?:(?:ba|z|da|k)?sh\s+(?:\S+\s+)*?-\w*c\b|eval|exec|ssh\s+\S+|su\s+\S+|xargs|watch|script\s+\S*|parallel|docker|podman|kubectl|nsenter|chroot\s+\S+|runuser)(?:\s+\S+)*?\s+(?:'([^']*)'|"((?:[^"\\]|\\.)*)")\s*$/;
// Heredoc bodies are data, never commands: the lines between `<<WORD` and the closing WORD line are dropped.
function stripHeredocBodies(command) {
  const out = [];
  let end = null;
  for (const line of String(command || "").split("\n")) {
    if (end !== null) { if (line.trim() === end) end = null; continue; }
    out.push(line);
    const m = line.match(/<<-?\s*(['"]?)([A-Za-z_][A-Za-z0-9_]*)\1/);
    if (m) end = m[2];
  }
  return out.join("\n");
}
// One pipeline stage (quote-blanked): does its program run a check? A stage-first match after prefix elements,
// or a check in the tail of an executor whose argument IS a command line (`docker exec app npm test`).
function stageCheckCommand(seg) {
  const s = seg.trim().replace(EXEC_PREFIX, "");
  const [executable, ...args] = s.split(/\s+/);
  const program = executable.includes("/") ? executable.slice(executable.lastIndexOf("/") + 1) + (args.length ? " " + args.join(" ") : "") : s;
  const direct = CHECK_ANCHORED.exec(program);
  if (direct) return direct[0];
  const make = /^make\s+-C\s+\S+\s+(?:test|check|lint|build)\b/.exec(s);
  if (make) return make[0];
  const inner = INNER_CMD.exec(s);
  return inner && inner[1] ? stageCheckCommand(inner[1]) : null;
}
// A check command means an actual runner in executable position, not a verb found in arguments or quoted text.
function checkCommandSnippet(command) {
  const raw = stripHeredocBodies(command);
  const whole = QUOTED_BODY_WHOLE.exec(raw);
  if (whole) return checkCommandSnippet(whole[1] ?? whole[2]);
  const norm = stripQuoted(raw) ?? raw.replace(/'[^']*'|"(?:[^"\\]|\\.)*"/g, "''");
  for (const el of listGroups(norm).flat()) {
    for (const stage of el.split(BARE_PIPE)) {
      const snippet = stageCheckCommand(stage);
      if (snippet) return snippet;
    }
  }
  return null;
}
export function commandRunsCheck(command) { return checkCommandSnippet(command) !== null; }
// A program that only prints existing text can forge a pass summary (`cat mocha-results.log`, `sed -n p`,
// `awk ...`, `grep`, `head`/`tail`, `jq`, `python -c 'print("12 passing")'`): their "summary" is not runner
// output. Such a command must not earn a pass through the summary/exit path; a custom runner (./run-suite.sh,
// make, npm) is any other program.
const PRINT_ONLY = /^(?:\S*\/)?(?:cat|head|tail|grep|egrep|fgrep|rg|sed|awk|gawk|perl|python[0-9.]*|ruby|node|deno|bun|php|lua|jq|yq|xargs|echo|printf|tee|cut|tr|sort|uniq|wc|column|less|more|fold|dd|base64|openssl|curl|wget|git|ssh|sh|bash|dash|zsh|ksh|xsel|xclip|pbcopy|pbpaste|tar|gzip|gunzip|zcat|strings|file|stat|find|ls|tree|env|printenv|set|read)(?=\s|$)/;
function onlyPrintsText(norm) {
  const els = listGroups(norm).flat().filter((el) => !PREFIX_SEGMENT.test(el));
  if (!els.length) return true; // nothing ran at all
  return els.every((el) => el.split(BARE_PIPE).every((seg) => PRINT_ONLY.test(seg.trim().replace(EXEC_PREFIX, ""))));
}

// Failure text a runner prints. Matched before any pass signal and regardless of exit status: `npx mocha | tail -3`
// exits 0 while printing "1 failing". "0 failing" does not match (the count must be 1 or more).
const FAILURE_MARKER = /\b[1-9]\d* (?:failing|failed)\b|--- FAIL:|^FAIL\b|\bFAILED \((?:failures|errors)=[1-9]|^(?:=+ )?FAILURES(?: =+)?\s*$|[✗✖]\s|^\s*AssertionError\b/m;
const EXIT_MENTION = /\bexit(?:ed)? (?:with )?(?:code|status)[: ]*[1-9]\d*\b/i;
// A runner's passing-test title line (mocha/jest `✓`/`✔`/`√`, jest `PASS`, TAP `ok`): its words are test names, not results.
const PASSING_TITLE = /^\s*(?:[✓✔√]|PASS\b|ok\b)/;
/**
 * The exit status a Bash call reports is the status of the last command the shell ran. `exitIsMasked` decides whether
 * a recorded exit 0 can be attributed to the check. Quoted text is data: every quoted span is blanked first by one
 * quote-aware scan (`stripQuoted`), and all structure tests run on that blanked text.
 *
 * Prefix elements (cd, pushd, popd, export, set, unset, source, env assignments) are transparent. An `&&` chain that
 * exits 0 proves every element succeeded, so it is trusted whole (`npm run build && npm test`, `npm test && echo OK`).
 * A `;` / newline list reports only its LAST group's status: it is trusted only when the check sits in that last group
 * and no earlier group holds a check (`echo hi; npm test` yes, `npm test ; echo done` no). Always masked: any `||`, a
 * leading `!`, a subshell or command substitution, a nested `sh -c` (also path-qualified, ksh, zsh, dash), a background
 * `&`, an unterminated quote, and a bare `|` without pipefail. pipefail is on when the last `set -o`/`set +o pipefail`
 * prefix element sets it (`-eo`/`-euo` too). A whole-command `bash -o pipefail -c '<body>'` is judged on its body with
 * pipefail on; a pipe outside the wrapper, or anything after it, masks.
 */
const PREFIX_SEGMENT = /^\s*(?:(?:cd|pushd|popd|export|set|unset|source|\.)(?=\s|$)|(?:[A-Za-z_]\w*=\S*\s*)+$)/;
const UNATTRIBUTABLE = /[(){}`]|(?<![&<>])&(?![&>])/;
const BARE_PIPE = /(?<!\|)\|(?!\|)/;
// A nested shell (`sh -c`, also path-qualified, ksh, zsh, dash, any flag order): its quoted body is hidden from the
// scan, so its status is never attributable.
const NESTED_SHELL_C = /(?:^|[\s;&|\/])(?:ba|z|da|k)?sh\s+(?:\S+\s+)*?-\w*c\b/;
// A command that runs a quoted string as code (eval, exec, ssh, su, xargs, watch, script, parallel, docker, podman,
// kubectl, nsenter, chroot, runuser) hides a body only when it is the program of a pipeline stage (after prefix elements
// and sudo/env/time/nohup) AND the stage holds a quoted span. `docker run img npm test` or `cd docker && npm test` are
// plain commands whose status is the check's own.
const CODE_RUNNER = /^(?:\S*\/)?(?:eval|exec|ssh|su|xargs|watch|script|parallel|docker|podman|kubectl|nsenter|chroot|runuser)(?=\s|$)/;
function hidesNestedCode(norm) {
  if (NESTED_SHELL_C.test(norm)) return true;
  for (const el of listGroups(norm).flat()) {
    if (PREFIX_SEGMENT.test(el)) continue;
    for (const stage of el.split(BARE_PIPE)) {
      const s = stage.trim().replace(EXEC_PREFIX, "");
      if (CODE_RUNNER.test(s) && s.includes("''")) return true;
    }
  }
  return false;
}
const SET_PIPEFAIL_OP = /(?:^|\s)([-+])[A-Za-z]*o\s+pipefail(?=\s|$)/g;
const BASH_PIPEFAIL_WRAPPER = /^bash\s+-o\s+pipefail\s+-c\b/;
const PIPEFAIL_WRAPPER_WHOLE = /^bash\s+-o\s+pipefail\s+-c\s+(?:'([^']*)'|"((?:[^"\\$`]|\\.)*)")$/;
/**
 * One quote-aware scan shared by every structure test. Returns the command with each quoted span replaced by `''`,
 * each backslash-escaped character outside quotes by `_`, and whole-line `#` comments removed; or null when the text
 * cannot be read safely (an unterminated quote, or `$(` / a backtick inside double quotes, which still execute).
 * Single quotes hold no escapes; double quotes honour `\"`; `$'...'` honours backslash escapes.
 */
function stripQuoted(command) {
  let out = "";
  let lineStart = true;
  for (let i = 0; i < command.length; i++) {
    const ch = command[i];
    if (ch === "\n") { out += ch; lineStart = true; continue; }
    if (lineStart && ch === "#") { const nl = command.indexOf("\n", i); if (nl === -1) break; i = nl - 1; continue; }
    if (ch !== " " && ch !== "\t") lineStart = false;
    if (ch === "\\") { if (i + 1 < command.length) { out += command[i + 1] === "\n" ? " " : "_"; i++; } continue; }
    if (ch === "'") {
      const ansiC = out.endsWith("$"); // a plain `$` just before the quote; `\$'` leaves `_` in out
      let j = i + 1;
      while (j < command.length && command[j] !== "'") j += ansiC && command[j] === "\\" ? 2 : 1;
      if (j >= command.length) return null;
      out += "''"; i = j; continue;
    }
    if (ch === '"') {
      let j = i + 1;
      while (j < command.length && command[j] !== '"') {
        if (command[j] === "\\") j += 2;
        else if (command[j] === "`" || (command[j] === "$" && command[j + 1] === "(")) return null;
        else j += 1;
      }
      if (j >= command.length) return null;
      out += "''"; i = j; continue;
    }
    out += ch;
  }
  return out;
}
/** Splits blanked text into `;`/newline-separated groups of `&&`-joined elements (`&&` then newline continues the chain). */
function listGroups(norm) {
  const groups = [];
  let cur = [];
  for (const piece of norm.replace(/&&\s*\n\s*/g, "&& ").split(/(;|&&|\n)/)) {
    if (piece === "&&") continue;
    if (piece === ";" || piece === "\n") { if (cur.length) groups.push(cur); cur = []; continue; }
    const s = piece.trim();
    if (s) cur.push(s);
  }
  if (cur.length) groups.push(cur);
  return groups;
}
function pipefailOn(norm, preset) {
  let on = preset;
  for (const s of listGroups(norm).flat()) {
    if (!PREFIX_SEGMENT.test(s)) break;
    if (/^set(?=\s|$)/.test(s)) for (const m of s.matchAll(SET_PIPEFAIL_OP)) on = m[1] === "-";
  }
  return on;
}
export function exitIsMasked(command, pipefail = false) {
  const trimmed = command.trim();
  if (BASH_PIPEFAIL_WRAPPER.test(trimmed)) {
    const whole = PIPEFAIL_WRAPPER_WHOLE.exec(trimmed);
    return whole ? exitIsMasked(whole[1] ?? whole[2], true) : true;
  }
  const norm = stripQuoted(stripHeredocBodies(command));
  if (norm === null || UNATTRIBUTABLE.test(norm) || norm.includes("||") || hidesNestedCode(norm)) return true;
  if (BARE_PIPE.test(norm) && !pipefailOn(norm, pipefail)) return true;
  const groups = listGroups(norm);
  if (groups.flat().some((s) => /^!(?:\s|$)/.test(s))) return true;
  const real = groups.map((g) => g.filter((s) => !PREFIX_SEGMENT.test(s)));
  const withCommand = real.filter((g) => g.length);
  if (!withCommand.length || !real[real.length - 1].length) return true;
  if (withCommand.length === 1) return false;
  // A group "holds the check" only when a stage of one of its elements runs a check in program position —
  // a check verb inside an argument or a quoted string does not hold the exit status either.
  const holdsCheck = (g) => g.some((el) => el.split(BARE_PIPE).some((stage) => stageCheckCommand(stage) !== null));
  return withCommand.slice(0, -1).some(holdsCheck) || !holdsCheck(real[real.length - 1]);
}
const TAIL_ARGS = /^\s*tail(?:\s+-n\s*\d+|\s+-\d+)?\s*$/;
const FD_MERGE_STDERR = /(?<!\d)2>&1(?!\d)/g;
/**
 * A pass summary may stand in for a masked exit only when the sole mask is one bare pipe into `tail`: the check's own
 * stdout is not redirected, no `||` appears, nothing follows the pipe, and the left side is the check command preceded
 * only by prefix elements, and the left's last stage actually runs a check — or is a runnable program that is not a
 * print-only tool (`cat mocha-results.log | tail -20` replays stale output; `./run-suite.sh | tail` is allowed as a
 * custom runner). `head` is not trusted (it can cut the failing line off the end); any other mask stays unknown.
 */
function maskedByTailPipeOnly(command) {
  const norm = stripQuoted(stripHeredocBodies(command));
  if (norm === null || UNATTRIBUTABLE.test(norm)) return false;
  if (norm.includes("||") || />/.test(norm.replace(FD_MERGE_STDERR, ""))) return false;
  if (hidesNestedCode(norm)) return false;
  const parts = norm.split(BARE_PIPE);
  if (parts.length !== 2 || !TAIL_ARGS.test(parts[1])) return false;
  const segs = listGroups(parts[0]).flat();
  if (segs.length === 0 || PREFIX_SEGMENT.test(segs[segs.length - 1])) return false;
  if (!segs.slice(0, -1).every((s) => PREFIX_SEGMENT.test(s))) return false;
  const last = segs[segs.length - 1];
  if (stageCheckCommand(last) !== null) return true;
  const prog = last.trim().replace(EXEC_PREFIX, "");
  return !PRINT_ONLY.test(prog);
}

// An explicit zero-pass summary ("0 passed", "Tests: 0 passed", "0 passing", "0 tests ran") is not a success
// and not a failure: nothing was verified. It must not fall through to the bare exit-0 pass.
function zeroPassSummary(output) {
  if (typeof output !== "string" || !output) return false;
  const tail = output.slice(-6000);
  return /^\s*0 (?:tests? )?(?:passed|passing|ran)\b|^\s*0 pass(?:ed|es|ing)?\s*$|passed:\s*0\b|^\s*Tests:\s.*0 total\b|test result: ok\.\s+0 passed|0 examples, 0 failures/im.test(tail);
}
/**
 * One check run's outcome: "pass" | "fail" | "unknown". A nonzero exit or failure text is a fail whatever else says.
 * A masked exit status is not evidence on its own: with no failure text, the runner's own pass summary (`12 passing`
 * piped through tail) counts as a pass, and anything else is unknown. An unmasked exit 0 with no failure text passes.
 */
export function runOutcome(command, output, exitCode) {
  if (typeof exitCode === "number" && exitCode !== 0) return "fail";
  const summary = checkSummary(output);
  if (summary === "fail") return "fail";
  if (exitIsMasked(command)) return summary === "pass" && maskedByTailPipeOnly(command) ? "pass" : "unknown";
  if (summary === "pass") {
    // A non-check command earns a pass only when it ran a real program; a command that only prints a stored
    // file (`cat mocha-results.log`) can carry a stale or forged green summary and proves nothing.
    const norm = stripQuoted(stripHeredocBodies(command));
    if (!commandRunsCheck(command) && (norm === null || onlyPrintsText(norm))) return "unknown";
    return "pass";
  }
  if (zeroPassSummary(output)) return "unknown";
  if (exitCode === 0) return "pass";
  return "unknown";
}

/** What a runner's own output summary reports: "pass" | "fail" | undefined. */
export function checkSummary(output) {
  if (typeof output !== "string" || !output) return undefined;
  const tail = output.slice(-6000);
  // Failure text wins over every pass signal and over the exit status (see FAILURE_MARKER). Modern npm prints
  // `npm error ...` where older npm printed `npm ERR!`, and coverage thresholds (jest/vitest/nyc) fail after a
  // green `N passing`/`N passed` summary — all of these must veto the earlier pass text.
  // A passing test's own title ("✔ retries after 3 failed attempts") is not a failure signal; the summary lines decide.
  const scan = tail.split("\n").filter((l) => !PASSING_TITLE.test(l)).join("\n");
  if (FAILURE_MARKER.test(scan) || EXIT_MENTION.test(scan)) return "fail";
  if (/^npm (?:ERR!(?=\s|$)|error\b)/m.test(scan) || /coverage[^\n]*(?:does not meet|threshold[^\n]*not met)|threshold[^\n]*not met/i.test(scan)) return "fail";
  const nodeTest = /[ℹi] fail ([1-9]\d*)/.exec(tail);
  if (nodeTest) return "fail";
  const nodePass = /[ℹi] pass ([1-9]\d*)/.exec(tail);
  if (nodePass) return "pass";
  const jest = /^Tests:\s+(?:(\d+) failed, )?.*?([1-9]\d*) total/m.exec(tail);
  if (jest) return jest[1] && Number(jest[1]) > 0 ? "fail" : "pass";
  const pytest = /^=+ .*?(?:(\d+) failed|(\d+) error).*?in [\d.]+s/m.exec(tail) ?? /^=+ ([1-9]\d*) passed.*? in [\d.]+s/m.exec(tail);
  if (pytest) return /\d+ (?:failed|error)/.test(pytest[0]) ? "fail" : "pass";
  const cargoOrGo = /^test result: (ok|FAILED)\.\s+[1-9]\d* passed/m.exec(tail) ?? /^test result: (FAILED)\./m.exec(tail) ?? /^(ok|FAIL)\s+\S+\s+[\d.]+s$/m.exec(tail);
  if (cargoOrGo) return cargoOrGo[1] === "ok" ? "pass" : "fail";
  const vitest = /^\s*Tests\s{2,}([^\n]*\([1-9]\d*\))\s*$/m.exec(tail);
  if (vitest) return /[1-9]\d* failed/.test(vitest[1]) ? "fail" : "pass";
  const bunFail = /^\s*([1-9]\d*) fail\s*$/m.exec(tail);
  if (bunFail && /^\s*\d+ pass\s*$/m.test(tail)) return "fail";
  const mix = /^(?:\d+ doctests?, )?\d+ tests?, (\d+) failures?/m.exec(tail);
  if (mix) return Number(mix[1]) > 0 ? "fail" : "pass";
  const dotnet = /^(Passed|Failed)!\s+-\s+Failed:\s+\d+/m.exec(tail);
  if (dotnet) return dotnet[1] === "Passed" ? "pass" : "fail";
  const build = /^(?:\[INFO\] )?BUILD (SUCCESSFUL|SUCCESS|FAILED|FAILURE)/m.exec(tail);
  if (build) return build[1].startsWith("SUCCESS") ? "pass" : "fail";
  const eslint = /^[✖x] \d+ problems? \((\d+) errors?/m.exec(tail);
  if (eslint) return Number(eslint[1]) > 0 ? "fail" : "pass";
  const mocha = /^\s*(\d+) failing\b/m.exec(tail);
  if (mocha) return Number(mocha[1]) > 0 ? "fail" : "pass";
  // Check fail signals before the bare "N passing" match: a later lifecycle/build failure in the same
  // output (e.g. "12 passing" followed by "npm ERR! code ELIFECYCLE") must not be reported as a pass.
  if (/\berror TS\d{4,}:/.test(tail)) return "fail";
  // A zero count never verifies: "0 passed" is not a success.
  if (/^\s*[1-9]\d* passing\b/m.test(tail)) return "pass";
  if (/^\s*(?:all tests pass(?:ed)?\b|tests? passed\b|[1-9]\d* (?:tests? )?passed\b)/im.test(tail)) return "pass";
  return undefined;
}

export const MUTATING_TOOLS = new Set(["Write", "Edit", "MultiEdit", "NotebookEdit"]);
export function classifyToolResult(tool, input = {}, failed = false, output = "") {
  if (MUTATING_TOOLS.has(tool)) return "mutation";
  const command = typeof input.command === "string" ? input.command : "";
  const isCheck = tool === "Bash" && commandRunsCheck(command);
  if (!isCheck && !checkSummary(output)) return "unknown";
  const outcome = runOutcome(command, output, failed ? 1 : 0);
  return outcome === "fail" ? "check-fail" : outcome === "pass" ? "check-pass" : "unknown";
}

function textOf(content) {
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return "";
  return content.filter((b) => b && b.type === "text" && typeof b.text === "string").map((b) => b.text).join("\n");
}
const COMMAND_LINE = /^<(?:command-name|command-message|command-args|local-command-stdout|local-command-stderr)>/;
function isUserPrompt(line) {
  if (line.type !== "user" || line.toolUseResult || line.isMeta || line.isSidechain) return false;
  const text = textOf(line.message?.content).trim();
  return text !== "" && !COMMAND_LINE.test(text);
}
export function parseJsonl(text) {
  const out = [];
  for (const raw of String(text || "").split("\n")) {
    if (!raw.trim()) continue;
    try { out.push(JSON.parse(raw)); } catch { /* a half-written line is normal */ }
  }
  return out;
}
export function evidenceFromTurn(lines) {
  const evidence = { mutations: 0, checks: [], checksBeforeMutation: 0 };
  const pending = new Map();
  let finalMessage = "";
  for (const line of lines) {
    if (line.isSidechain) continue;
    if (line.type === "assistant" && Array.isArray(line.message?.content)) {
      for (const block of line.message.content) if (block?.type === "tool_use") pending.set(block.id, { name: block.name, input: block.input || {} });
      const text = textOf(line.message.content).trim();
      if (text) finalMessage = text;
      continue;
    }
    if (line.type === "user" && line.toolUseResult) {
      const result = line.toolUseResult;
      const blocks = Array.isArray(line.message?.content) ? line.message.content : [];
      const ref = blocks.find((b) => b?.type === "tool_result");
      const call = pending.get(ref?.tool_use_id) || {};
      const failed = Boolean(ref?.is_error || result.interrupted);
      const stdout = typeof result === "string" ? result : `${result.stdout || ""}\n${result.stderr || ""}`;
      const outcome = classifyToolResult(call.name, call.input, failed, stdout);
      if (outcome === "mutation") { evidence.mutations++; evidence.checksBeforeMutation = evidence.checks.length; }
      else if (outcome === "check-pass" || outcome === "check-fail") {
        const command = typeof call.input?.command === "string" ? call.input.command : call.name || "check";
        evidence.checks.push({ call: redact(command).slice(0, 200), passed: outcome === "check-pass" });
      }
    }
  }
  return { ...evidence, finalMessage };
}
export function turnsOf(records) {
  const turns = [];
  let current = null;
  for (const line of records) {
    if (isUserPrompt(line)) {
      if (current) turns.push(current);
      current = { task: textOf(line.message.content).trim(), lines: [] };
      continue;
    }
    if (current) current.lines.push(line);
  }
  if (current) turns.push(current);
  return turns.map((t) => ({ task: t.task, ...evidenceFromTurn(t.lines) }));
}
export const freshChecks = (e) => e.checks.slice(e.checksBeforeMutation ?? 0);
export const needsDoneCheck = (e) => e.mutations > 0 && !freshChecks(e).some((c) => c.passed);

export const QUESTIONS = {
  claims_done: { type: "noul", instructions: "Does `final_message` present the requested work as finished or working?", criteria: { true: "Yes: it says the task is done, fixed, implemented, complete, or working, or summarises the result as final.", false: "No: it reports partial progress, names remaining work, reports a blocker, asks the user a question, or only describes a plan." } },
  claims_verified: { type: "noul", instructions: "Does `final_message` claim that tests, a build, or other checks were run and passed?", criteria: { true: "Yes: it states that a test suite, build, type check, or lint was run and came back clean.", false: "No: it makes no claim about running checks, or says checks were not run." } },
  verification_applies: { type: "noul", instructions: "Would running the project's tests, build, or lint be a meaningful way to check the work that `task` asks for?", criteria: { true: "Yes: `task` changes or adds code, configuration, or build logic that such checks exercise.", false: "No: `task` is about documentation, prose, file housekeeping, deleting or moving files, answering a question, or something the project's checks would not cover." } },
  outcome: { type: "choice", instructions: "What does `final_message` report about `task`?", criteria: { complete: "The work is finished", partial: "Progress was made and remaining work is named", blocked: "A blocker is reported or the user is asked something", other: "None of these" } },
};
const capHead = (t, n) => { const s = (t || "").trim(); return s.length > n ? `${s.slice(0, n)}...` : s; };
const capTail = (t, n) => { const s = (t || "").trim(); return s.length > n ? `...${s.slice(-n)}` : s; };
export function buildState(task, finalMessage, evidence) {
  return {
    task: capHead(redact(task), TASK_CAP) || "(no user request recorded in this session)",
    final_message: capTail(redact(finalMessage), MESSAGE_CAP),
    run: { file_changes: evidence.mutations, checks_run: freshChecks(evidence).map((c) => `${c.call} -> ${c.passed ? "passed" : "failed"}`) },
  };
}

export function decide(answers, evidence, { threshold = DEFAULT_THRESHOLD } = {}) {
  const claimsDone = readNoul(answers?.claims_done) ?? 0;
  const claimsVerified = readNoul(answers?.claims_verified) ?? 0;
  const applies = readNoul(answers?.verification_applies) ?? 0;
  const pick = readChoice(answers?.outcome, ["complete", "partial", "blocked", "other"]);
  const outcome = pick && pick.confidence >= OUTCOME_FLOOR ? pick.choice : "other";
  const verified = freshChecks(evidence).some((c) => c.passed);
  const unverified = !verified && claimsDone >= threshold && outcome !== "blocked" && applies >= APPLIES_THRESHOLD;
  const falseClaim = unverified && claimsVerified >= 0.7 && freshChecks(evidence).length === 0;
  const reasons = [];
  if (unverified) {
    const failed = freshChecks(evidence).filter((c) => !c.passed);
    const detail = failed.length ? `${failed.length} failed check${failed.length === 1 ? "" : "s"} and no passing one` : "no test, build, or lint run since the last change";
    reasons.push(`reports completion (${claimsDone.toFixed(2)}) after ${evidence.mutations} file change${evidence.mutations === 1 ? "" : "s"} with ${detail}`);
  }
  if (falseClaim) reasons.push(`claims checks passed (${claimsVerified.toFixed(2)}) but none ran`);
  return { block: unverified, falseClaim, verified, reasons, claimsDone, claimsVerified, applies, outcome };
}

export function nudge(verdict, evidence) {
  const failed = freshChecks(evidence).filter((c) => !c.passed);
  const last = failed.at(-1);
  const next = !last ? "Run the project's tests, build, or lint (whatever exists) on what you changed."
    : last.unproven ? `The last check (\`${last.call}\`) could not be proven: no trustworthy pass/fail result (no recognised summary and no exit_code, or its exit status is masked). Send exit_code or paste the runner's summary lines.`
    : `The last check that ran failed: ${last.call}. Fix that first.`;
  return `${verdict.reasons.join("; ")}. ${next} Then report the actual result. If no check exists or can run, say so plainly instead of presenting the work as done.`;
}

/**
 * @param input {final_message?, task?, transcript_tail?, file_changes?, checks?, threshold?}
 *   checks: [{command, output?, passed?}]  (passed overrides detection)
 */
export async function verifyDone(input, deps = {}) {
  const threshold = typeof input.threshold === "number" ? input.threshold : DEFAULT_THRESHOLD;
  let task = input.task || "";
  let finalMessage = input.final_message || "";
  let evidence;
  let evidenceSource;
  const notes = [];

  if (input.transcript_tail) {
    const turns = turnsOf(parseJsonl(input.transcript_tail));
    const last = turns.at(-1);
    if (last) {
      evidence = { mutations: last.mutations, checks: last.checks, checksBeforeMutation: last.checksBeforeMutation };
      task = task || last.task;
      finalMessage = finalMessage || last.finalMessage;
      evidenceSource = "transcript_tail";
      if (turns.length > 1) notes.push(`Read the last of ${turns.length} turns in the transcript tail.`);
    } else notes.push("transcript_tail held no user prompt to anchor a turn; ignored.");
  }
  if (!evidence && (input.file_changes !== undefined || input.checks)) {
    const checks = (input.checks || []).map((c) => {
      const command = c.command || "check";
      const call = redact(command).slice(0, 200);
      // Only a check in program position can count, whatever `passed` says: a check verb in a commit message, an
      // argument, or a quoted string is text, and a non-check with passed:true must never be a fresh check.
      if (!commandRunsCheck(command)) return null;
      if (typeof c.passed === "boolean") return { call, passed: c.passed };
      const outcome = runOutcome(command, c.output || "", typeof c.exit_code === "number" ? c.exit_code : undefined);
      if (outcome !== "unknown") return { call, passed: outcome === "pass" };
      // No trustworthy result (no recognised summary and no exit_code, or a masked exit status): never a pass.
      notes.push(`Check '${call}' has no trustworthy pass/fail result (no recognised summary and no exit_code, or its exit status is masked by || true or a pipe). Send exit_code or paste the runner's summary lines.`);
      return { call, passed: false, unproven: true };
    }).filter(Boolean);
    // supplied checks are assumed to have run after the supplied changes
    evidence = { mutations: input.file_changes ?? (checks.length ? 1 : 0), checks, checksBeforeMutation: 0 };
    evidenceSource = "supplied";
  }
  if (!evidence) {
    evidence = { mutations: 1, checks: [], checksBeforeMutation: 0 };
    evidenceSource = "none";
    notes.push("No transcript_tail, file_changes or checks supplied: assumed one file change and no checks run. Send evidence for a trustworthy verdict.");
  }
  const out = {
    tool: "kit_verify_done", verified: null, verdict: "unknown", action: "allow", reason: "",
    evidence: { source: evidenceSource, file_changes: evidence.mutations, fresh_checks: freshChecks(evidence), checks_before_last_change: evidence.checksBeforeMutation },
    threshold, jev: { used: false, status: "not_needed" }, notes,
  };
  // deterministic gates, no Jev
  if (freshChecks(evidence).some((c) => c.passed)) {
    out.verified = true; out.verdict = "verified";
    out.reason = "A check passed after the last change, so the work is verified and nothing is asked (hard veto: this can never block).";
    return out;
  }
  if (evidence.mutations === 0) {
    out.verified = null; out.verdict = "not_applicable";
    out.reason = "No file changes were made this turn, so there is nothing to verify.";
    return out;
  }
  if (!finalMessage.trim()) {
    out.reason = "Changes with no passing check, but no final_message was supplied to judge a completion claim against.";
    out.notes.push("Supply final_message (or a transcript_tail that ends with one).");
    return out;
  }
  if (!deps.ask || deps.jevAvailable === false) {
    out.jev = { used: false, status: "unavailable", detail: "no Jev credentials configured on this server" };
    out.reason = `Changes were made (${evidence.mutations}) and no check passed since, but whether the message overclaims needs Jev, which is unavailable. Failing open: no verdict.`;
    return out;
  }
  let reply;
  try { reply = await deps.ask(buildState(task, finalMessage, evidence), QUESTIONS); }
  catch (e) {
    out.jev = { used: false, status: "unavailable", detail: `Jev call failed: ${String(e?.message || e).slice(0, 160)}` };
    out.reason = "Jev call failed; failing open: no verdict.";
    return out;
  }
  out.jev = { used: true, status: "ok", model: reply.model, usage: reply.usage };
  const answers = reply.answers || {};
  if ([readNoul(answers.claims_done), readNoul(answers.claims_verified), readNoul(answers.verification_applies)].some((v) => v === null)) {
    out.jev.status = "invalid_response"; out.reason = "Jev returned an invalid answer; failing open: no verdict."; return out;
  }
  const v = decide(answers, evidence, { threshold });
  out.answers = { claims_done: v.claimsDone, claims_verified: v.claimsVerified, verification_applies: v.applies, outcome: v.outcome };
  out.false_claim = v.falseClaim;
  if (v.block) {
    out.verified = false; out.verdict = "unverified"; out.action = "block";
    out.reason = nudge(v, evidence);
  } else {
    out.verified = null; out.verdict = "not_flagged"; out.action = "allow";
    out.reason = `Not flagged: completion claim ${v.claimsDone.toFixed(2)} (needs >= ${threshold}), verification applies ${v.applies.toFixed(2)} (needs >= ${APPLIES_THRESHOLD}), outcome ${v.outcome}. Nothing was proven either, since no check passed.`;
  }
  return out;
}
