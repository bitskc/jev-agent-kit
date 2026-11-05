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
// What Claude Code answers a Bash call started with run_in_background: the command has not finished, so the reply
// carries no result and exit status 0 proves nothing.
const BACKGROUND_RESULT = /^\s*Command running in background\b/i;

// Analysis never reads past this many characters of one command: a longer command is classified (check or not) from its
// first and last half-caps (`boundedCommand`) and can never earn a pass, because whatever follows the cut could mask the
// status. 2000 is also the wire cap.
export const ANALYSIS_CAP = 2000;
// The text analysis runs on: the command itself, or for an over-cap one its first ANALYSIS_CAP/2 characters, a newline,
// and its last ANALYSIS_CAP/2 (cut forward to a token boundary). A check at either end stays visible; a detection made
// from the splice is harmless because an over-cap command is never a pass.
function boundedCommand(command) {
  const s = String(command ?? "");
  if (s.length <= ANALYSIS_CAP) return s;
  const half = ANALYSIS_CAP / 2;
  const tail = s.slice(s.length - half);
  const ws = tail.search(/\s/);
  return s.slice(0, half) + "\n" + (ws === -1 ? tail : tail.slice(ws));
}
// Option words an npm-family runner takes before its script: bare flags (`-s`, `-r`, `--silent`) and value flags
// (`-w x`, `--prefix x`, `--filter x`, `-C dir`). A bare flag is never one of the value flags followed by a space, so
// every token has exactly one parse (no regex backtracking blow-up on a long run of dashes).
const NPM_OPT = String.raw`(?:\s+(?:(?:-w|-C|-F|--prefix|--workspace|--filter|--dir|--cwd)\s+\S+|-{1,2}(?!(?:w|C|F|prefix|workspace|filter|dir|cwd)(?:\s|$))[A-Za-z][\w-]*(?:=\S+)?))*`;
// Script verbs. Only `test` takes a `:suffix`, and only from a short list of conventional test-suite names
// (`npm run test:unit`, `test:e2e`, `test:integration`, `test:coverage`, ...): `test:watch`, `test:db:reset`,
// `test:update-snapshots`, `test:install-browsers` and `test-seed-db` do not run the suite once and report. `lint:fix`,
// `build:docs` and `format` are not checks either. `ci` counts only as a script (`npm run ci`); `npm ci` is an install.
const SCRIPT_VERB = String.raw`(?:test(?::(?:unit|e2e|integration|int|ci|coverage|all|ui|api|server|client))?|check|lint|typecheck|build|verify)`;
const RUNNER_OPT = String.raw`(?:\s+(?:(?:-p|--package)(?:=|\s+)\S+|--?(?!(?:p|package)(?:\s|$))[A-Za-z][\w-]*|--))*`;
const MAKE_OPT = String.raw`(?:\s+(?:(?:-C|-f|-I|--directory|--file)(?:\s+|=)\S+|-j\s*\d+|-(?!(?:C|f|I)(?:\s|$))[A-Za-z]+|--(?!(?:directory|file)(?:\s|$))[a-z][\w-]*(?:=\S+)?|[A-Za-z_]\w*=\S*))*`;
const PM_CHECK = String.raw`(?:npm|pnpm|yarn|bun)${NPM_OPT}\s+(?:(?:run(?:-script)?${NPM_OPT}\s+)?${SCRIPT_VERB}|run(?:-script)?${NPM_OPT}\s+ci)`;
const PKG_RUNNER_CHECK = String.raw`(?:npx|bunx|pnpm(?:\s+(?:exec|dlx))?|yarn(?:\s+dlx)?|npm\s+(?:exec|x)|bun\s+x)${RUNNER_OPT}\s+(?:tsc|jest|vitest|mocha|eslint|biome|prettier\s+--check)`;
const OTHER_CHECK = String.raw`(?:python3?|pypy3?)\s+-m\s+(?:pytest|unittest)|pytest|jest|vitest|mocha|tsc|eslint|biome\s+check|ruff(?!\s+(?:version|format|rule|config|linter|clean|server|help|generate-shell-completion)(?:\s|$))|mypy|flake8|pylint|black\s+--check|cargo\s+(?:test|check|build|clippy)|go\s+(?:test|vet|build)|make${MAKE_OPT}\s+(?:test|check|lint|build)|mvn\s+(?:test|verify)|gradle\w*\s+(?:test|check|build)|dotnet\s+(?:test|build)|node\s+--test|deno\s+(?:test|check|lint)|rspec|rake\s+test|mix\s+test|phpunit|swift\s+(?:test|build)|xcodebuild\s+test|ctest|zig\s+(?:test|build)`;
// The verb must END at whitespace, end of text or a shell operator: `tsc-alias`, `lint:fix`, `test-seed-db` are not checks.
export const CHECK_COMMAND = new RegExp(String.raw`\b(?:${PM_CHECK}|${PKG_RUNNER_CHECK}|${OTHER_CHECK})(?=\s|$|[&<>)])`);

// A check counts only in executable position: the program of a pipeline stage after prefix elements
// (VAR=val, sudo [-u user], env [-i], time, nohup, nice -n N, stdbuf -oL, `timeout [opts] <dur>`, xvfb-run, `bundle exec`,
// `command`, `uv|poetry|pipenv|pdm run`, and a leading `exec`). A check verb anywhere else — a commit message, an `echo`
// payload, a filename, a flag argument, inside a quoted string — is text, never a check. CHECK_ANCHORED is CHECK_COMMAND
// required to lead the stage (allowing a path prefix: `./gradlew`, `vendor/bin/phpunit`). A check carrying a flag that
// stops it from running tests (`--help`, `--version`, `--collect-only`, `--listTests`, `--dry-run`) is not a check.
const CHECK_ANCHORED = new RegExp("^" + CHECK_COMMAND.source.replace(/^\\b/, ""));
// Every alternative has one parse per token (value flags are excluded from the bare-flag branch), so a long run of
// dashes cannot make the prefix regex backtrack exponentially.
const PREFIX_ELEMENTS = [
  String.raw`[A-Za-z_]\w*=\S*`,
  String.raw`sudo(?:\s+(?:-[ugCDRTUrtp]\s+\S+|--|-(?![lvkKVhe-]|[ugCDRTUrtp](?:\s|$))[A-Za-z]\S*|--[a-z][\w-]*=\S*))*`,
  String.raw`env(?:\s+(?:-[uCS]\s+\S+|--|-(?![uCS](?:\s|$))[A-Za-z]\S*))*`,
  String.raw`time(?:\s+-\S+)*`,
  "nohup",
  String.raw`nice(?:\s+(?:-n\s*-?\d+|-\d+|--adjustment=-?\d+))*`,
  String.raw`stdbuf(?:\s+-[ioe]\s*\S+)+`,
  String.raw`timeout(?:\s+(?:(?:-k|-s|--kill-after|--signal)(?:=|\s+)\S+|--?(?!(?:k|s|kill-after|signal)(?:\s|$))[A-Za-z][\w-]*(?:=\S+)?))*\s+\S+`,
  String.raw`xvfb-run(?:\s+-\S+)*`,
  String.raw`bundle\s+exec`,
  String.raw`command(?:\s+-p)?`,
  String.raw`(?:uv|poetry|pipenv|pdm)\s+run(?:\s+-\S+)*`,
].join("|");
const EXEC_PREFIX = new RegExp(String.raw`^(?:(?:${PREFIX_ELEMENTS})\s+)*`);
// `exec <program>` replaces the shell with the program: its status IS the program's, so `exec npm test` is the check.
const EXEC_BUILTIN = /^exec(?:\s+-\S+)*\s+(?=\S)/;
// Flags that make a runner print something other than a suite run: help/version, listing, dry runs, config dumps, creating
// a config, compiling without running (`cargo test --no-run`), and `--if-present` (npm skips a missing script).
const NON_RUN_FLAG = /(?:^|\s)(?:--help|-h|--version|-V|--collect-only|--co|--listTests|--dry-run|--if-present|--showConfig|--init|--print-config|--no-run|--fixtures|--markers|--list|-list)(?=\s|$|=)/;
// make's own non-running modes: -n/--just-print/--dry-run/--recon, -t/--touch, -q/--question, -p/--print-data-base, alone or
// bundled (`-nB`, `-kn`). Letters after an option that takes a value (`-fMakefile`, `-C dir`, `-j4`) are that value.
const MAKE_NON_RUN_LONG = /(?:^|\s)--(?:just-print|dry-run|recon|touch|question|print-data-base)(?=\s|$|=)/;
function makeShortNonRun(s) {
  for (const m of s.matchAll(/(?:^|\s)-([A-Za-z]+)(?=\s|$)/g)) {
    for (const ch of m[1]) {
      if ("CfIoWlOj".includes(ch)) break;
      if ("ntqp".includes(ch)) return true;
    }
  }
  return false;
}
function isNonRun(s) {
  const t = /^(?:\S*\/)?ctest(?=\s)/.test(s) ? s.replace(/(?:^|\s)-V(?=\s|$)/g, " ") : s; // `ctest -V` is verbose, not version
  if (NON_RUN_FLAG.test(t)) return true;
  if (/(?:^|[\s/])(?:tsc|eslint)(?=\s)/.test(s) && /(?:^|\s)-v(?=\s|$)/.test(s)) return true; // tsc -v / eslint -v print the version
  return /^(?:\S*\/)?make(?=\s)/.test(s) && (MAKE_NON_RUN_LONG.test(s) || makeShortNonRun(s));
}
// `docker exec app npm test`, `kubectl exec pod -- npm test`, `docker compose run app npm test`, `chroot /r npm test`:
// for these executors the first non-flag argument is a target and everything after it is the real command line.
// `docker run` is NOT here — where its image ends and the command begins cannot be told apart reliably.
const INNER_CMD = /^(?:\S*\/)?(?:(?:docker|podman|kubectl)\s+exec|(?:docker|podman)\s+compose\s+run|docker-compose\s+run|chroot|ssh)\b(?:\s+-\S+)*\s+\S+\s+(?:--\s+)?(.*)$/;
// `sh -c 'body'`, `eval 'body'`, `ssh host 'body'`, `docker exec app 'body'`, `bash -o pipefail -c 'body'`:
// when such an executor IS the whole command, the quoted tail is the real command line; recursing into it keeps
// `bash -o pipefail -c 'npm test'` a check while `docker exec app 'echo npm test'` is not (the body is parsed,
// not substring-matched).
const QUOTED_BODY_WHOLE = new RegExp(String.raw`^\s*(?:(?:${PREFIX_ELEMENTS})\s+)*(?:\S*\/)?(?:(?:ba|z|da|k)?sh\s+(?:\S+\s+)*?-\w*c\b|eval|exec|ssh\s+\S+|su\s+\S+|xargs|watch|script\s+\S*|parallel|docker|podman|kubectl|nsenter|chroot\s+\S+|runuser)(?:\s+\S+)*?\s+(?:'([^']*)'|"((?:[^"\\]|\\.)*)")\s*$`);
// One pipeline stage (quote-blanked): does its program run a check? A stage-first match after prefix elements,
// or a check in the tail of an executor whose argument IS a command line (`docker exec app npm test`).
function stageCheckCommand(seg) {
  let s = seg.trim();
  for (let k = 0; k < 2; k++) s = s.replace(EXEC_PREFIX, "").replace(EXEC_BUILTIN, "");
  const [executable, ...args] = s.split(/\s+/);
  const program = executable.includes("/") ? executable.slice(executable.lastIndexOf("/") + 1) + (args.length ? " " + args.join(" ") : "") : s;
  const direct = CHECK_ANCHORED.exec(program);
  if (direct) return isNonRun(s) ? null : direct[0];
  const inner = INNER_CMD.exec(s);
  return inner && inner[1] ? stageCheckCommand(inner[1]) : null;
}
// A check command means an actual runner in executable position, not a verb found in arguments or quoted text. A
// command whose heredoc has no exact closing line is not read at all (bash would run it differently from how it
// reads): never a check.
function checkCommandSnippet(command) {
  const sc = scanShell(boundedCommand(command));
  if (!sc.ok) return null;
  const whole = QUOTED_BODY_WHOLE.exec(sc.raw);
  if (whole) return checkCommandSnippet(whole[1] ?? whole[2]);
  const sub = loneSubshellBody(sc);
  if (sub !== null) return checkCommandSnippet(sub);
  const norm = sc.norm ?? sc.raw.replace(/'[^']*'|"(?:[^"\\]|\\.)*"/g, "''");
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
 * quote-, comment- and heredoc-aware scan (`scanShell`), and all structure tests run on that blanked text.
 *
 * Prefix elements (cd, pushd, popd, export, set, unset, source, env assignments) are transparent. An `&&` chain that
 * exits 0 proves every element succeeded, so it is trusted whole (`npm run build && npm test`, `npm test && echo OK`).
 * A `;` / newline list reports only its LAST group's status: it is trusted only when the check sits in that last group
 * and no earlier group holds a check (`echo hi; npm test` yes, `npm test ; echo done` no). Always masked: any `||`, a
 * leading `!`, a command substitution or an inner subshell, a nested `sh -c` (also path-qualified, ksh, zsh, dash) unless
 * it is the whole command (`sh -c 'npm test'` is judged on its body), a background `&`, an unterminated quote, an
 * unclosed heredoc, a terminator or compound keyword in program position (`exit 0; npm test`), and a bare `|` without
 * pipefail. A whole-command `(cd dir && check)` subshell is judged on its body. pipefail is on when the last
 * `set -o`/`set +o pipefail` prefix element sets it (`-eo`/`-euo` too). A whole-command `bash -o pipefail -c '<body>'` is
 * judged on its body with pipefail on; a pipe outside the wrapper, or anything after it, masks. A command longer than
 * ANALYSIS_CAP is always masked.
 */
const PREFIX_SEGMENT = /^\s*(?:(?:cd|pushd|popd|export|set|unset|source|\.)(?=\s|$)|(?:[A-Za-z_]\w*=\S*\s*)+$)/;
// A program in a position that decides the shell's exit status without being the check: a terminator (`exit 0; npm test`,
// `trap 'exit 0' EXIT; mypy .`, `exec true; pytest`, `return 0`, `kill $$`, `builtin exit`, `logout`) or a compound-command
// keyword (`if x; then exit 0; fi; npm test`). `exec npm test` is the check itself. A program name written with quotes,
// an escape or a bare variable (`\exit 0`, `"exit" 0`, `$cmd 0`) is resolved by bash before lookup, so it is never trusted.
const ESC = "\u0001";
const MASKING_WORD = /^(?:exit|return|exec|trap|kill|builtin|logout|if|then|else|elif|fi|while|until|do|done|for|case|esac|select|coproc|function)(?=\s|$)/;
function masksStatus(stage) {
  const s = stage.trim().replace(EXEC_PREFIX, "");
  const word = s.split(/\s+/, 1)[0];
  if (word.includes("''") || word.includes(ESC) || /^\$\{?\w+\}?$/.test(word)) return true;
  return /^exec(?=\s|$)/.test(s) ? stageCheckCommand(s) === null : MASKING_WORD.test(s);
}
const SHELL_C_WHOLE = /^(?:ba|z|da|k)?sh(?:\s+-[A-Za-np-z]+)*\s+-[A-Za-np-z]*c\s+(?:'([^']*)'|"((?:[^"\\$`]|\\.)*)")$/;
// `(cd server && npm test)`: a whole-command subshell is its last command's status. Only the `cd dir && ...` idiom is
// trusted for the exit status (a bare `(npm test)` stays masked, as asserted by the existing tests).
const CD_THEN = /^\s*(?:cd|pushd)\s[^;&|]*&&/;
function loneSubshellBody(sc) {
  if (sc.norm === null || !/^\s*\([^()]*\)\s*$/.test(sc.norm)) return null;
  const r = sc.raw.trim();
  return r.startsWith("(") && r.endsWith(")") ? r.slice(1, -1) : null;
}
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
 * One quote-, comment- and heredoc-aware scan shared by every structure test. Returns
 *   raw:  the command with comments and heredoc bodies removed, quotes intact;
 *   norm: the same with each quoted span replaced by `''`, each backslash-escaped character outside quotes by ESC, and
 *         heredoc delimiters by `_`; null when the text cannot be read safely (an unterminated quote, or `$(` / a
 *         backtick inside double quotes, which still execute);
 *   ok:   false when a heredoc opener has no exact closing line (bash needs the delimiter alone on its line; `<<-`
 *         also allows leading tabs only) — the command is then not read at all (fail closed).
 * Single quotes hold no escapes; double quotes honour `\"`; `$'...'` honours backslash escapes. A `#` starts a comment
 * only at the start of a word (after whitespace or `; & | ( ) < >`); `<<WORD` opens a heredoc only outside quotes
 * and comments.
 */
function readHeredocOpener(s, at) {
  let j = at + 2;
  let strip = false;
  if (s[j] === "-") { strip = true; j++; }
  while (s[j] === " " || s[j] === "\t") j++;
  const start = j;
  let delim = "";
  while (j < s.length && !/[\s;&|()<>]/.test(s[j])) {
    const c = s[j];
    if (c === "'") { const e = s.indexOf("'", j + 1); if (e === -1) return null; delim += s.slice(j + 1, e); j = e + 1; }
    else if (c === '"') {
      let e = j + 1;
      while (e < s.length && s[e] !== '"') { if (s[e] === "\\" && e + 1 < s.length) e++; delim += s[e]; e++; }
      if (e >= s.length) return null;
      j = e + 1;
    }
    else if (c === "\\") { if (j + 1 >= s.length) return null; delim += s[j + 1]; j += 2; }
    else { delim += c; j++; }
  }
  return j > start ? { end: j, delim, strip } : null;
}
function scanShell(command) {
  const s = String(command ?? "");
  const n = s.length;
  let raw = "";
  let norm = "";
  let normOk = true;
  let wordStart = true;
  let ok = true;
  const pending = [];
  let i = 0;
  while (i < n) {
    const ch = s[i];
    if (ch === "\n") {
      raw += ch; norm += ch; wordStart = true; i++;
      for (const h of pending) {
        let found = false;
        while (i < n && !found) {
          const nl = s.indexOf("\n", i);
          const line = nl === -1 ? s.slice(i) : s.slice(i, nl);
          i = nl === -1 ? n : nl + 1;
          found = (h.strip ? line.replace(/^\t+/, "") : line) === h.delim;
        }
        if (!found) ok = false;
      }
      pending.length = 0;
      continue;
    }
    if (ch === "#" && wordStart) { const nl = s.indexOf("\n", i); i = nl === -1 ? n : nl; continue; }
    if (ch === "\\") {
      if (i + 1 < n) {
        raw += ch + s[i + 1];
        norm += s[i + 1] === "\n" ? " " : ESC;
        if (s[i + 1] !== "\n") wordStart = false;
      }
      i += 2;
      continue;
    }
    if (ch === "'") {
      const ansiC = norm.endsWith("$"); // a plain `$` just before the quote; `\$'` leaves ESC in norm
      let j = i + 1;
      while (j < n && s[j] !== "'") j += ansiC && s[j] === "\\" ? 2 : 1;
      if (j >= n) { raw += s.slice(i); normOk = false; break; }
      raw += s.slice(i, j + 1); norm += "''"; wordStart = false; i = j + 1;
      continue;
    }
    if (ch === '"') {
      let j = i + 1;
      while (j < n && s[j] !== '"') {
        if (s[j] === "\\") j += 2;
        else { if (s[j] === "`" || (s[j] === "$" && s[j + 1] === "(")) normOk = false; j += 1; }
      }
      if (j >= n) { raw += s.slice(i); normOk = false; break; }
      raw += s.slice(i, j + 1); norm += "''"; wordStart = false; i = j + 1;
      continue;
    }
    if (ch === "<" && s[i + 1] === "<") {
      if (s[i + 2] === "<") { raw += "<<<"; norm += "<<<"; wordStart = true; i += 3; continue; }
      const h = readHeredocOpener(s, i);
      if (h) { pending.push(h); raw += s.slice(i, h.end); norm += "<<_"; wordStart = false; i = h.end; continue; }
    }
    raw += ch; norm += ch;
    wordStart = ch === " " || ch === "\t" || ";&|()<>".includes(ch);
    i++;
  }
  if (pending.length) ok = false;
  return { raw, norm: normOk ? norm : null, ok };
}
// The quote-blanked, comment- and heredoc-free text, or null when it cannot be read.
function blankCommand(command) {
  const sc = scanShell(command);
  return sc.ok ? sc.norm : null;
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
// Elements that run BEFORE the check decide whether it runs at all, so they are trusted only when harmless: the shell
// builtins that cannot change what runs next (cd, pushd, popd, echo, printf without -v, pwd, test, true, :, export NAME=...,
// plain assignments, `set` with only -e/-u/-x/-o pipefail|errexit|nounset|xtrace and their + forms), well-known external
// programs and any path-qualified program (an external process cannot touch this shell), and recognised checks/builds.
// Everything else — source, ., eval, hash, alias, shopt, enable, ulimit, wait, unalias, other `set` options (`-n`, `-o noexec`),
// function definitions, assignments to variables that change what runs (PATH, BASH_ENV, ...) — masks.
const DANGEROUS_VAR = /^(?:PATH|BASH_ENV|ENV|IFS|SHELL|SHELLOPTS|BASHOPTS|PROMPT_COMMAND|CDPATH|GLOBIGNORE|FUNCNEST|HISTFILE|LD_\w+|DYLD_\w+|NODE_OPTIONS|NODE_PATH|PYTHON\w*|RUBY\w*|PERL5?\w*|JAVA_TOOL_OPTIONS|_?JAVA_OPTIONS|JDK_JAVA_OPTIONS|CLASSPATH|GIT_\w+|(?:NPM|npm)_config_\w+|BASH_\w+|COMP\w*)$/;
const SAFE_SET_NAMES = new Set(["pipefail", "errexit", "nounset", "xtrace"]);
function isSafeSet(words) {
  for (let i = 0; i < words.length; i++) {
    const m = /^([-+])([euxo]+)$/.exec(words[i]);
    if (!m) return false;
    for (const ch of m[2]) if (ch === "o" && !SAFE_SET_NAMES.has(words[++i])) return false;
  }
  return true;
}
// An element that only sets up the environment for what follows: cd/pushd/popd, export NAME[=val], plain NAME=val, safe `set`.
function prefixLike(el) {
  const s = el.trim();
  if (BARE_PIPE.test(s)) return false;
  const name = (a) => a.replace(/\+?=.*$/, "");
  if (/^(?:[A-Za-z_]\w*\+?=\S*\s*)+$/.test(s)) return s.split(/\s+/).every((a) => !DANGEROUS_VAR.test(name(a)));
  const [word, ...args] = s.split(/\s+/);
  if (word === "cd" || word === "pushd" || word === "popd") return true;
  if (word === "export") return args.every((a) => /^[A-Za-z_]\w*(?:\+?=\S*)?$/.test(a) && !DANGEROUS_VAR.test(name(a)));
  return word === "set" && isSafeSet(args);
}
const SAFE_PROGRAMS = new Set(["echo", "pwd", "true", ":", "[", "test", "mkdir", "rm", "cp", "mv", "touch", "ls", "cat", "git", "make", "cmake", "cargo", "rustc", "go", "node",
  "npx", "npm", "pnpm", "yarn", "bun", "deno", "python", "python3", "pip", "pip3", "uv", "poetry", "bundle", "gem", "rake", "mvn", "gradle", "dotnet", "swift", "zig", "docker",
  "docker-compose", "curl", "wget", "sleep", "ln", "chmod", "tar", "unzip", "sed", "awk", "grep", "head", "tail", "sort", "wc", "find", "diff", "tee", "date", "which",
  "dirname", "basename", "mktemp", "rsync", "tsc", "eslint", "prettier"]);
function stageHarmless(stage) {
  if (prefixLike(stage) || stageCheckCommand(stage) !== null) return true;
  const s = stage.trim().replace(EXEC_PREFIX, "");
  if (s === "" || /^[A-Za-z_]\w*\+?=/.test(s)) return false; // a leftover assignment: to a variable that changes what runs
  const [word, ...args] = s.split(/\s+/);
  if (word === "printf") return !args.some((a) => /^-[A-Za-z]*v/.test(a)); // printf -v assigns a shell variable
  return word.includes("/") || SAFE_PROGRAMS.has(word);
}
const harmless = (el) => el.split(BARE_PIPE).every(stageHarmless);
export function exitIsMasked(command, pipefail = false) {
  if (command.length > ANALYSIS_CAP) return true;
  const sc = scanShell(command);
  if (!sc.ok || sc.norm === null) return true;
  const body = sc.raw.trim();
  if (BASH_PIPEFAIL_WRAPPER.test(body)) {
    const whole = PIPEFAIL_WRAPPER_WHOLE.exec(body);
    return whole ? exitIsMasked(whole[1] ?? whole[2], true) : true;
  }
  // A whole-command `sh -c 'body'` (no `-o`, no other words) is its body's status; a fresh shell has pipefail off.
  const shell = SHELL_C_WHOLE.exec(body);
  if (shell) return exitIsMasked(shell[1] ?? shell[2], false);
  const sub = loneSubshellBody(sc);
  if (sub !== null && CD_THEN.test(sub)) return exitIsMasked(sub, pipefail);
  const norm = sc.norm;
  if (UNATTRIBUTABLE.test(norm) || norm.includes("||") || hidesNestedCode(norm)) return true;
  if (BARE_PIPE.test(norm) && !pipefailOn(norm, pipefail)) return true;
  const groups = listGroups(norm);
  if (groups.flat().some((s) => /^!(?:\s|$)/.test(s))) return true;
  if (groups.flat().some((el) => el.split(BARE_PIPE).some(masksStatus))) return true;
  // The check must sit in the LAST `;`/newline group and no earlier group may hold one (`npm test ; echo done`). What runs
  // before it must be harmless: a builtin that stops the shell or changes what runs next (`set -n`, `eval exit 0`,
  // `source`, `hash`, `alias`, ...) would make a later exit 0 not the check's own. Elements after the check only run when
  // it passed (`&&`), so they cannot hide a failure. With no check at all (a custom runner), only prefix-like elements may
  // precede it and the command must be that one runner.
  const holdsEl = (el) => el.split(BARE_PIPE).some((stage) => stageCheckCommand(stage) !== null);
  const last = groups[groups.length - 1];
  if (!last) return true;
  const earlier = groups.slice(0, -1);
  let anchor;
  if (groups.flat().some(holdsEl)) {
    anchor = last.findIndex(holdsEl);
    if (anchor < 0 || earlier.some((g) => g.some(holdsEl))) return true;
    if (!earlier.every((g) => g.every(harmless))) return true;
  } else {
    anchor = last.length - 1;
    if (!earlier.every((g) => g.every(prefixLike)) || prefixLike(last[anchor])) return true;
  }
  return !last.slice(0, anchor).every(harmless);
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
  if (command.length > ANALYSIS_CAP) return false;
  const norm = blankCommand(command);
  if (norm === null || UNATTRIBUTABLE.test(norm)) return false;
  if (norm.includes("||") || />/.test(norm.replace(FD_MERGE_STDERR, ""))) return false;
  if (hidesNestedCode(norm)) return false;
  const parts = norm.split(BARE_PIPE);
  if (parts.length !== 2 || !TAIL_ARGS.test(parts[1])) return false;
  const segs = listGroups(parts[0]).flat();
  if (segs.length === 0 || prefixLike(segs[segs.length - 1])) return false;
  if (!segs.slice(0, -1).every(prefixLike)) return false;
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
  if (/^\s*0 (?:tests? )?(?:passed|passing|ran)\b|^\s*0 pass(?:ed|es|ing)?\s*$|passed:\s*0\b|^\s*Tests:\s.*0 total\b|test result: ok\.\s+0 passed|0 examples, 0 failures|\bNo tests found\b|\bcollected 0 items\b|\b0 tests? collected\b|^=+ no tests ran\b/im.test(tail)) return true;
  // Everything skipped, todo or deselected: jest/vitest `Tests: N skipped, N total`, pytest `= 2 skipped in 0.1s =`.
  const jt = /^\s*Tests(?::|\s{2,})[^\n]*/m.exec(tail);
  if (jt && !/[1-9]\d* (?:passed|failed)/.test(jt[0])) return true;
  if (/^=+ (?:\d+ (?:skipped|deselected|warnings?|xfailed|xpassed),? ?)+ in [\d.]+s/m.test(tail)) return true;
  // go test: every package printed `[no test files]` or `[no tests to run]` and none printed a real `ok` line.
  const noTests = /^\?\s+\S+\s+\[no test files\]/m.test(tail) || /^ok\s+\S+\s+[\d.]+s\s+\[no tests to run\]/m.test(tail);
  return noTests && !/^ok\s+\S+\s+[\d.]+s\s*(?:\(cached\))?$/m.test(tail);
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
  if (command.length > ANALYSIS_CAP) return "unknown"; // not analysed past the cap: nothing after the cut can be ruled out
  if (exitIsMasked(command)) return summary === "pass" && maskedByTailPipeOnly(command) ? "pass" : "unknown";
  if (summary === "pass") {
    // A non-check command earns a pass only when it ran a real program; a command that only prints a stored
    // file (`cat mocha-results.log`) can carry a stale or forged green summary and proves nothing.
    const norm = blankCommand(command);
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
  if (jest) {
    if (jest[1] && Number(jest[1]) > 0) return "fail";
    if (/^Tests:[^\n]*[1-9]\d* passed/m.test(tail)) return "pass"; // only skipped/todo tests: nothing was verified
  }
  const pytest = /^=+ .*?(?:(\d+) failed|(\d+) error).*?in [\d.]+s/m.exec(tail) ?? /^=+ ([1-9]\d*) passed.*? in [\d.]+s/m.exec(tail);
  if (pytest) return /\d+ (?:failed|error)/.test(pytest[0]) ? "fail" : "pass";
  const cargoOrGo = /^test result: (ok|FAILED)\.\s+[1-9]\d* passed/m.exec(tail) ?? /^test result: (FAILED)\./m.exec(tail) ?? /^(ok|FAIL)\s+\S+\s+[\d.]+s$/m.exec(tail);
  if (cargoOrGo) return cargoOrGo[1] === "ok" ? "pass" : "fail";
  const vitest = /^\s*Tests\s{2,}([^\n]*\([1-9]\d*\))\s*$/m.exec(tail);
  if (vitest) {
    if (/[1-9]\d* failed/.test(vitest[1])) return "fail";
    if (/[1-9]\d* passed/.test(vitest[1])) return "pass";
  }
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
// A non-check command can earn a pass only as a custom runner: a script path (`./run-suite.sh`, `scripts/ci.sh`),
// `make ...` or `npm|pnpm|yarn|bun run ...`, and only when it is the one command that ran: the last and only element
// that is not a prefix (`cd x && ./run.sh` yes, `cat forged.log && ./noop.sh` no). Anything else — including text printers
// the PRINT_ONLY list does not name (`tac`, `nl`, `docker logs`, `gh run view --log`, `diff`) — can only replay or forge a
// summary. (`bash x.sh` stays print-only: PRINT_ONLY lists the shells, since `bash -c 'echo ...'` prints.)
const CUSTOM_RUNNER = /^(?:\.{1,2}\/\S*|\S*\/scripts?\/\S*|scripts?\/\S*|make(?=\s|$)|(?:npm|pnpm|yarn|bun)\s+run\b)/;
function runsCustomRunner(command) {
  const norm = blankCommand(boundedCommand(command));
  if (norm === null) return false;
  const els = listGroups(norm).flat().filter((el) => !prefixLike(el));
  if (els.length !== 1) return false;
  return CUSTOM_RUNNER.test(els[0].split(BARE_PIPE)[0].trim().replace(EXEC_PREFIX, ""));
}
export function classifyToolResult(tool, input = {}, failed = false, output = "") {
  if (MUTATING_TOOLS.has(tool)) return "mutation";
  const command = typeof input.command === "string" ? input.command : "";
  const isCheck = tool === "Bash" && commandRunsCheck(command);
  if (!isCheck && !(tool === "Bash" && runsCustomRunner(command) && checkSummary(output))) return "unknown";
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
      const outcome = call.input?.run_in_background || BACKGROUND_RESULT.test(stdout) ? "unknown" : classifyToolResult(call.name, call.input, failed, stdout);
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
