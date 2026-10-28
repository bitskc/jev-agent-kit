// Shell-text helpers for the kit_* tools.
//
// Ported from jonathanavis96/jev-kit (MIT, Copyright (c) 2026 Jonathan Avis):
//   airlock/rules.py   split_segments, words, program_of, _wrapped_command
//   airlock/scope.py   strip_heredocs, strip_shell_comment
//   airlock/redact.py  (replaced by the jev-belay redactor below)
// Redactor adapted from valentynkit/jev-belay belay.mjs (MIT, Copyright (c) 2026 Valentyn Kit).
// See NOTICE-jev-kit.md. Everything here is pure string work: no I/O, never throws.

import { posix as posixPath } from "node:path";
export const ASSIGN_RE = /^[A-Za-z_][A-Za-z_0-9]*=/;

/** Split a command line into segments on ; && || | and newlines, respecting quotes. */
export function splitSegments(command) {
  const segs = [];
  let buf = [];
  let quote = null;
  // Real bash deletes backslash-newline pairs BEFORE tokenizing (line continuation); folding them here,
  // outside quotes, keeps `rm -rf \<newline>/` one `/` token the way bash sees it.
  const s = (command || "").replace(/\\\r?\n/g, "");
  const n = s.length;
  let i = 0;
  while (i < n) {
    const ch = s[i];
    if (quote) {
      buf.push(ch);
      // `\"` inside a double-quoted run is an escaped quote, not a closer — the same rule words() and
      // splitPipelines() apply. Without it, `bash -c "bash -c \"rm -rf /\""` shredded the inner -c's
      // script at its \" boundary and every downstream rule saw mangled text.
      if (ch === "\\" && quote === '"' && i + 1 < n) { buf.push(s[i + 1]); i += 2; continue; }
      if (ch === quote) quote = null;
      i++;
      continue;
    }
    if (ch === "'" || ch === '"') { quote = ch; buf.push(ch); i++; continue; }
    if (ch === "\\" && i + 1 < n) { buf.push(ch, s[i + 1]); i += 2; continue; }
    if (ch === ";" || ch === "\n") { segs.push(buf.join("")); buf = []; i++; continue; }
    if (ch === "&" || ch === "|") {
      segs.push(buf.join("")); buf = [];
      while (i < n && (s[i] === "&" || s[i] === "|")) i++;
      continue;
    }
    buf.push(ch);
    i++;
  }
  segs.push(buf.join(""));
  return segs.map((x) => x.trim()).filter(Boolean);
}

/** Whitespace-delimited tokens of a segment, shell-quote-aware: a quoted run (even one containing spaces)
 *  stays part of the SAME token as any adjacent unquoted/quoted content, and quote delimiters/backslash
 *  escapes are removed in the same pass -- not as a separate split-then-strip step. That separate-step
 *  order used to be the bug: splitting on raw whitespace BEFORE stripping quotes shredded a quoted
 *  multi-word argument into several tokens (`-c "x = 1; print(open('.env').read())"` -> five ordinary-
 *  looking tokens instead of one script string), so a caller that only ever inspects `args[i+1]` (the
 *  single token right after a flag) silently stopped seeing almost any real `-c`/`-e` one-liner. Now a
 *  fully-quoted run with internal spaces becomes exactly one token, matching real bash word-formation
 *  (`"a b"c` -> one token `a bc`; `.e''nv` -> `.env`). Heuristic, not a full shell parser: a single open
 *  quote is tracked at a time (no nesting), and deliberately permissive about an obfuscated quote char
 *  landing inside a word -- for a security prefilter, collapsing is the safer failure mode than preserving
 *  an exotic literal. */
export function words(segment) {
  const out = [];
  let buf = "";
  let quote = null;
  let ansiC = false; // inside a $'...' ANSI-C quoted run: bash decodes \xNN/\n/\t/... escapes
  let inWord = false;
  const s = segment || "";
  const n = s.length;
  for (let i = 0; i < n; i++) {
    const ch = s[i];
    if (quote) {
      if (ch === quote) { quote = null; ansiC = false; continue; }
      if (ansiC && ch === "\\" && i + 1 < n) {
        const [decoded, len] = ansiEscape(s.slice(i));
        buf += decoded; i += len - 1; inWord = true; continue; // for-loop continue still runs i++
      }
      if (ch === "\\" && quote === '"' && i + 1 < n && '"\\$`'.includes(s[i + 1])) {
        buf += s[i + 1]; i++; inWord = true; continue;
      }
      // Inside double quotes bash only unescapes \" \\ \$ \` (and \newline); every other backslash
      // pair stays literal. Dequoting the four real escapes is what makes a nested -c script survive one
      // more tokenization round as ONE token: `bash -c "bash -c \"echo hi\""` -> `bash -c "echo hi"`,
      // exactly the script the inner bash would receive. Before this, `\"` inside a double-quoted run
      // closed the quote early and shredded the nested script into several tokens.
      buf += ch; inWord = true;
      continue;
    }
    // $'...' ANSI-C quoting and $"..." locale quoting: the `$` is consumed by the quote, not part of the
    // word's value -- `$'/'` is just `/` to the shell, and `$'\x2eenv'` decodes byte-for-byte to `.env`.
    if (ch === "$" && i + 1 < n && (s[i + 1] === "'" || s[i + 1] === '"')) {
      quote = s[i + 1]; ansiC = s[i + 1] === "'"; i++; inWord = true; continue;
    }
    if (ch === "'" || ch === '"') { quote = ch; inWord = true; continue; }
    if (ch === "\\" && i + 1 < n) { buf += s[i + 1]; i++; inWord = true; continue; }
    if (/\s/.test(ch)) {
      if (inWord) { out.push(buf); buf = ""; inWord = false; }
      continue;
    }
    buf += ch; inWord = true;
  }
  if (inWord) out.push(buf);
  return out;
}

/** Decode one ANSI-C escape at s[0]==="\\" inside a $'...' run: \xNN and the common one-char escapes.
 *  Returns [decodedChar, charsConsumed]. Unknown escapes keep the char but drop the backslash, matching
 *  bash's own "unrecognised escape = literal char" behaviour closely enough for path/flag matching. */
function ansiEscape(s) {
  const c = s[1];
  if (c === "x") {
    const m = /^[0-9a-fA-F]{1,2}/.exec(s.slice(2));
    if (m) return [String.fromCodePoint(parseInt(m[0], 16)), 2 + m[0].length];
    return ["x", 2];
  }
  if (c === "u") {
    const m = /^[0-9a-fA-F]{1,4}/.exec(s.slice(2));
    if (m) return [String.fromCodePoint(parseInt(m[0], 16)), 2 + m[0].length];
    return ["u", 2];
  }
  if (c >= "0" && c <= "7") {
    const m = /^[0-7]{1,3}/.exec(s.slice(1));
    return [String.fromCodePoint(parseInt(m[0], 8)), 1 + m[0].length];
  }
  const ONE = { n: "\n", t: "\t", r: "\r", a: "\x07", b: "\b", f: "\f", v: "\x0b", e: "\x1b", E: "\x1b" };
  return [ONE[c] !== undefined ? ONE[c] : c, 2];
}

// ── ONE shared command-resolution layer ──────────────────────────────────────
// Every rule used to peel a different subset of wrappers (programOf knew env/timeout/nice/stdbuf,
// rdCommand knew doas, peelArgv knew sudo, nobody knew pkexec/systemd-run/nsenter/...), and a rule whose
// walk lacked a wrapper silently missed the command behind it. Now there is exactly one argv walk:
// peelCommand() below, driven by WRAPPER_SPECS, and programOf()/resolveCommand()/unwrapScripts()' walk
// are three thin consumers of it.
//
// WRAPPER_SPECS[prog] = {
//   valueOpts:  tokens that consume the FOLLOWING argv element as their value (spaced form). An
//               `--opt=val` / `-oval` attached form never consumes the next element.
//   flags:      tokens that are pure flags (consumed, value never eaten). Unknown option-looking tokens
//               are conservatively skipped as flags: under-skipping (treating a value as the command)
//               resolves to the wrong program, while over-skipping (eating the command as a value)
//               resolves to nothing -- and a miss on the WRONG program is still a miss either way, so
//               the flag default is the safer side.
//   shortValue: single chars that take a value inside a bundled short-option run (sudo -u root ->
//               'u' consumes the next token only when it's the LAST char of the bundle).
//   operands:   bare non-option tokens consumed before the command (timeout's duration, chroot's
//               new-root, taskset's mask).
//   operandsIfNoOpts: consume `operands` only when no valueOpt was actually seen (taskset -c consumes
//               the cpu mask AS the -c value, so the operand rule must not eat the program too).
//   spliceOpts: tokens whose VALUE is itself a command line to splice back into the argv walk
//               (env -S 'cmd args' splits that string and keeps resolving through it).
//   joinAfterDashDash: after `--`, the remaining tokens join into ONE script string (capsh -- -c 'x').
// }
const SUDO_SHORT_VALUE = new Set("ugpCUrtDRTh".split(""));
const SUDO_LONG_VALUE = new Set(["--user", "--group", "--prompt", "--close-from", "--other-user", "--role",
  "--type", "--chdir", "--chroot", "--command-timeout", "--host", "--login-class"]);
export const ELEVATED_PROGS = new Set(["sudo", "doas"]);
const WRAPPER_SPECS = {
  env: { valueOpts: new Set(["-u", "--unset", "-C", "--chdir", "-S", "--split-string"]),
         spliceOpts: new Set(["-S", "--split-string"]), envAssignments: true },
  timeout: { valueOpts: new Set(["-s", "--signal", "-k", "--kill-after"]), operands: 1 },
  nice: { valueOpts: new Set(["-n", "--adjustment"]) },
  ionice: { valueOpts: new Set(["-c", "--class", "-n", "--classdata", "-p", "--pid"]) },
  stdbuf: { valueOpts: new Set(["-i", "-o", "-e"]) },
  taskset: { valueOpts: new Set(["-c", "--cpu-list", "-p", "--pid"]), operands: 1, operandsIfNoOpts: true },
  chrt: { valueOpts: new Set(["-p", "--pid"]), operands: 1, operandsIfNoOpts: true },
  sudo: { valueOpts: SUDO_LONG_VALUE, shortValue: SUDO_SHORT_VALUE },
  doas: { valueOpts: new Set(["-u", "-C"]), shortValue: new Set("uC".split("")) },
  runuser: { runuserStyle: true },
  // Everything after `--` is bash -c's script, not argv -- handled by joinAfterDashDash.
  capsh: { joinAfterDashDash: true },
  // plain peels: no operand before the command; leading options skipped (listed value-opts consumed).
  nohup: {}, exec: {}, command: {}, builtin: {}, time: {}, pkexec: { valueOpts: new Set(["-u", "--user"]) }, setsid: {}, fakeroot: {},
  eatmydata: {}, proxychains: {}, proxychains4: {}, busybox: {},
  watch: { valueOpts: new Set(["-n", "--interval"]) },
  unshare: { valueOpts: new Set(["-S", "-G", "--setuid", "--setgid", "-w", "--wd",
    "--map-user", "--map-group"]) },
  nsenter: { valueOpts: new Set(["-t", "--target", "-r", "--root", "-w", "--wd", "-S", "--setuid",
    "-G", "--setgid"]) },
  setpriv: { valueOpts: new Set(["--reuid", "--regid", "--groups", "--supp-groups", "--inh-caps",
    "--ambient-caps", "--bounding-set", "--no-new-privs", "--selinux-label", "--apparmor-profile",
    "--rlimit-as", "--rlimit-core", "--rlimit-cpu", "--rlimit-data", "--rlimit-fsize", "--rlimit-memlock",
    "--rlimit-nofile", "--rlimit-nproc", "--rlimit-rss", "--rlimit-stack", "--securebits"]) },
  chpst: { valueOpts: new Set(["-u", "-U", "-b", "-e", "-m", "-d", "-o", "-f", "-c", "-n"]) },
  "flatpak-spawn": { valueOpts: new Set(["--env", "--forward-fd", "--watch-fd", "--env-fd",
    "--expose-pids", "--directory", "--sandbox-expose", "--sandbox-expose-ro", "--sandbox-expose-fd",
    "--sandbox-expose-fd-ro", "--unset-env"]) },
  "systemd-run": { valueOpts: new Set(["--unit", "--uid", "--gid", "--nice", "--working-directory",
    "--setenv", "--on-active", "--on-boot", "--on-startup", "--on-unit-active", "--on-unit-inactive",
    "--on-calendar", "--timer-property", "--property", "-p", "--description", "--slice",
    "--pty-delay"]) },
  firejail: { valueOpts: new Set(["--profile", "--dns", "--hosts-file", "--private-home",
    "--name", "--hostname", "--nice", "--cpu", "--rlimit-as", "--rlimit-cpu",
    "--rlimit-nofile", "--rlimit-nproc", "--rlimit-fsize", "--rlimit-sigpending", "--interface",
    "--veth-name", "--bridge", "--netmask", "--ip6", "--mtu", "--defaultgw", "--shell",
    "--protocol", "--chroot", "--overlay", "--whitelist", "--env"]) },
  chroot: { valueOpts: new Set(["--userspec", "--groups"], ), operands: 1 },
};
// Shell keywords and compound-syntax markers that precede the real command: `if true; then cat x; fi`,
// `{ cat x; }`, `( cat x )`, `! cat x`, `case x in y) cat x;; esac`, `for v in a; do cat x; done`.
// rdCommand historically knew a SUBSET of these and programOf knew none -- a rule routing through
// programOf saw "if"/"{"/"!(" as the program and missed everything behind it.
const KEYWORD_SKIP = new Set(["if", "then", "elif", "else", "fi", "do", "done", "while", "until",
  "in", "esac", "select", "coproc", "{", "}", "!", "time"]);
const base = (p) => p.slice(p.lastIndexOf("/") + 1);
const stripHeadMarks = (t) => t.replace(/^[({!]+/, "");
const isCaseLabel = (t) => t.endsWith(")") && !t.includes("(");

/** The single argv peel walk. Consumes leading VAR=val assignments, shell keywords/grouping markers,
 *  and every WRAPPER_SPECS wrapper -- each wrapper's own flags, value-taking options, operands and
 *  script-splicing -- until an ordinary command word surfaces. Options:
 *    stopAt: a Set of program names the walk does NOT peel but returns AS the command (programOf uses
 *      ELEVATED_PROGS so the R5-sudo rule still sees `sudo`/`doas` as the program it must policy-check;
 *      the canonicalization consumers pass nothing and peel them too).
 *    splice: collected script strings pulled out of spliceOpts values along the way (env -S 'cmd').
 *  Returns the remaining argv ([] when nothing concrete is left). Never throws; worst case stops early. */
export function peelCommand(toksIn, opts = {}) {
  const stopAt = opts.stopAt || null;
  let toks = toksIn;
  for (;;) {
    if (!toks.length) return [];
    const head = stripHeadMarks(toks[0]);
    if (head !== toks[0]) {
      // `!( cmd` / `{ cmd` / `( cmd`: the grouping marker rides the first token. If stripping it empties
      // the token (a bare `(`/`{`/`!` word) or leaves a keyword, fall through to the keyword branch.
      toks = [head, ...toks.slice(1)];
    }
    const t0 = toks[0];
    if (!t0) { toks = toks.slice(1); continue; }
    if (t0 === ")") { toks = toks.slice(1); continue; }
    if (isCaseLabel(t0)) { toks = toks.slice(1); continue; }
    if (t0 === "for" || t0 === "select") {
      // `for v in a b; do ...`: the words between `in` and `do` are the list, not commands.
      let i = 1;
      while (i < toks.length && toks[i] !== "in" && toks[i] !== "do") i++;
      while (i < toks.length && toks[i] !== "do") i++;
      toks = i < toks.length ? toks.slice(i + 1) : [];
      continue;
    }
    if (t0 === "case") {
      const k = toks.indexOf("in");
      toks = k >= 0 ? toks.slice(k + 1) : [];
      continue;
    }
    if (KEYWORD_SKIP.has(t0)) { toks = toks.slice(1); continue; }
    if (ASSIGN_RE.test(t0)) { toks = toks.slice(1); continue; }
    const prog = base(t0);
    if (stopAt && stopAt.has(prog)) return toks;
    const spec = WRAPPER_SPECS[prog];
    if (!spec) return toks;
    if (spec.runuserStyle) {
      // runuser [opts] [-] [user] cmd...: the first bare positional is the user ONLY when a command
      // still follows it, never when it IS the command (`runuser -u root bash -c ...` already named
      // the user via -u).
      let i = 1;
      let namedUser = false;
      while (i < toks.length) {
        const t = toks[i];
        if (t === "--") { i++; break; }
        if (!t.startsWith("-") || t === "-") break;
        if (["-u", "--user", "-s", "--shell", "-g", "--group", "-G", "--supp-group", "-c", "--command"].includes(t)) {
          if (t === "-u" || t === "--user") namedUser = true;
          i += 2;
          continue;
        }
        i++;
      }
      if (i < toks.length && toks[i] === "-") i++;
      // The first bare positional is the USER only when -u/--user didn't already name one and a
      // command still follows it (`runuser bob ls` vs `runuser -u bob ls`).
      if (!namedUser && i < toks.length && i + 1 < toks.length && !toks[i].startsWith("-")) i++;
      if (i < toks.length && toks[i] === "--") i++;
      toks = toks.slice(i);
      continue;
    }
    let i = 1;
    let sawValueOpt = false;
    while (i < toks.length) {
      const t = toks[i];
      if (t === "--") {
        i++;
        if (spec.joinAfterDashDash) return toks.slice(i).length ? ["bash", ...toks.slice(i)] : [];
        break;
      }
      if (!t.startsWith("-") || t === "-") break;
      if (spec.envAssignments && ASSIGN_RE.test(t)) { i++; continue; }
      if (spec.spliceOpts) {
        // --split-string=x / -S=x: the attached value is still a command line to splice.
        const eq = spec.spliceOpts && [...spec.spliceOpts].find((o) => t.startsWith(o + "="));
        if (eq) {
          const val = t.slice(eq.length + 1);
          if (opts.splice) opts.splice.push(val);
          toks = [...toks.slice(0, i), ...words(val), ...toks.slice(i + 1)];
          i = 1;
          continue;
        }
      }
      if (t.includes("=")) { i++; continue; } // --opt=val: value attached, nothing more to consume
      if (spec.spliceOpts && spec.spliceOpts.has(t) && i + 1 < toks.length) {
        // env -S/--split-string: the value IS a command line. Splice its words back into the argv walk
        // (env -S 'rm -rf /' resolves to rm) AND record the raw text for script-level consumers.
        if (opts.splice) opts.splice.push(toks[i + 1]);
        toks = [...toks.slice(0, i), ...words(toks[i + 1]), ...toks.slice(i + 2)];
        i = 1;
        continue;
      }
      if (spec.valueOpts && spec.valueOpts.has(t)) { i += 2; sawValueOpt = true; continue; }
      // Attached short-form value for a spliceOpt (env -S'cmd args').
      if (spec.spliceOpts && !t.startsWith("--") && t.length > 2 && [...spec.spliceOpts].some((o) => o.length === 2 && t.startsWith(o))) {
        const val = t.slice(2);
        if (opts.splice) opts.splice.push(val);
        toks = [...toks.slice(0, i), ...words(val), ...toks.slice(i + 1)];
        i = 1;
        continue;
      }
      if (!t.startsWith("--") && spec.shortValue) {
        let consumed = false;
        for (let j = 1; j < t.length; j++) {
          if (spec.shortValue.has(t[j])) { if (j === t.length - 1) { i += 2; consumed = true; } break; }
        }
        if (consumed) continue;
        i++;
        continue;
      }
      i++; // unknown option: conservatively a flag
    }
    const operands = spec.operandsIfNoOpts && sawValueOpt ? 0 : (spec.operands || 0);
    i += operands;
    if (i >= toks.length) {
      // The wrapper IS the command (bare `env` dumps the environment, bare `xargs` echoes stdin):
      // surface it as the program with its own args, not as a resolved-nothing.
      return toks;
    }
    toks = toks.slice(i);
  }
}

/** First real command word of a segment, past VAR=val, keywords and wrapper prefixes -- deliberately
 *  NOT past sudo/doas (ELEVATED_PROGS), which surface AS the program so the R5-sudo/doas policy rule
 *  still applies to them; every other consumer resolves elevation via resolveCommand/peelCommand.
 *  Returns [program, args]. */
export function programOf(segment) {
  const toks = peelCommand(words(segment), { stopAt: ELEVATED_PROGS });
  if (!toks.length) return [null, []];
  return [base(toks[0]), toks.slice(1)];
}

// ── wrapper unwrap: bash -c/sh -c/eval/xargs/find -exec/su/ssh/..., shared by every rule ──────────────
export const SHELL_WRAPPER_PROGS = new Set(["sh", "bash", "dash", "zsh", "ksh", "fish", "csh", "tcsh"]);
const SHELL_WRAPPER_VALUE_OPTS = new Set(["-o", "+o", "-O", "+O", "--rcfile", "--init-file"]);
const XARGS_VALUE_OPTS = new Set(["-a", "-d", "-E", "-I", "-J", "-L", "-n", "-P", "-s",
  "--arg-file", "--delimiter", "--max-args", "--max-procs", "--max-chars", "--process-slot-var"]);
const PARALLEL_VALUE_OPTS = new Set(["-a", "--arg-file", "-A", "-j", "--jobs", "-N", "-n", "--max-lines",
  "-L", "-l", "-s", "--colsep", "--delay", "--retries", "-S", "--trc", "-W", "--workdir", "-P",
  "--max-procs", "-I", "--replace", "-B", "--slot-replace", "--timeout"]);
const SSH_VALUE_OPTS = new Set(["-b", "-c", "-D", "-E", "-F", "-I", "-i", "-J", "-L", "-l", "-m", "-O",
  "-o", "-p", "-Q", "-R", "-S", "-W", "-w"]);
/** For a shell invoked with -c ('bash -c', 'sh -c', 'zsh -c', ...), the wrapped script text as a single
 *  trimmed, outer-quote-stripped string; null if `args` isn't a -c invocation. Handles a combined short
 *  flag group (`-xc`) and -o/-O's own value. The one shared -c detector: both expandWrappedSegments below
 *  and R7-root-delete's own recursive rdHit (which needs the identical detection, just reached through its
 *  own stricter tokenizer upstream) call this same function, so there is one implementation of "does this
 *  shell invocation carry an inline script, and what is it" rather than two independently-maintained ones. */
export function shellDashCScript(args) {
  let hasC = false;
  let i = 0;
  while (i < args.length) {
    const a = args[i];
    if (a === "--") { i++; break; }
    if (SHELL_WRAPPER_VALUE_OPTS.has(a)) { i += 2; continue; }
    if (a.startsWith("-") && !a.startsWith("--") && a.length > 1) {
      hasC = hasC || a.slice(1).includes("c");
      i += "oO".includes(a[a.length - 1]) ? 2 : 1;
      continue;
    }
    if (a.startsWith("--") || (a.startsWith("+") && a.length > 1)) { i++; continue; }
    break;
  }
  if (!hasC) return null;
  const script = args.slice(i).join(" ").trim().replace(/^['"]+|['"]+$/g, "");
  return substLiteral(script) || script;
}

/** The real [program, args] an item-feeding or shell-indirection command runs: `xargs`'/`parallel`'s
 *  invoked argv, `find ... -exec cmd \;`'s argv, or -- for su/ssh -- the inline script itself.
 *  The invoked argv gets the SAME full prefix peeling a bare command line would (env/timeout/nice/
 *  sudo/setsid/systemd-run/...): without it `xargs -I{} timeout {} bash -c 'rm -rf /'` resolved to
 *  `timeout` -- not a shell wrapper -- and the -c script was never unwrapped. Returns [program, args],
 *  or null when prog isn't one of the known indirections / has no invoked command. */
export function indirectInvokes(prog, args) {
  if (prog === "xargs" || prog === "parallel") {
    const i = firstPositional(args, prog === "xargs" ? XARGS_VALUE_OPTS : PARALLEL_VALUE_OPTS);
    if (i === null) return null;
    const rest = peelCommand(args.slice(i));
    return rest.length ? [base(rest[0]), rest.slice(1)] : null;
  }
  if (prog === "find") {
    for (let i = 0; i < args.length; i++) {
      if (!["-exec", "-execdir", "-ok", "-okdir"].includes(args[i])) continue;
      const rest = [];
      for (let j = i + 1; j < args.length && args[j] !== ";" && args[j] !== "+"; j++) rest.push(args[j]);
      const peeled = peelCommand(rest);
      if (peeled.length) return [base(peeled[0]), peeled.slice(1)];
    }
  }
  return null;
}

/** Full command resolution: programOf's keyword/wrapper peel, then the item-feeding/shell indirection
 *  resolution (xargs/parallel/find -exec), then a final peel of whatever that produced -- iterated until
 *  stable (an -exec'd command can itself be an indirection). This is THE entry point every per-segment
 *  rule uses when it asks "what program does this segment actually run, and with what args": the invoked
 *  argv is rescanned through every rule exactly like a bare command (xargs curl -d @.env, find -exec dd,
 *  xargs aws s3 cp secrets all reach their rules). `stopAt` forwards to programOf. */
export function resolveCommand(segment, opts = {}) {
  const [prog0, args0] = programOf(segment);
  if (prog0 === null) return [null, []];
  // programOf deliberately stops AT sudo/doas (R5 sees the elevation wrapper); everything else needs
  // the command behind it, so the head goes through one more peel with no stopAt.
  let toks = peelCommand([prog0, ...args0]);
  if (!toks.length) return [null, []];
  let [prog, args] = [base(toks[0]), toks.slice(1)];
  for (let k = 0; k < 4; k++) {
    const invoked = indirectInvokes(prog, args);
    if (!invoked) return [prog, args];
    const peeled = peelCommand([invoked[0], ...invoked[1]]);
    if (!peeled.length) return [null, []];
    [prog, args] = [base(peeled[0]), peeled.slice(1)];
  }
  return [prog, args];
}

/** `su [-] [user] -c 'script'` / `su -c'script'` / `su --command='script'`: the -c operand is a full
 *  shell script, same indirection class as `bash -c` (GNU su accepts the -c<value> attached form too). */
function suScript(args) {
  for (let i = 0; i < args.length; i++) {
    if ((args[i] === "-c" || args[i] === "--command") && i + 1 < args.length) return args[i + 1];
    if (args[i].startsWith("--command=")) return args[i].slice("--command=".length);
    if (args[i].length > 2 && args[i].startsWith("-c") && !args[i].startsWith("--")) return args[i].slice(2);
  }
  return null;
}
/** `ssh [opts] dest 'remote script'`: first non-option operand is the destination, everything after it is
 *  one remote command line -- re-tokenizable script text for our purposes. */
function sshScript(args) {
  const i = firstPositional(args, SSH_VALUE_OPTS);
  return i !== null && i + 1 < args.length ? args.slice(i + 1).join(" ") : null;
}
const TMUX_SCRIPT_SUBS = new Set(["new-session", "neww", "new-window", "split-window", "splitw", "respawn-pane", "respawnw"]);
/** Interpreters whose -c/-e/--eval/-r operand is an inline script (versioned binary names like
 *  python3.11 match via the same trailing-version rule the pipe detector uses). */
export const INTERP_SCRIPT_PROGS = new Set(["python", "python3", "node", "nodejs", "ruby", "perl", "php",
  "deno", "bun", "pwsh", "powershell", "lua"]);
const INTERP_SCRIPT_OPTS = new Set(["-c", "-e", "--eval", "-r"]);
const INTERP_PROG_BASES = new Set(["python", "node", "nodejs", "ruby", "perl", "php", "deno", "bun", "lua", "pwsh", "powershell"]);
const INTERP_VERSION_RE2 = /^([a-z]+?)(\d+(?:\.\d+)*)$/i;
function interpBase(prog) {
  if (INTERP_PROG_BASES.has(prog)) return prog;
  const m = INTERP_VERSION_RE2.exec(prog || "");
  return m && INTERP_PROG_BASES.has(m[1].toLowerCase()) ? m[1].toLowerCase() : null;
}
/** The inline-script text of an interpreter invocation (`python -c X`, `node --eval X`, `php -r X`,
 *  `deno eval X`, `bun -e X`), or null. deno's `eval` is a SUBCOMMAND (first positional), not a flag. */
export function interpScriptText(prog, args) {
  const b = interpBase(prog);
  if (!b) return null;
  if (b === "deno") {
    const i = firstPositional(args, new Set());
    return i !== null && args[i] === "eval" && args[i + 1] !== undefined ? args[i + 1] : null;
  }
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--") break;
    if (INTERP_SCRIPT_OPTS.has(a) && args[i + 1] !== undefined) return args[i + 1];
    if (a.startsWith("--eval=")) return a.slice("--eval=".length);
  }
  return null;
}
/** A script string carried by a segment's resolved invocation: bash/sh/fish -c, eval's whole args, an
 *  interpreter's -c/-e/-r/--eval payload, su -c, ssh's remote command line, tmux's shell-command
 *  operand, capsh's post-`--` join, or an env -S/--split-string value. Returns script text or null. */
export function scriptOf(prog, args, opts = {}) {
  if (prog === "eval") return args.length ? args.join(" ") : null;
  if (SHELL_WRAPPER_PROGS.has(prog)) return shellDashCScript(args);
  if (prog === "su" || prog === "runuser") return suScript(args);
  if (prog === "ssh") return sshScript(args);
  if (prog === "tmux") {
    const i = firstPositional(args, new Set(["-L", "-S", "-f", "-T", "-t", "-s"]));
    if (i !== null && TMUX_SCRIPT_SUBS.has(args[i]) && args.slice(i + 1).length) return args.slice(i + 1).join(" ");
    return null;
  }
  if (prog === "env") {
    for (let i = 0; i < args.length; i++) {
      if ((args[i] === "-S" || args[i] === "--split-string") && args[i + 1]) return args[i + 1];
      if (args[i].startsWith("--split-string=")) return args[i].slice("--split-string=".length);
      if (args[i].length > 2 && args[i].startsWith("-S")) return args[i].slice(2);
    }
    return null;
  }
  if (opts.interp !== false) {
    const t = interpScriptText(prog, args);
    if (t !== null) return t;
  }
  return null;
}

/** Every script body reachable by peeling wrapper layers around any of `segments` -- bash -c/sh -c/
 *  eval/xargs/find -exec/parallel/su/runuser/ssh/tmux/capsh/env -S/interp -c -- recursively, up to
 *  maxDepth levels. Raw, unsplit text, so a caller needing pipeline structure (splitPipelines) or
 *  per-segment matching (splitSegments) parses it whichever way it needs. Returns only the NEWLY found
 *  script bodies, not the original segments (callers already have those). */
export function unwrapScripts(segments, maxDepth = 3) {
  const out = [];
  const walk = (segs, depth) => {
    if (depth >= maxDepth) return;
    for (const seg of segs) {
      // env -S/--split-string's value is a script line peelCommand splices into argv (resolveCommand
      // sees `env -S 'rm -rf /'` as rm); collect the same text as a SCRIPT so pipeline-shape rules
      // (env --split-string='curl x | sh') see the | as a real pipeline, not argv noise.
      const splices = [];
      peelCommand(words(seg), { splice: splices });
      for (const sp of splices) {
        out.push(sp);
        walk(splitSegments(stripHeredocs(sp)), depth + 1);
      }
      let [prog, args] = programOf(seg);
      if (prog === null) continue;
      const invoked = indirectInvokes(prog, args);
      if (invoked) [prog, args] = invoked;
      const script = scriptOf(prog, args);
      if (!script) continue;
      out.push(script);
      walk(splitSegments(stripHeredocs(script)), depth + 1);
      // An interpreter's -c/-e/--eval payload is ITS language, not shell -- but string literals inside
      // it passed to os.system()/execSync()/system()/qx are shell command lines with literal text
      // right there to scan: python3 -c "import os;os.system('rm -rf /')" unwraps the os.system
      // operand exactly like any other -c script.
      if (interpBase(prog) !== null) {
        for (const lit of interpShellLiterals(script)) {
          out.push(lit);
          walk(splitSegments(stripHeredocs(lit)), depth + 1);
        }
      }
    }
  };
  walk(segments, 0);
  return out;
}

const SUBST_LIT_TOKEN_RE = /^(?:\$\((.*)\)|`(.*)`)$/s;
/** If a token is exactly one `$(cmd ...)`/`` `cmd ...` `` substitution whose command is a literal-
 *  printing builtin (`echo X`, `printf X`), resolve to the literal the substitution emits -- the
 *  common way to smuggle a dangerous operand ("rm -rf $(echo /)") behind a substitution the path
 *  checks would otherwise see as opaque. Any other inner command (mktemp, cat, ...) can't be proven
 *  from the text and resolves to null (treated as an unprovable value, not a literal). */
export function substLiteral(tok) {
  if (typeof tok !== "string") return null;
  const m = SUBST_LIT_TOKEN_RE.exec(tok.trim());
  if (!m) return null;
  const inner = (m[1] !== undefined ? m[1] : m[2]).trim();
  const ws = words(inner);
  if (!ws.length) return null;
  let toks = ws;
  if (toks[0] === "printf" && toks.length > 1) toks = toks.slice(1);
  if (toks[0] !== "echo") return null;
  const val = toks.slice(1).filter((t) => t !== "-n" && t !== "-e").join(" ");
  return val || null;
}

/** Shell-command-looking string literals inside an interpreter -c/-e payload: the operands of
 *  os.system/subprocess/exec/spawn/execSync/system/backtick/qx calls, plus perl's system qw(...)
 *  list joined back into a command line. Heuristic: only literals that look like a command line
 *  (a leading bare word followed by a space or a / path) qualify -- data strings never do. */
const STRING_LIT_RE2 = /'([^'\\]*(?:\\.[^'\\]*)*)'|"([^"\\]*(?:\\.[^"\\]*)*)"|`([^`\\]*(?:\\.[^`\\]*)*)`/g;
const SHELLISH_RE = /^[~.\/]|[A-Za-z0-9_][A-Za-z0-9_.\/-]*\s/;
function interpShellLiterals(script) {
  const out = [];
  for (const m of script.matchAll(STRING_LIT_RE2)) {
    const lit = (m[1] !== undefined ? m[1] : m[2] !== undefined ? m[2] : m[3] || "")
      .replace(/\\(['"\\`])/g, "$1");
    if (lit.length > 2 && lit.length < 4000 && SHELLISH_RE.test(lit)) out.push(lit);
  }
  for (const m of script.matchAll(/\bqw\s*[(\[{]\s*([^)\]}]+)\s*[)\]}]/g)) {
    const joined = m[1].trim().replace(/\s+/g, " ");
    if (SHELLISH_RE.test(joined)) out.push(joined);
  }
  return out;
}

// ── input-supplied scripts: heredocs and here-strings feeding an executor ────────────────────────────
// stripHeredocs drops a heredoc body as inert data -- correct when it lands in a file or a non-
// executor's stdin, but a `<<`-redirect onto a shell/interpreter/at/crontab makes the body a SCRIPT,
// literal text every rule should see the same as `bash -c '...'`'s operand.
/** Does a segment resolve to something that EXECUTES its stdin (or named operand) as a script?
 *  Covers `sh`, `bash -s`, an interpreter with no script argument, `at`/`batch` (the body IS the
 *  at-job's command list), `crontab` (body lines are cron entries: five fields then the command),
 *  `xargs`/`parallel`/`find -exec` whose invoked program is itself an executor (itemFed bodies get
 *  the same per-item ask the direct indirections get), and `ssh dest 'sh'` whose REMOTE command reads
 *  stdin. Returns {prog, itemFed, crontab} or null. */
function executorOf(prog, args) {
  if (prog === null) return null;
  const invoked = indirectInvokes(prog, args);
  if (invoked) {
    const [iprog, iargs] = invoked;
    if (SHELL_WRAPPER_PROGS.has(iprog) && scriptOf(iprog, iargs, { interp: false }) === null) {
      return { prog: iprog, itemFed: true, crontab: false };
    }
    if (interpBase(iprog) && !iargs.some((a) => !a.startsWith("-"))) {
      return { prog: iprog, itemFed: true, crontab: false };
    }
    const inner = scriptOf(iprog, iargs, { interp: false });
    if (inner) {
      const [p2] = programOf(inner);
      if (p2 && SHELL_WRAPPER_PROGS.has(p2)) return { prog: p2, itemFed: true, crontab: false };
    }
    return null;
  }
  if (SHELL_WRAPPER_PROGS.has(prog)) {
    if (scriptOf(prog, args, { interp: false }) !== null) return null; // sh -c: stdin is data
    const fileArg = args.some((a) => !a.startsWith("-"));
    return fileArg ? null : { prog, itemFed: false, crontab: false };
  }
  if (interpBase(prog) && interpScriptText(prog, args) === null &&
      !args.some((a) => !a.startsWith("-"))) {
    return { prog, itemFed: false, crontab: false };
  }
  if (prog === "at" || prog === "batch" || prog === "eval") return { prog, itemFed: false, crontab: false };
  if (prog === "crontab") return { prog, itemFed: false, crontab: true };
  if (prog === "ssh") {
    const remote = sshScript(args);
    if (!remote) return null;
    const [rp, ra] = programOf(remote);
    return executorOf(rp, ra);
  }
  return null;
}
/** Scan a line for the executor a heredoc/here-string on it feeds: checks EVERY stage of the line's
 *  pipelines, not just the first command (`cat <<EOF | sh` executes the body through the sh stage). */
function lineExecutor(line) {
  for (const pipeline of splitPipelines(stripRedirects(line))) {
    for (const stage of pipeline) {
      const [prog, args] = programOf(stage);
      const ex = executorOf(prog, args);
      if (ex) return ex;
    }
  }
  return null;
}
const HERESTRING_RE = /(?<!<)<<<\s*(?:'([^']*)'|"([^"]*)"|(\S+))/g;
const CRON_FIELD_RE = /^\s*\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+/;
/** Script bodies a heredoc or here-string feeds to an executor: [{body, itemFed, crontab}].
 *  `itemFed` marks xargs/parallel/find -exec-driven bodies (an rm -r inside one asks the way the
 *  direct indirection asks); `crontab` marks bodies whose lines need the 5-field cron prefix
 *  stripped to reach the command. */
export function inputScripts(command) {
  const out = [];
  if (!command) return out;
  const lines = String(command).split("\n");
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    const delims = heredocDelimiters(line);
    const hs = [];
    for (const m of line.matchAll(HERESTRING_RE)) {
      const v = m[1] !== undefined ? m[1] : m[2] !== undefined ? m[2] : m[3] || "";
      if (v.trim()) hs.push(v.trim());
    }
    const executor = (delims.length || hs.length) ? lineExecutor(line) : null;
    if (executor) for (const v of hs) out.push({ body: v, itemFed: executor.itemFed, crontab: executor.crontab });
    if (!delims.length) { i++; continue; }
    i++;
    for (const [delim, dashed] of delims) {
      const body = [];
      while (i < lines.length) {
        const l = lines[i]; i++;
        const probe = dashed ? l.replace(/^\t+/, "") : l;
        if (probe.replace(/\r+$/, "") === delim) break;
        body.push(l);
      }
      if (executor) out.push({ body: body.join("\n"), itemFed: executor.itemFed, crontab: executor.crontab });
    }
  }
  return out;
}
/** The command lines of a crontab body: each entry's five schedule fields stripped; comments, blank
 *  lines and VAR=val environment lines dropped. */
export function crontabCommands(body) {
  const out = [];
  for (const line of String(body || "").split("\n")) {
    if (!line.trim() || line.trim().startsWith("#")) continue;
    const m = CRON_FIELD_RE.exec(line);
    if (m) out.push(line.slice(m[0].length));
  }
  return out;
}

// ── path normalization (lexical only, no fs access) ──────────────────────────
/** Resolve `.`/`..` segments and duplicate slashes in a path, string-level only -- `path.posix.normalize`
 *  canonicalizes to `/` and `/dev/./sda` / `//dev/sda` to `/dev/sda` before any root/home/device-literal
 *  comparison runs, instead of a literal-string check that a dot-segment or doubled slash trivially dodges. */
export function normalizePath(p) {
  return p ? posixPath.normalize(p) : p;
}

// ── heredocs and comments ────────────────────────────────────────────────────
const HEREDOC_RE = /(?<!<)<<(-?)[ \t]*(?!<)(?:'([^']*)'|"([^"]*)"|((?:\\.|[^\s;&|<>()'"])+))/g;

function insideQuotes(text, index) {
  let quote = null;
  let escaped = false;
  for (let pos = 0; pos < text.length; pos++) {
    if (pos >= index) break;
    const c = text[pos];
    if (escaped) { escaped = false; continue; }
    if (c === "\\" && quote !== "'") { escaped = true; continue; }
    if (quote === null && (c === "'" || c === '"')) quote = c;
    else if (c === quote) quote = null;
  }
  return quote !== null;
}

function heredocDelimiters(line) {
  const found = [];
  for (const m of line.matchAll(HEREDOC_RE)) {
    if (insideQuotes(line, m.index)) continue;
    const delim = m[2] || m[3] || m[4];
    if (delim) found.push([delim, m[1] === "-"]);
  }
  return found;
}

/** Remove heredoc BODIES (data, not commands); keep the opening line. */
export function stripHeredocs(command) {
  if (!command || !command.includes("<<")) return command;
  const lines = String(command).split("\n");
  const kept = [];
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    kept.push(line);
    i++;
    for (const [delim, dashed] of heredocDelimiters(line)) {
      while (i < lines.length) {
        const body = lines[i];
        i++;
        const probe = dashed ? body.replace(/^\t+/, "") : body;
        if (probe.replace(/\r+$/, "") === delim) break;
      }
    }
  }
  return kept.join("\n");
}

/** Drop an unquoted trailing `# comment` (a `#` that starts a word). */
export function stripShellComment(command) {
  if (!command) return command;
  const out = [];
  let quote = null;
  let i = 0;
  const n = command.length;
  while (i < n) {
    const c = command[i];
    if (quote) {
      if (c === "\\" && quote === '"' && i + 1 < n) { out.push(c, command[i + 1]); i += 2; continue; }
      out.push(c);
      if (c === quote) quote = null;
      i++;
      continue;
    }
    if (c === "\\" && i + 1 < n) { out.push(c, command[i + 1]); i += 2; continue; }
    if (c === "'" || c === '"') { quote = c; out.push(c); i++; continue; }
    if (c === "#" && (out.length === 0 || /\s/.test(out[out.length - 1]))) {
      const nl = command.indexOf("\n", i);
      if (nl === -1) break;
      i = nl;
      continue;
    }
    out.push(c);
    i++;
  }
  return out.join("");
}

const QUOTED_RE = /'[^']*'|"(?:[^"\\]|\\.)*"/g;
const ESCAPED_RE = /\\./g;
/** The command with everything bash would not run as syntax blanked out. */
export function shellCodeOnly(command) {
  let text = stripShellComment(stripHeredocs(command));
  text = text.split("\n").map((l) => stripShellComment(l)).join("\n");
  return text.replace(ESCAPED_RE, "_").replace(QUOTED_RE, '""');
}

const SUBST_RE = /\$\(([^()]*)\)|`([^`]*)`|<\(([^()]*)\)|>\(([^()]*)\)/g;
/** Segments of every `$(...)` / backtick substitution (an assignment's value is skipped). */
export function substitutedSegments(command) {
  const out = [];
  try {
    const cmd = stripHeredocs(command);
    for (const m of cmd.matchAll(SUBST_RE)) {
      const before = splitSegments(cmd.slice(0, m.index));
      const toks = before.length ? words(before[before.length - 1]) : [];
      if (toks.length && toks.every((t) => ASSIGN_RE.test(t) || ["export", "local", "readonly", "declare", "typeset"].includes(t))) continue;
      // <(cmd)/>(cmd) process substitution: the inner command line is literal text that runs
      // (diff <(cat ~/.env) really executes cat on the secret) -- extracted like $(...) since it IS
      // executed code, unlike the opaque data a substitution PRODUCES at runtime.
      let inner = m[1] !== undefined ? m[1] : m[2] !== undefined ? m[2] : (m[3] !== undefined ? m[3] : m[4]);
      if (inner.startsWith("<")) inner = "cat " + inner.slice(1);
      out.push(...splitSegments(inner));
    }
  } catch { return []; }
  return out;
}

/** `~`-normalise a path. `home` is optional: with it, absolute home paths are recognised too. */
export function expand(path, home) {
  let p = path || "";
  p = p.replace(/^\$\{HOME\}|^\$HOME/, "~");
  if (home && (p === home || p.startsWith(home + "/"))) p = "~" + p.slice(home.length);
  return p;
}

export function firstPositional(args, valueOpts) {
  let i = 0;
  while (i < args.length) {
    const a = args[i];
    if (a.startsWith("-")) { i += valueOpts.has(a) ? 2 : 1; continue; }
    return i;
  }
  return null;
}

// ── redaction (jev-belay SECRET_RULES) ───────────────────────────────────────
const REDACTED = "<redacted>";
const SECRET_RULES = [
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, REDACTED],
  [/(authorization\s*[:=]\s*)(?:basic|bearer|token)?\s*\S+/gi, `$1${REDACTED}`],
  [/\b(bearer\s+)[\w.-]{16,}/gi, `$1${REDACTED}`],
  // name-based: anything ending in key/pass/pwd/auth/cookie/session/signature/token/secret, plus the classic words;
  // a quoted value runs to the closing quote (multi-word passphrases), an unquoted one to the next delimiter.
  [/((?:\b[a-z0-9_-]{0,64}(?:api[_-]?key|apikey|access[_-]?key|secret[_-]?key|client[_-]?secret|private[_-]?key|passw(?:or)?d|passphrase|credentials?|_key|_pass|_pwd|_auth|_cookie|_session|_signature|token|secret)[a-z0-9_-]{0,64})["']?\s*[=:]\s*)("([^"]*)"|'([^']*)'|[^\s"'&;]+)/gi, `$1${REDACTED}`],
  // CLI option values, scoped to avoid eating -p/-u on unrelated programs (mkdir -p, cp -p, scp -p, ssh -p,
  // docker -p, sort -u, git push -u, psql/redis-cli -p are a port or a flag, not a secret):
  // --password x, --token x, --api-key x, --secret x, --auth x (any program); -u/--user only for a user:pass shape;
  // -p as a password only for the few CLIs where -p truly means password (mysql family, mongosh, sshpass, smbclient).
  [/((?:^|\s)(?:--password|--passwd|--token|--api-key|--secret|--auth)\s+)(\S+)/gi, `$1${REDACTED}`],
  [/((?:^|\s)(?:-u|--user|--username)\s+)(\S+:\S+)/gi, `$1${REDACTED}`],
  [/(\b(?:mysql|mariadb|mysqldump|mongosh|sshpass|smbclient)\b[^|;&\n]*?\s-p\s*)(\S+)/gi, `$1${REDACTED}`],
  [/((?:aws_)?secret_access_key\s+)(\S+)/gi, `$1${REDACTED}`],
  [/\b([a-z][a-z0-9+.-]{0,63}:\/\/)[^\s/@:]*:[^\s/@]+@/gi, `$1${REDACTED}@`],
  [/\bsk-[A-Za-z0-9_-]{8,}/g, REDACTED],
  [/\bapikey_[A-Za-z0-9_]+/g, REDACTED],
  [/\b[sr]k_(?:live|test)_[A-Za-z0-9]{10,}/g, REDACTED],
  [/\bnpm_[A-Za-z0-9]{30,}/g, REDACTED],
  [/\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}/g, REDACTED],
  [/\bgithub_pat_[A-Za-z0-9_]{20,}/g, REDACTED],
  [/\bAKIA[0-9A-Z]{16}\b/g, REDACTED],
  [/\bxox[abprs]-[A-Za-z0-9-]{10,}/g, REDACTED],
  [/\bAIza[0-9A-Za-z_-]{30,}/g, REDACTED],
  [/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, REDACTED],
];

/** Scrub credentials before anything is sent to Jev. Never throws; over-redacts on failure. */
export function redact(text) {
  if (typeof text !== "string") return "";
  try {
    let out = text;
    for (const [re, rep] of SECRET_RULES) out = out.replace(re, rep);
    return out;
  } catch { return REDACTED; }
}

/** Redact first, truncate second, so a secret straddling the cut is not half-leaked. */
export const redactCap = (text, limit) => redact(text).slice(0, limit);

// ── pipeline-aware segment grouping (for curl|sh and secret-exfiltration detection) ────────────
/** Like splitSegments, but keeps segments joined by a bare `|` together as one pipeline, instead of
 *  flattening everything the way splitSegments does. A run of `&`, `&&`, `||` or `;` starts a new
 *  pipeline (same ambiguity as splitSegments on `2>&1`-style redirects: callers that care should run
 *  stripRedirects() first). Each returned pipeline is a non-empty array of >=1 segment strings. */
export function splitPipelines(command) {
  const pipelines = [];
  let segs = [];
  let buf = [];
  let quote = null;
  const s = (command || "").replace(/\\\r?\n/g, "");
  const n = s.length;
  let i = 0;
  const flushSeg = () => { const t = buf.join("").trim(); if (t) segs.push(t); buf = []; };
  const flushPipeline = () => { flushSeg(); if (segs.length) pipelines.push(segs); segs = []; };
  while (i < n) {
    const ch = s[i];
    if (quote) {
      if (ch === "\\" && quote === '"' && i + 1 < n) { buf.push(ch, s[i + 1]); i += 2; continue; }
      buf.push(ch); if (ch === quote) quote = null; i++; continue;
    }
    if (ch === "'" || ch === '"') { quote = ch; buf.push(ch); i++; continue; }
    if (ch === "\\" && i + 1 < n) { buf.push(ch, s[i + 1]); i += 2; continue; }
    if (ch === ";" || ch === "\n") { flushPipeline(); i++; continue; }
    if (ch === "&" || ch === "|") {
      let j = i;
      while (j < n && (s[j] === "&" || s[j] === "|")) j++;
      const run = s.slice(i, j);
      if (run === "|") { flushSeg(); i = j; continue; } // a single bare pipe: stay in this pipeline
      flushPipeline(); i = j; continue; // &&, ||, & (or anything mixed): a new pipeline
    }
    buf.push(ch); i++;
  }
  flushPipeline();
  return pipelines;
}

// a leading digit is an fd number (2>&1, 2>/dev/null); the target after >/>>/< is a single word
const REDIRECT_RE = /\d*(?:>{1,2}&\d+|>{1,2}\S*|<{1,2}\S*)/g;
/** Blank out shell redirects (`>out`, `>>log`, `2>&1`, `</dev/null`, ...) so a trailing redirect after a
 *  piped command doesn't break program-name matching. Heuristic text substitution, not parsing: scoped to
 *  callers that specifically need redirect-free text (curl|sh / secret-exfiltration detection), not applied
 *  globally to every rule. */
export function stripRedirects(text) {
  return (text || "").replace(REDIRECT_RE, " ");
}
