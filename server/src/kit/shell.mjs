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
  const s = command || "";
  const n = s.length;
  let i = 0;
  while (i < n) {
    const ch = s[i];
    if (quote) {
      buf.push(ch);
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
  let inWord = false;
  const s = segment || "";
  const n = s.length;
  for (let i = 0; i < n; i++) {
    const ch = s[i];
    if (quote) {
      if (ch === quote) { quote = null; continue; }
      buf += ch; inWord = true;
      continue;
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

const SKIP_PREFIX = new Set(["nice", "time", "command", "exec", "builtin", "stdbuf", "nohup", "ionice"]);
const VALUE_WRAPPERS = new Set(["env", "timeout"]);
const ENV_VALUE_OPTS = new Set(["-u", "--unset", "-C", "--chdir", "-S", "--split-string"]);
const TIMEOUT_VALUE_OPTS = new Set(["-s", "--signal", "-k", "--kill-after"]);
const base = (p) => p.slice(p.lastIndexOf("/") + 1);

function wrappedCommand(toks) {
  const wrapper = base(toks[0]);
  let i = 1;
  const valueOpts = wrapper === "env" ? ENV_VALUE_OPTS : TIMEOUT_VALUE_OPTS;
  while (i < toks.length) {
    const t = toks[i];
    if (t === "--") { i++; break; }
    if (t.startsWith("-") && t.length > 1) { i += valueOpts.has(t) ? 2 : 1; continue; }
    if (wrapper === "env" && ASSIGN_RE.test(t)) { i++; continue; }
    break;
  }
  if (wrapper === "timeout") i++;
  const rest = toks.slice(i);
  return rest.length ? rest : null;
}

/** First real command word of a segment, past VAR=val and wrappers. Returns [program, args]. */
export function programOf(segment) {
  let toks = words(segment);
  while (toks.length) {
    if (ASSIGN_RE.test(toks[0])) { toks = toks.slice(1); continue; }
    if (VALUE_WRAPPERS.has(base(toks[0]))) {
      const rest = wrappedCommand(toks);
      if (rest === null) break;
      toks = rest;
      continue;
    }
    if (SKIP_PREFIX.has(toks[0])) {
      toks = toks.slice(1);
      while (toks.length && toks[0].startsWith("-")) {
        const flag = toks[0];
        toks = toks.slice(1);
        if (["-n", "-p", "-o", "-e", "-i"].includes(flag) && toks.length && !toks[0].startsWith("-")) {
          if (/^[+-]*\d+$/.test(toks[0])) toks = toks.slice(1);
        }
      }
      continue;
    }
    break;
  }
  if (!toks.length) return [null, []];
  return [base(toks[0]), toks.slice(1)];
}

// ── wrapper unwrap: bash -c/sh -c/eval/xargs, one shared implementation every rule routes through ───────
export const SHELL_WRAPPER_PROGS = new Set(["sh", "bash", "dash", "zsh", "ksh"]);
const SHELL_WRAPPER_VALUE_OPTS = new Set(["-o", "+o", "-O", "+O", "--rcfile", "--init-file"]);
const XARGS_VALUE_OPTS = new Set(["-a", "-d", "-E", "-I", "-L", "-n", "-P", "-s",
  "--arg-file", "--delimiter", "--max-args", "--max-procs", "--max-chars", "--process-slot-var"]);
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
  return args.slice(i).join(" ").trim().replace(/^['"]+|['"]+$/g, "");
}
/** The real [program, args] a `xargs ...` invocation runs, same unwrap readerBehind() in guard.mjs already
 *  does for secret-read detection, duplicated here (guard.mjs can't be imported from shell.mjs) so the
 *  wrapper-expansion below also sees through `xargs -I{} bash -c 'rm -rf {}'`-style indirection. */
function xargsInvokes(prog, args) {
  if (prog !== "xargs") return null;
  const i = firstPositional(args, XARGS_VALUE_OPTS);
  return i === null ? null : [base(args[i]), args.slice(i + 1)];
}
/** Every shell-script body reachable by peeling off a `bash -c`/`sh -c`/`eval`/`xargs ... <real command>`
 *  wrapper around any of `segments`, recursively, up to `maxDepth` levels -- raw, unsplit text, so a caller
 *  needing pipeline structure (splitPipelines) or per-segment matching (splitSegments) parses it whichever
 *  way it needs. `programOf` already strips env/timeout/nice/nohup/command/builtin/stdbuf/sudo-less prefix
 *  wrappers on its own, so only an actual -c body or an `eval`/`xargs` layer needs handling here. Returns
 *  only the NEWLY found script bodies, not the original segments (callers already have those). */
export function unwrapScripts(segments, maxDepth = 3) {
  const out = [];
  const walk = (segs, depth) => {
    if (depth >= maxDepth) return;
    for (const seg of segs) {
      let [prog, args] = programOf(seg);
      if (prog === null) continue;
      const invoked = xargsInvokes(prog, args);
      if (invoked) [prog, args] = invoked;
      const script = prog === "eval" ? (args.length ? args.join(" ") : null)
        : SHELL_WRAPPER_PROGS.has(prog) ? shellDashCScript(args) : null;
      if (!script) continue;
      out.push(script);
      walk(splitSegments(stripHeredocs(script)), depth + 1);
    }
  };
  walk(segments, 0);
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

const SUBST_RE = /\$\(([^()]*)\)|`([^`]*)`/g;
/** Segments of every `$(...)` / backtick substitution (an assignment's value is skipped). */
export function substitutedSegments(command) {
  const out = [];
  try {
    const cmd = stripHeredocs(command);
    for (const m of cmd.matchAll(SUBST_RE)) {
      const before = splitSegments(cmd.slice(0, m.index));
      const toks = before.length ? words(before[before.length - 1]) : [];
      if (toks.length && toks.every((t) => ASSIGN_RE.test(t) || ["export", "local", "readonly", "declare", "typeset"].includes(t))) continue;
      let inner = m[1] !== undefined ? m[1] : m[2];
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
  const s = command || "";
  const n = s.length;
  let i = 0;
  const flushSeg = () => { const t = buf.join("").trim(); if (t) segs.push(t); buf = []; };
  const flushPipeline = () => { flushSeg(); if (segs.length) pipelines.push(segs); segs = []; };
  while (i < n) {
    const ch = s[i];
    if (quote) { buf.push(ch); if (ch === quote) quote = null; i++; continue; }
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
