// Shell-text helpers for the kit_* tools.
//
// Ported from jonathanavis96/jev-kit (MIT, Copyright (c) 2026 Jonathan Avis):
//   airlock/rules.py   split_segments, words, program_of, _wrapped_command
//   airlock/scope.py   strip_heredocs, strip_shell_comment
//   airlock/redact.py  (replaced by the jev-belay redactor below)
// Redactor adapted from valentynkit/jev-belay belay.mjs (MIT, Copyright (c) 2026 Valentyn Kit).
// See NOTICE-jev-kit.md. Everything here is pure string work: no I/O, never throws.

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

/** Whitespace tokens of a segment, matching quotes stripped off the ends. */
export function words(segment) {
  const out = [];
  for (let tok of (segment || "").split(/\s+/).filter(Boolean)) {
    if (tok.length >= 2 && tok[0] === tok[tok.length - 1] && (tok[0] === "'" || tok[0] === '"')) tok = tok.slice(1, -1);
    out.push(tok);
  }
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
  [/((?:\b[a-z0-9_-]*(?:api[_-]?key|apikey|access[_-]?key|secret[_-]?key|client[_-]?secret|private[_-]?key|passw(?:or)?d|passphrase|credentials?|_key|_pass|_pwd|_auth|_cookie|_session|_signature|token|secret)[a-z0-9_-]*)["']?\s*[=:]\s*)("([^"]*)"|'([^']*)'|[^\s"'&;]+)/gi, `$1${REDACTED}`],
  // CLI option values: -u user:pass, --password x, -p x, --token x, aws ... secret_access_key x
  [/((?:^|\s)(?:-u|--user|--username|-p|--password|--passwd|--token|--api-key|--secret|--auth)\s+)(\S+)/gi, `$1${REDACTED}`],
  [/((?:aws_)?secret_access_key\s+)(\S+)/gi, `$1${REDACTED}`],
  [/\b([a-z][a-z0-9+.-]*:\/\/)[^\s/@:]*:[^\s/@]+@/gi, `$1${REDACTED}@`],
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
