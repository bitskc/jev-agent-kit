// safere.mjs — a bounded, backtracking-free regex tester for untrusted patterns.
// The guard probes a grep pattern against a fixed list of short sample strings to decide whether the
// pattern selects secret assignment lines. Running `new RegExp(userInput)` on the pattern makes a hostile
// nested quantifier (`(a|a)*$`-style) catastrophic on the engine's backtracker, and the hook's timeout
// then fails the guard open. This module compiles the pattern to a Thompson NFA and simulates it by
// subset construction: work is O(pattern-states x sample-length), never exponential.
// Supported: literals, `.`, character classes (ranges, negation, \d\w\s class escapes), alternation,
// capturing and non-capturing groups, `*`/`+`/`?`/`{m,n}` (lazy suffixes read as greedy — only
// match/no-match is ever asked), anchors `^` `$` `\b` `\B`, `(?i:`/`(?m:`/`(?s:` scoped flag groups,
// and lookahead/lookbehind via bounded sub-simulation. Unsupported but valid syntax (e.g. backreferences)
// and patterns over MAX_PATTERN_LEN or MAX_STATES return unknown, which the caller treats conservatively
// as possibly selecting a credential assignment. Invalid regex syntax returns no-match.

const MAX_PATTERN_LEN = 512;
const MAX_STATES = 16384;
const MAX_REPEAT = 1000;

const WORD = /[A-Za-z0-9_]/;

class ReSyntax extends Error {
  constructor(message, unsupported = false) { super(message); this.unsupported = unsupported; }
}

// ── parser → AST ────────────────────────────────────────────────────────────
// {t:'lit',c,ci} {t:'class',neg,ci,items:[lo,hi] pairs or predicates} {t:'any',nl}
// {t:'cat',xs} {t:'alt',xs} {t:'rep',x,min,max} {t:'anchor',k:'start'|'end'|'wb'|'nwb'}
// {t:'look',neg,ahead,x,ci}
function parse(src) {
  let i = 0;
  const peek = () => src[i];
  const take = () => src[i++];
  const err = (m, unsupported = false) => { throw new ReSyntax(m, unsupported); };

  const CLASS_ESCAPES = {
    d: (ch) => ch >= "0" && ch <= "9",
    w: (ch) => WORD.test(ch),
    s: (ch) => /\s/.test(ch),
  };
  function clsEscape() { // inside [...]: a class-escape predicate or {lit}
    const c = take();
    if (CLASS_ESCAPES[c]) return { p: CLASS_ESCAPES[c] };
    if (CLASS_ESCAPES[c.toLowerCase()]) return { p: (ch) => !CLASS_ESCAPES[c.toLowerCase()](ch) };
    switch (c) {
      case "n": return { lit: "\n" };
      case "t": return { lit: "\t" };
      case "r": return { lit: "\r" };
      case "f": return { lit: "\f" };
      case "v": return { lit: "\v" };
      case "0": return { lit: "\0" };
      case "b": return { lit: "\b" }; // inside a class, \b is the backspace character
      case "x": { const h = src.slice(i, i + 2); if (!/^[0-9a-fA-F]{2}$/.test(h)) err("\\x"); i += 2; return { lit: String.fromCharCode(parseInt(h, 16)) }; }
      case "u": {
        if (peek() === "{") { take(); const j = src.indexOf("}", i); if (j < 0 || !/^[0-9a-fA-F]+$/.test(src.slice(i, j))) err("\\u{"); const cp = parseInt(src.slice(i, j), 16); i = j + 1; return { lit: String.fromCodePoint(cp) }; }
        const h = src.slice(i, i + 4); if (!/^[0-9a-fA-F]{4}$/.test(h)) err("\\u"); i += 4; return { lit: String.fromCharCode(parseInt(h, 16)) };
      }
      case "c": { const l = take(); if (l === undefined || !/[a-zA-Z]/.test(l)) err("\\c"); return { lit: String.fromCharCode(l.toUpperCase().charCodeAt(0) % 32) }; }
      default: return { lit: c };
    }
  }
  function atomEscape(flags) { // outside [...]
    const c = take();
    if (CLASS_ESCAPES[c]) return { t: "class", neg: false, ci: flags.i, items: [CLASS_ESCAPES[c]] };
    if (CLASS_ESCAPES[c.toLowerCase()]) return { t: "class", neg: false, ci: flags.i, items: [(ch) => !CLASS_ESCAPES[c.toLowerCase()](ch)] };
    switch (c) {
      case "n": return { t: "lit", c: "\n", ci: flags.i };
      case "t": return { t: "lit", c: "\t", ci: flags.i };
      case "r": return { t: "lit", c: "\r", ci: flags.i };
      case "f": return { t: "lit", c: "\f", ci: flags.i };
      case "v": return { t: "lit", c: "\v", ci: flags.i };
      case "0": return { t: "lit", c: "\0", ci: flags.i };
      case "b": return { t: "anchor", k: "wb" };
      case "B": return { t: "anchor", k: "nwb" };
      case "x": { const h = src.slice(i, i + 2); if (!/^[0-9a-fA-F]{2}$/.test(h)) err("\\x"); i += 2; return { t: "lit", c: String.fromCharCode(parseInt(h, 16)), ci: flags.i }; }
      case "u": {
        if (peek() === "{") { take(); const j = src.indexOf("}", i); if (j < 0 || !/^[0-9a-fA-F]+$/.test(src.slice(i, j))) err("\\u{"); const cp = parseInt(src.slice(i, j), 16); i = j + 1; return { t: "lit", c: String.fromCodePoint(cp), ci: flags.i }; }
        const h = src.slice(i, i + 4); if (!/^[0-9a-fA-F]{4}$/.test(h)) err("\\u"); i += 4; return { t: "lit", c: String.fromCharCode(parseInt(h, 16)), ci: flags.i };
      }
      case "c": { const l = take(); if (l === undefined || !/[a-zA-Z]/.test(l)) err("\\c"); return { t: "lit", c: String.fromCharCode(l.toUpperCase().charCodeAt(0) % 32), ci: flags.i }; }
      default:
        if (/[1-9]/.test(c)) err("backreference", true); // valid syntax, unsupported by an NFA
        return { t: "lit", c, ci: flags.i };
    }
  }
  function parseClass(flags) {
    const neg = peek() === "^" ? (take(), true) : false;
    const items = [];
    // In JS `[]` is a valid empty class (never matches) and `[^]` matches anything: a `]` in first
    // position CLOSES the class. Only `-` is literal at the edges.
    while (i < src.length && peek() !== "]") {
      let lo;
      if (peek() === "\\") { take(); const e = clsEscape(); if (e.p) { items.push(e.p); continue; } lo = e.lit; }
      else lo = take();
      if (lo === "-") { items.push([lo, lo]); continue; }
      if (peek() === "-" && src[i + 1] !== "]") {
        take();
        let hi;
        if (peek() === "\\") { take(); const e = clsEscape(); if (e.p) { items.push([lo, lo], e.p); continue; } hi = e.lit; }
        else hi = take();
        if (lo > hi) err("range");
        items.push([lo, hi]);
      } else items.push([lo, lo]);
    }
    if (peek() !== "]") err("unclosed class");
    take();
    return { t: "class", neg, ci: flags.i, items };
  }
  function repeatBounds() { // {m} {m,} {m,n} after an atom; null = not a quantifier (literal '{')
    const save = i;
    take(); // '{'
    const m = /^\d+/.exec(src.slice(i));
    if (!m) { i = save; return null; }
    i += m[0].length;
    const min = parseInt(m[0], 10);
    let max = min;
    if (peek() === ",") {
      take();
      if (peek() === "}") max = Infinity;
      else { const n = /^\d+/.exec(src.slice(i)); if (!n) { i = save; return null; } i += n[0].length; max = parseInt(n[0], 10); }
    }
    if (peek() !== "}") { i = save; return null; }
    take();
    if (max !== Infinity && max < min) err("{n,m}");
    if (min > MAX_REPEAT || (max !== Infinity && max > MAX_REPEAT)) err("repeat too large", true);
    return [min, max];
  }
  function atom(flags) {
    const c = take();
    if (c === undefined) err("empty atom");
    switch (c) {
      case "(": {
        if (src[i] === "?") {
          const k1 = src[i + 1];
          if (k1 === ":" || k1 === "=" || k1 === "!") {
            i += 2;
            const body = alt(flags);
            if (take() !== ")") err("unclosed group");
            if (k1 === ":") return body;
            return { t: "look", neg: k1 === "!", ahead: true, x: body, ci: flags.i };
          }
          if (k1 === "<") {
            if (src[i + 2] !== "=" && src[i + 2] !== "!") err("named group", true);
            const neg = src[i + 2] === "!";
            i += 3;
            const body = alt(flags);
            if (take() !== ")") err("unclosed group");
            return { t: "look", neg, ahead: false, x: body, ci: flags.i };
          }
          // (?flags:...) — scoped i/m/s flags
          {
            let j = i + 1;
            const nf = { ...flags };
            while (/[ims]/.test(src[j])) { nf[src[j]] = true; j++; }
            if (src[j] === ":") { i = j + 1; const body = alt(nf); if (take() !== ")") err("unclosed group"); return body; }
          }
          err("unsupported group", true); // valid/unknown group syntax is conservatively flagged
        }
        const body = alt(flags);
        if (take() !== ")") err("unclosed group");
        return body;
      }
      case "[": return parseClass(flags);
      case ".": return { t: "any", nl: flags.s };
      case "^": return { t: "anchor", k: "start" };
      case "$": return { t: "anchor", k: "end" };
      case "\\": return atomEscape(flags);
      case "*": case "+": case "?": case ")": err(`dangling ${c}`);
      default: return { t: "lit", c, ci: flags.i };
    }
  }
  function piece(flags) {
    let a = atom(flags);
    for (;;) {
      const c = peek();
      let min = null, max = null;
      if (c === "*") { min = 0; max = Infinity; take(); }
      else if (c === "+") { min = 1; max = Infinity; take(); }
      else if (c === "?") { min = 0; max = 1; take(); }
      else if (c === "{") { const b = repeatBounds(); if (b) [min, max] = b; }
      if (min === null) return a;
      if (peek() === "?") take(); // lazy: same match set, and only the set matters
      a = { t: "rep", x: a, min, max };
    }
  }
  function seq(flags) {
    const xs = [];
    while (i < src.length && peek() !== "|" && peek() !== ")") xs.push(piece(flags));
    return xs.length === 1 ? xs[0] : { t: "cat", xs };
  }
  function alt(flags) {
    const xs = [seq(flags)];
    while (peek() === "|") { take(); xs.push(seq(flags)); }
    return xs.length === 1 ? xs[0] : { t: "alt", xs };
  }
  const body = alt({ i: false, m: false, s: false });
  if (i < src.length) err("trailing");
  return body;
}

// ── compiler → NFA ──────────────────────────────────────────────────────────
// {kind:'lit',c,ci,out} {kind:'class',f,out} {kind:'any',nl,out} {kind:'eps',out}
// {kind:'split',a,b} {kind:'pred',k,sub,subStates,out} {kind:'match'}
function compile(ast) {
  const states = [];
  const add = (s) => { if (states.length >= MAX_STATES) throw new ReSyntax("too many states", true); states.push(s); return s; };
  const patch = (outs, target) => { for (const o of outs) o.st[o.f] = target; };
  // returns {start, outs:[{st,f}]} — outs are dangling arrow fields to patch
  function build(n) {
    switch (n.t) {
      case "cat": {
        if (n.xs.length === 0) { const s = add({ kind: "eps", out: null }); return { start: s, outs: [{ st: s, f: "out" }] }; }
        let start = null; let pending = [];
        for (const x of n.xs) {
          const f = build(x);
          if (start === null) start = f.start; else patch(pending, f.start);
          pending = f.outs;
        }
        return { start, outs: pending };
      }
      case "lit": {
        const s = add({ kind: "lit", c: n.ci ? n.c.toLowerCase() : n.c, ci: n.ci, out: null });
        return { start: s, outs: [{ st: s, f: "out" }] };
      }
      case "class": {
        const ci = n.ci, neg = n.neg, items = n.items;
        const f = (ch) => {
          const c = ci ? ch.toLowerCase() : ch;
          let m = false;
          for (const it of items) {
            if (typeof it === "function") { if (it(ch)) { m = true; break; } }
            else { const lo = ci ? it[0].toLowerCase() : it[0], hi = ci ? it[1].toLowerCase() : it[1]; if (c >= lo && c <= hi) { m = true; break; } }
          }
          return m !== neg;
        };
        const s = add({ kind: "class", f, out: null });
        return { start: s, outs: [{ st: s, f: "out" }] };
      }
      case "any": {
        const s = add({ kind: "any", nl: n.nl, out: null });
        return { start: s, outs: [{ st: s, f: "out" }] };
      }
      case "alt": {
        const heads = [];
        let outs = [];
        for (const x of n.xs) { const f = build(x); heads.push(f.start); outs = outs.concat(f.outs); }
        // split chain: s1{a:h1,b:s2}, s2{a:h2,b:s3}, ..., last{a:h(k-1),b:hk}
        if (heads.length === 1) return { start: heads[0], outs };
        const splits = [];
        for (let k = 0; k < heads.length - 1; k++) splits.push(add({ kind: "split", a: null, b: null }));
        for (let k = 0; k < splits.length; k++) {
          splits[k].a = heads[k];
          splits[k].b = k + 1 < splits.length ? splits[k + 1] : heads[heads.length - 1];
        }
        return { start: splits[0], outs };
      }
      case "rep": {
        const { min, max } = n;
        let start = null; let pending = [];
        const concatFrag = (f) => { if (start === null) start = f.start; else patch(pending, f.start); pending = f.outs; };
        for (let k = 0; k < min; k++) concatFrag(build(n.x));
        if (max === Infinity) {
          const sp = add({ kind: "split", a: null, b: null });
          concatFrag({ start: sp, outs: [{ st: sp, f: "b" }] });
          const f = build(n.x);
          sp.a = f.start;
          patch(f.outs, sp);
        } else {
          for (let k = min; k < max; k++) {
            const sp = add({ kind: "split", a: null, b: null });
            const f = build(n.x);
            sp.a = f.start;
            // both the sub-match's end and the skipped path continue
            if (start === null) start = sp; else patch(pending, sp);
            pending = f.outs.concat([{ st: sp, f: "b" }]);
          }
        }
        if (start === null) { const s = add({ kind: "eps", out: null }); return { start: s, outs: [{ st: s, f: "out" }] }; }
        return { start, outs: pending };
      }
      case "anchor": {
        const s = add({ kind: "pred", k: n.k, out: null });
        return { start: s, outs: [{ st: s, f: "out" }] };
      }
      case "look": {
        const inner = compile(n.x);
        const s = add({ kind: "pred", k: n.ahead ? (n.neg ? "nla" : "la") : (n.neg ? "nlb" : "lb"), sub: inner.start, subStates: inner.states, out: null });
        states.push(...inner.states); // inner states count against the same cap
        if (states.length > MAX_STATES) throw new ReSyntax("too many states", true);
        return { start: s, outs: [{ st: s, f: "out" }] };
      }
    }
    throw new ReSyntax("node");
  }
  const f = build(ast);
  const m = add({ kind: "match" });
  patch(f.outs, m);
  return { start: f.start, states };
}

// ── simulation ──────────────────────────────────────────────────────────────
// epsilon/predicate closure, iterative. Lookaround predicates run a bounded sub-simulation and are
// memoized per (pred state, position) inside predMemo.
function closure(list, text, pos, set, predMemo) {
  const stack = [...list];
  while (stack.length) {
    const s = stack.pop();
    if (set.has(s)) continue;
    set.add(s);
    switch (s.kind) {
      case "split": stack.push(s.a, s.b); break;
      case "eps": stack.push(s.out); break;
      case "pred": {
        let ok;
        switch (s.k) {
          case "start": ok = pos === 0; break;
          case "end": ok = pos === text.length; break;
          case "wb": ok = (pos > 0 && WORD.test(text[pos - 1])) !== (pos < text.length && WORD.test(text[pos])); break;
          case "nwb": ok = (pos > 0 && WORD.test(text[pos - 1])) === (pos < text.length && WORD.test(text[pos])); break;
          default: { // la / nla / lb / nlb
            let rec = predMemo.get(s);
            if (!rec) { rec = new Map(); predMemo.set(s, rec); }
            if (!rec.has(pos)) rec.set(pos, lookResult(s, text, pos));
            ok = rec.get(pos);
          }
        }
        if (ok) stack.push(s.out);
        break;
      }
    }
  }
}
function stepConsume(set, ch) {
  const move = [];
  for (const s of set) {
    if (s.kind === "lit" && (s.ci ? s.c === ch.toLowerCase() : s.c === ch)) move.push(s.out);
    else if (s.kind === "class" && s.f(ch)) move.push(s.out);
    else if (s.kind === "any" && (s.nl || ch !== "\n")) move.push(s.out);
  }
  return move;
}
// Does the lookaround sub-automaton hold at pos?
//   la:  some match starts at pos (consuming forward; may consume zero chars)
//   nla: no match starts at pos
//   lb:  some match ends exactly at pos
//   nlb: no match ends exactly at pos
function lookResult(pred, text, pos) {
  const predMemo = new Map();
  const starts = [pred.sub];
  if (pred.k === "la" || pred.k === "nla") {
    let set = new Set();
    closure(starts, text, pos, set, predMemo);
    for (let p = pos; ; p++) {
      for (const s of set) if (s.kind === "match") return pred.k === "la";
      if (p >= text.length) break;
      const move = stepConsume(set, text[p]);
      if (!move.length) break;
      const next = new Set();
      closure(move, text, p + 1, next, predMemo);
      set = next;
    }
    return pred.k === "nla";
  }
  // behind: unanchored match over text[0..pos] that accepts ending exactly at pos
  let set = new Set();
  closure([pred.sub], text, 0, set, predMemo); // an attempt may begin at position 0
  for (let p = 0; p <= pos; p++) {
    for (const s of set) if (s.kind === "match") return pred.k === "lb";
    if (p === pos) break;
    const move = stepConsume(set, text[p]);
    move.push(pred.sub); // a new attempt may begin at every position
    const next = new Set();
    closure(move, text, p + 1, next, predMemo);
    set = next;
  }
  for (const s of set) if (s.kind === "match") return pred.k === "lb";
  return pred.k === "nlb";
}

/** test(pattern, text): does `pattern` match a substring of `text` — RegExp.prototype.test semantics
 *  without the backtracker. Returns null for valid but unsupported/over-budget patterns and false
 *  for syntax errors; callers must not silently allow the null case. Never throws on user input. */
export function safeRegexTest(pattern, text) {
  if (typeof pattern !== "string") return false;
  if (pattern.length > MAX_PATTERN_LEN) return null;
  let nfa;
  try { nfa = compile(parse(pattern)); }
  catch (e) { return e instanceof ReSyntax ? (e.unsupported ? null : false) : null; }
  const predMemo = new Map();
  // Inject a fresh start state at each input position instead of re-running a search from every
  // possible start. That preserves unanchored RegExp.test semantics while keeping work linear in
  // sample length times NFA state count.
  let set = new Set();
  closure([nfa.start], text, 0, set, predMemo);
  for (let pos = 0; ; pos++) {
    for (const s of set) if (s.kind === "match") return true;
    if (pos >= text.length) break;
    const move = stepConsume(set, text[pos]);
    move.push(nfa.start);
    const next = new Set();
    closure(move, text, pos + 1, next, predMemo);
    set = next;
  }
  return false;
}
