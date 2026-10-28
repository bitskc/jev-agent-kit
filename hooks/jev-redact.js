// Ported from server/src/kit/shell.mjs's redact()/redactCap() (in turn adapted from valentynkit/jev-belay
// belay.mjs, MIT — see server/NOTICE-jev-kit.md). Not imported directly: the server is a separate
// Cloudflare Worker package (ESM, its own deps); hooks stay zero-dependency plain Node (CommonJS). This
// is a byte-for-byte copy of SECRET_RULES/redact/redactCap — keep it in sync by hand. Drift is caught by
// hooks/jev-stop-verify.test.mjs's dedicated test, which runs the server's own redact-test strings through
// BOTH copies and fails if they ever disagree.
'use strict';

const REDACTED = '<redacted>';
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
function redact(text) {
  if (typeof text !== 'string') return '';
  try {
    let out = text;
    for (const [re, rep] of SECRET_RULES) out = out.replace(re, rep);
    return out;
  } catch { return REDACTED; }
}

/** Redact first, truncate second, so a secret straddling the cut is not half-leaked. */
const redactCap = (text, limit) => redact(text).slice(0, limit);

module.exports = { redact, redactCap };
