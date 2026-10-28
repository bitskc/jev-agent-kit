#!/usr/bin/env python3
"""PreToolUse hook for Claude Code (and Claude-Code-compatible agents).

Reads the hook JSON on stdin, asks the jev-mcp server's `kit_guard_command` tool
(MCP tools/call over streamable HTTP), and prints Claude Code's PreToolUse decision JSON:

    allow -> no output, exit 0 (the normal permission flow continues)
    ask   -> {"hookSpecificOutput": {"permissionDecision": "ask",  ...}}
    block -> {"hookSpecificOutput": {"permissionDecision": "deny", ...}}

Fails OPEN: any error, timeout (default 2 s hard cap), missing token, non-200, or malformed reply
exits 0 with no output. Set JEV_GUARD_DEBUG=1 to see why on stderr.

Env:
  JEV_MCP_TOKEN        required. Bearer token; never hardcoded, never logged.
  JEV_MCP_URL          required. Your deployed endpoint, e.g. https://<your-worker>.workers.dev/mcp
  JEV_GUARD_TIMEOUT    seconds, default 2
  JEV_GUARD_MODE       enforce (default) | shadow (never blocks; logs what it would do to stderr)
  JEV_GUARD_ASK_AT     risk threshold sent as ask_at (server default 0.65)
  JEV_GUARD_HOME       the user's home dir to send as `home` (default $HOME)
  JEV_GUARD_DEBUG      1 = explain on stderr
"""
import json
import os
import signal
import sys
import urllib.request

URL = os.environ.get("JEV_MCP_URL", "").strip()
TIMEOUT = float(os.environ.get("JEV_GUARD_TIMEOUT", "2"))
MODE = os.environ.get("JEV_GUARD_MODE", "enforce")
DEBUG = os.environ.get("JEV_GUARD_DEBUG") == "1"


def note(msg):
    if DEBUG:
        sys.stderr.write("jev-guard: %s\n" % msg)


def fail_open(why):
    note("fail-open: %s" % why)
    sys.exit(0)


def _alarm(_signum, _frame):
    raise TimeoutError("hard timeout")


class RedirectRefused(Exception):
    """The endpoint tried to redirect the call: the server answered (just not sanely), so this is not an
    outage to fail open on — same class as ServerRejected, never a silent allow."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    # A redirect would re-send the bearer to whatever host/scheme the 3xx names. Never follow one.
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RedirectRefused("redirect refused (%s -> %s)" % (code, newurl[:80]))


_opener = urllib.request.build_opener(_NoRedirect)

# Server-side input caps (server/src/kit/tools.mjs). Anything longer would be rejected by the schema, and a
# schema rejection must not turn into a silent allow, so oversized input is answered with "ask" before any call.
CAPS = {"command": 20000, "file_path": 2000, "cwd": 1000, "home": 500, "description": 500}


class ServerRejected(Exception):
    """The server answered but refused the call: the server is up, so this is not an outage to fail open on."""


def call_guard(args):
    token = os.environ.get("JEV_MCP_TOKEN", "").strip()
    if not URL.startswith("https://"):
        fail_open("JEV_MCP_URL must be https:// (got %r)" % URL[:40])
    if not token:
        fail_open("JEV_MCP_TOKEN is not set")
    if not URL:
        fail_open("JEV_MCP_URL is not set")
    body = json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "kit_guard_command", "arguments": args},
    }).encode()
    req = urllib.request.Request(URL, data=body, method="POST", headers={
        "content-type": "application/json",
        "accept": "application/json, text/event-stream",
        "authorization": "Bearer " + token,
        "user-agent": "jev-guard-hook/1.0",  # Cloudflare 403s the default Python-urllib UA
    })
    with _opener.open(req, timeout=TIMEOUT) as resp:
        raw = resp.read().decode("utf-8", "replace")
    # The server answers JSON or a single SSE `data:` frame.
    payload = None
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("data:"):
            line = line[5:].strip()
        if line.startswith("{"):
            try:
                payload = json.loads(line)
                break
            except ValueError:
                continue
    if not payload:
        raise ValueError("no JSON-RPC payload")
    if "error" in payload:  # JSON-RPC error: the server is up and refused this call (bad input, unknown tool)
        raise ServerRejected(str(payload["error"].get("message", payload["error"]))[:200])
    result = payload.get("result") or {}
    if result.get("isError"):
        raise ServerRejected(str((result.get("content") or [{}])[0].get("text", "tool error"))[:200])
    return json.loads(result["content"][0]["text"])


def emit(decision, reason):
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": decision,
        "permissionDecisionReason": reason[:1500],
    }}))
    sys.exit(0)


def main():
    try:
        event = json.load(sys.stdin)
    except Exception:
        fail_open("stdin was not JSON")
    tool = event.get("tool_name", "")
    ti = event.get("tool_input") or {}
    if tool == "Bash" and ti.get("command"):
        args = {"tool": "Bash", "command": str(ti["command"])}
        if ti.get("description"):
            args["description"] = str(ti["description"])[:500]
    elif tool in ("Read", "NotebookRead") and (ti.get("file_path") or ti.get("notebook_path")):
        args = {"tool": "Read", "file_path": str(ti.get("file_path") or ti.get("notebook_path"))}
    elif tool == "Grep" and ti.get("pattern"):
        # Grep in content mode prints matching lines verbatim: judge it as the grep command it is (R1 secret reader).
        args = {"tool": "Bash", "command": "grep -r %s %s" % (json.dumps(str(ti["pattern"])), json.dumps(str(ti.get("path") or ".")))}
    else:
        sys.exit(0)  # not a tool this guard covers
    if event.get("cwd"):
        args["cwd"] = str(event["cwd"])
    home = os.environ.get("JEV_GUARD_HOME") or os.path.expanduser("~")
    if home and home != "~":
        args["home"] = home
    if os.environ.get("JEV_GUARD_ASK_AT"):
        try:
            args["ask_at"] = float(os.environ["JEV_GUARD_ASK_AT"])
        except ValueError:
            pass
    # Oversized input would be rejected by the server schema; a rejection is not a reason to run it unguarded.
    for key, cap in CAPS.items():
        if key in args and len(args[key]) > cap:
            if key in ("command", "file_path"):
                if MODE == "shadow":
                    sys.stderr.write("jev-guard (shadow): would ask: %s exceeds %d chars\n" % (key, cap))
                    sys.exit(0)
                emit("ask", "Jev guard: %s is %d chars, over the %d-char limit the guard can judge; confirm it by hand." % (key, len(args[key]), cap))
            args[key] = args[key][:cap]

    try:
        signal.signal(signal.SIGALRM, _alarm)
        signal.setitimer(signal.ITIMER_REAL, TIMEOUT + 0.5)
        r = call_guard(args)
    except (ServerRejected, RedirectRefused) as e:  # server reachable but refused/redirected the call: ask, never allow silently
        if MODE == "shadow":
            sys.stderr.write("jev-guard (shadow): would ask: server rejected call: %s\n" % str(e)[:200])
            sys.exit(0)
        emit("ask", "Jev guard could not judge this call (server rejected it: %s); confirm it by hand." % str(e)[:200])
    except Exception as e:  # timeout, DNS, HTTP error, bad JSON ... all fail open
        fail_open("%s: %s" % (type(e).__name__, str(e)[:120]))
    finally:
        try:
            signal.setitimer(signal.ITIMER_REAL, 0)
        except Exception:
            pass

    decision = r.get("decision")
    why = "%s%s%s" % (
        "Jev guard [%s]: " % r["rule"] if r.get("rule") else "Jev guard: ",
        r.get("reason", ""),
        (" " + r["suggestion"]) if r.get("suggestion") and decision != "allow" else "",
    )
    note("%s score=%s rule=%s decided_by=%s" % (decision, r.get("score"), r.get("rule"), r.get("decided_by")))
    if decision not in ("ask", "block"):
        sys.exit(0)  # allow (including the server's own fail-open)
    if MODE == "shadow":
        sys.stderr.write("jev-guard (shadow): would %s: %s\n" % (decision, why[:300]))
        sys.exit(0)
    emit("deny" if decision == "block" else "ask", why)


if __name__ == "__main__":
    main()
