// omp (oh-my-pi) hook: jev-mcp kit_guard_command before every bash tool call.
// Install:  cp jev-guard.ts ~/.omp/agent/hooks/pre/jev-guard.ts   (user)   or   .omp/hooks/pre/   (project)
// Try once: omp --hook /abs/path/jev-guard.ts
//
// CONFIRMED from omp docs (omp.sh/docs/hooks): hooks are .ts/.js modules in hooks/pre|post/ that default-export
// a factory(pi: ExtensionAPI); pi.on("tool_call", (event, ctx) => ...) may return { block: true, reason };
// isToolCallEventType("bash", event) narrows event.input.command; tool_call exceptions/timeouts FAIL CLOSED
// in omp (default 30 s, extensionHandlers.toolCallTimeoutMs), so everything below is wrapped to fail OPEN.
// ASSUMED (not verified; this file has not been run inside omp):
//   - ctx.ui.confirm(title, message) exists and returns Promise<boolean> (used for "ask"; guarded by typeof check)
//   - the built-in read tool is named "read" with event.input.path (only used for secret-file reads)
// Endpoint and token come from the env vars JEV_MCP_URL and JEV_MCP_TOKEN; never hardcode them.
import { isToolCallEventType, type ExtensionAPI } from "@oh-my-pi/pi-coding-agent";

const URL_ = (process.env.JEV_MCP_URL ?? "").trim(); // e.g. https://<your-worker>.workers.dev/mcp
const TIMEOUT_MS = Number(process.env.JEV_GUARD_TIMEOUT ?? "2") * 1000;
const SHADOW = process.env.JEV_GUARD_MODE === "shadow";
const ASK_NO_UI = process.env.JEV_GUARD_ASK_NO_UI ?? "block"; // "block" | "allow" when "ask" but nobody can answer

// Server-side input caps (server/src/kit/tools.mjs): over these the schema rejects the call, and a rejection must
// become "ask", never a silent allow.
const CAPS: Record<string, number> = { command: 20000, file_path: 2000, cwd: 1000, home: 500 };

type GuardReply = { decision?: string; rule?: string; reason?: string; suggestion?: string };
type GuardResult = { kind: "reply"; reply: GuardReply } | { kind: "rejected"; detail: string } | { kind: "unavailable" };

async function guard(args: Record<string, unknown>): Promise<GuardResult> {
  const token = (process.env.JEV_MCP_TOKEN ?? "").trim();
  if (!token || !URL_.startsWith("https://")) return { kind: "unavailable" };
  try {
    const res = await fetch(URL_, {
      method: "POST",
      redirect: "error", // a 3xx would re-send the bearer wherever it points
      signal: AbortSignal.timeout(TIMEOUT_MS),
      headers: {
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
        authorization: `Bearer ${token}`,
        "user-agent": "jev-guard-hook-omp/1.0",
      },
      body: JSON.stringify({
        jsonrpc: "2.0", id: 1, method: "tools/call",
        params: { name: "kit_guard_command", arguments: args },
      }),
    });
    if (!res.ok) return { kind: "unavailable" };
    const raw = await res.text();
    for (let line of raw.split("\n")) {
      line = line.trim();
      if (line.startsWith("data:")) line = line.slice(5).trim();
      if (!line.startsWith("{")) continue;
      const msg = JSON.parse(line) as { error?: { message?: string }; result?: { isError?: boolean; content?: { text?: string }[] } };
      if (msg.error) return { kind: "rejected", detail: String(msg.error.message ?? "error").slice(0, 200) };
      if (msg.result?.isError) return { kind: "rejected", detail: String(msg.result.content?.[0]?.text ?? "tool error").slice(0, 200) };
      const text = msg.result?.content?.[0]?.text;
      if (typeof text !== "string") return { kind: "unavailable" };
      return { kind: "reply", reply: JSON.parse(text) as GuardReply };
    }
  } catch {
    /* timeout, network, parse: fail open */
  }
  return { kind: "unavailable" };
}

type ToolCallEvent = { toolName?: string; input?: Record<string, unknown> };
type ToolCallCtx = { cwd?: string; hasUI?: boolean; ui?: { confirm?: (title: string, message: string) => Promise<boolean> } };
type Verdict = { block: true; reason: string } | undefined;

export default function jevGuard(pi: ExtensionAPI) {
  const ask = async (ctx: ToolCallCtx, why: string): Promise<Verdict> => {
    if (SHADOW) { pi.logger?.warn?.(`(shadow) would ask: ${why}`); return; }
    if (ctx.hasUI && typeof ctx.ui?.confirm === "function") {
      const ok = await ctx.ui.confirm("Jev guard: run this command?", why);
      return ok ? undefined : { block: true, reason: `${why} (declined by user)` };
    }
    return ASK_NO_UI === "allow" ? undefined : { block: true, reason: `${why} Needs human approval; ask the user and retry.` };
  };

  pi.on("tool_call", async (event: ToolCallEvent, ctx: ToolCallCtx): Promise<Verdict> => {
    try {
      let args: Record<string, unknown> | null = null;
      if (isToolCallEventType("bash", event)) {
        args = { tool: "Bash", command: String(event.input.command ?? ""), cwd: ctx.cwd, home: process.env.HOME };
      } else if (event.toolName === "read" && (event.input?.path || event.input?.file_path)) {
        args = { tool: "Read", file_path: String(event.input.path ?? event.input.file_path), cwd: ctx.cwd, home: process.env.HOME };
      } else if (event.toolName === "grep" && event.input?.pattern) {
        // grep in content mode prints matching lines verbatim: judge it as the grep command it is (R1 secret reader)
        args = { tool: "Bash", command: `grep -r ${JSON.stringify(String(event.input.pattern))} ${JSON.stringify(String(event.input.path ?? "."))}`, cwd: ctx.cwd, home: process.env.HOME };
      }
      if (!args) return;
      for (const [key, cap] of Object.entries(CAPS)) {
        const v = args[key];
        if (typeof v !== "string" || v.length <= cap) continue;
        if (key === "command" || key === "file_path") return ask(ctx, `Jev guard: ${key} is ${v.length} chars, over the ${cap}-char limit the guard can judge; confirm it by hand.`);
        args[key] = v.slice(0, cap);
      }
      const g = await guard(args);
      if (g.kind === "unavailable") return; // fail open
      if (g.kind === "rejected") return ask(ctx, `Jev guard could not judge this call (server rejected it: ${g.detail}); confirm it by hand.`);
      const r = g.reply;
      if (r.decision !== "ask" && r.decision !== "block") return;
      const why = `Jev guard${r.rule ? ` [${r.rule}]` : ""}: ${r.reason}${r.suggestion ? ` ${r.suggestion}` : ""}`;
      if (SHADOW) { pi.logger?.warn?.(`(shadow) would ${r.decision}: ${why}`); return; }
      if (r.decision === "block") return { block: true, reason: why };
      return ask(ctx, why);
    } catch {
      return; // never let the guard itself break the session
    }
  });
}
