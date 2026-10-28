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

async function guard(args: Record<string, unknown>): Promise<any | null> {
  const token = (process.env.JEV_MCP_TOKEN ?? "").trim();
  if (!token || !URL_) return null;
  try {
    const res = await fetch(URL_, {
      method: "POST",
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
    if (!res.ok) return null;
    const raw = await res.text();
    for (let line of raw.split("\n")) {
      line = line.trim();
      if (line.startsWith("data:")) line = line.slice(5).trim();
      if (!line.startsWith("{")) continue;
      const msg = JSON.parse(line);
      if (msg.result?.isError) return null;
      return JSON.parse(msg.result.content[0].text);
    }
  } catch {
    /* timeout, network, parse: fail open */
  }
  return null;
}

export default function jevGuard(pi: ExtensionAPI) {
  pi.on("tool_call", async (event: any, ctx: any) => {
    try {
      let args: Record<string, unknown> | null = null;
      if (isToolCallEventType("bash", event)) {
        args = { tool: "Bash", command: event.input.command, cwd: ctx.cwd, home: process.env.HOME };
      } else if (event.toolName === "read" && (event.input?.path || event.input?.file_path)) {
        args = { tool: "Read", file_path: event.input.path ?? event.input.file_path, cwd: ctx.cwd, home: process.env.HOME };
      }
      if (!args) return;
      const r = await guard(args);
      if (!r || (r.decision !== "ask" && r.decision !== "block")) return;
      const why = `Jev guard${r.rule ? ` [${r.rule}]` : ""}: ${r.reason}${r.suggestion ? ` ${r.suggestion}` : ""}`;
      if (SHADOW) { pi.logger?.warn?.(`(shadow) would ${r.decision}: ${why}`); return; }
      if (r.decision === "block") return { block: true, reason: why };
      // ask
      if (ctx.hasUI && typeof ctx.ui?.confirm === "function") {
        const ok = await ctx.ui.confirm("Jev guard: run this command?", why);
        return ok ? undefined : { block: true, reason: `${why} (declined by user)` };
      }
      return ASK_NO_UI === "allow" ? undefined : { block: true, reason: `${why} Needs human approval; ask the user and retry.` };
    } catch {
      return; // never let the guard itself break the session
    }
  });
}
