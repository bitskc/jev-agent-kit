// Cloudflare Worker host for jkudish/jev-mcp (upstream tools unmodified) plus the kit_* tools
// ported from jonathanavis96/jev-kit (MIT). Stateless streamable HTTP at /mcp, bearer-protected.
import { createMcpHandler } from "@modelcontextprotocol/server";
import { createServer } from "../vendor/server.js";
import { registerKitTools } from "./kit/tools.mjs";

let handler;
let currentEnv = {};
const enc = new TextEncoder();

async function sha(s) { return new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(s))); }
async function tokenOk(header, expected) {
  if (!expected) return false;
  const given = header && header.startsWith("Bearer ") ? header.slice(7) : "";
  const [a, b] = await Promise.all([sha(given), sha(expected)]);
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

// One factory per request: the 12 upstream tools, then the 3 kit tools.
function factory() {
  const server = createServer();
  registerKitTools(server, () => currentEnv);
  return server;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === "/health") return new Response("ok");
    if (url.pathname !== "/mcp") return new Response("Not found", { status: 404 });
    if (!(await tokenOk(request.headers.get("authorization"), env.MCP_BEARER_TOKEN))) {
      return new Response("Unauthorized", { status: 401, headers: { "www-authenticate": "Bearer" } });
    }
    currentEnv = env;
    // Upstream jev_* tools pick a carrier from process.env. If a Vercel AI Gateway key is set and the
    // operator did not choose a provider, use the gateway so the user pays through Vercel, not TypeSafe.
    if (env.AI_GATEWAY_API_KEY && !env.JEV_PROVIDER && typeof process !== "undefined") process.env.JEV_PROVIDER = "vercel";
    handler ??= createMcpHandler(factory, { maxSubscriptions: 0 });
    return handler.fetch(request);
  },
};
