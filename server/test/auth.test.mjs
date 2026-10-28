import test from "node:test";
import assert from "node:assert/strict";
import worker, { tokenOk, allowedTokens } from "../src/index.mjs";

const req = (auth) => new Request("https://x.test/mcp", { method: "POST", headers: auth ? { authorization: auth } : {} });

test("no token configured: fail closed", async () => {
  assert.equal(await tokenOk("Bearer anything", {}), false);
  assert.equal(await tokenOk("Bearer ", { MCP_BEARER_TOKEN: "" }), false);
});
test("single token (backward compatible)", async () => {
  const env = { MCP_BEARER_TOKEN: "secret-a" };
  assert.equal(await tokenOk("Bearer secret-a", env), true);
  assert.equal(await tokenOk("Bearer secret-b", env), false);
  assert.equal(await tokenOk("secret-a", env), false);
  assert.equal(await tokenOk(null, env), false);
  assert.equal(await tokenOk("Bearer ", env), false);
});
test("multiple comma-separated tokens", async () => {
  const env = { MCP_BEARER_TOKEN: "old", MCP_BEARER_TOKENS: " fin-tok , andy-tok ,," };
  assert.deepEqual(allowedTokens(env), ["old", "fin-tok", "andy-tok"]);
  for (const t of ["old", "fin-tok", "andy-tok"]) assert.equal(await tokenOk(`Bearer ${t}`, env), true, t);
  assert.equal(await tokenOk("Bearer fin", env), false);
  assert.equal(await tokenOk("Bearer ", env), false);
});
test("fetch: unauthenticated and wrong-token calls get 401", async () => {
  const env = { MCP_BEARER_TOKEN: "secret-a" };
  for (const a of [null, "Bearer wrong", "Basic abc"]) {
    const r = await worker.fetch(req(a), env);
    assert.equal(r.status, 401);
    assert.equal(r.headers.get("www-authenticate"), "Bearer");
  }
  assert.equal((await worker.fetch(req(null), {})).status, 401);
});
test("fetch: /health open, unknown path 404", async () => {
  assert.equal((await worker.fetch(new Request("https://x.test/health"), {})).status, 200);
  assert.equal((await worker.fetch(new Request("https://x.test/nope"), {})).status, 404);
});
