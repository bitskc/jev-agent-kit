// Upstream resolver + tiny TypeSafe-shaped client for the kit_* tools.
//
// Vercel AI Gateway's TypeSafe-compatible API (https://vercel.com/docs/ai-gateway/sdks-and-apis/typesafe)
// keeps TypeSafe's request/response shapes ({model, state, questions} -> {answers}; `noul`, `choice`,
// `score` unchanged), so no field mapping is needed: only base URL, key and model id differ.
//
// Precedence (first match wins):
//   1. JEV_UPSTREAM_API_KEY [+ JEV_UPSTREAM_BASE_URL, JEV_UPSTREAM_MODEL]   explicit override
//   2. AI_GATEWAY_API_KEY  -> https://ai-gateway.vercel.sh/typesafe , model typesafe-ai/jev
//   3. TYPESAFE_API_KEY    -> https://api.typesafe.ai ,               model jev-latest
//   (JEV_BASE_URL / TYPESAFE_BASE_URL change the base for 2 / 3 respectively.)

export const GATEWAY_BASE = "https://ai-gateway.vercel.sh/typesafe";
export const GATEWAY_MODEL = "typesafe-ai/jev";
export const TYPESAFE_BASE = "https://api.typesafe.ai";
export const TYPESAFE_MODEL = "jev-latest";

/** @returns {{name:string, base:string, key:string, model:string}|null} */
export function resolveUpstream(env = {}) {
  const trim = (s) => (typeof s === "string" ? s.trim() : "");
  const strip = (u) => u.replace(/\/+$/, "");
  if (trim(env.JEV_UPSTREAM_API_KEY)) {
    return { name: "custom", key: trim(env.JEV_UPSTREAM_API_KEY), base: strip(trim(env.JEV_UPSTREAM_BASE_URL) || GATEWAY_BASE), model: trim(env.JEV_UPSTREAM_MODEL) || GATEWAY_MODEL };
  }
  if (trim(env.AI_GATEWAY_API_KEY)) {
    return { name: "vercel-ai-gateway", key: trim(env.AI_GATEWAY_API_KEY), base: strip(trim(env.JEV_BASE_URL) || GATEWAY_BASE), model: trim(env.JEV_MODEL) || GATEWAY_MODEL };
  }
  if (trim(env.TYPESAFE_API_KEY)) {
    return { name: "typesafe", key: trim(env.TYPESAFE_API_KEY), base: strip(trim(env.TYPESAFE_BASE_URL) || TYPESAFE_BASE), model: trim(env.JEV_MODEL) || TYPESAFE_MODEL };
  }
  return null;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * POST {base}/v1/systemone. Retries 408/409/429/5xx up to 3 attempts inside one deadline.
 * Throws a short, credential-free Error on failure. Never includes response bodies.
 */
export async function askUpstream(upstream, state, questions, { fetchImpl = fetch, timeoutMs = 20000, signal } = {}) {
  const control = new AbortController();
  const timer = setTimeout(() => control.abort(new Error("Jev request timed out")), timeoutMs);
  if (signal) signal.addEventListener("abort", () => control.abort(signal.reason), { once: true });
  try {
    let res;
    for (let attempt = 0; ; attempt++) {
      try {
        res = await fetchImpl(`${upstream.base}/v1/systemone`, {
          method: "POST",
          headers: { "content-type": "application/json", authorization: `Bearer ${upstream.key}` },
          body: JSON.stringify({ model: upstream.model, state, questions }),
          signal: control.signal,
        });
        if (res.ok || ![408, 409, 429].includes(res.status) && res.status < 500 || attempt === 2) break;
        await res.text().catch(() => {});
      } catch (e) {
        if (control.signal.aborted || attempt === 2) throw e;
      }
      await sleep(400 * 2 ** attempt);
    }
    if (!res.ok) throw new Error(`${upstream.name} returned HTTP ${res.status}`);
    let body;
    try { body = await res.json(); } catch { throw new Error(`${upstream.name} returned an unparseable response`); }
    if (!body || typeof body !== "object" || !body.answers || typeof body.answers !== "object" || Array.isArray(body.answers)) {
      throw new Error(`${upstream.name} returned a malformed answers envelope`);
    }
    for (const id of Object.keys(questions)) if (!Object.hasOwn(body.answers, id)) throw new Error(`${upstream.name} omitted the answer for ${id}`);
    return { answers: body.answers, usage: body.usage ?? null, model: typeof body.model === "string" ? body.model : upstream.model, upstream: upstream.name };
  } finally {
    clearTimeout(timer);
  }
}

/** Build the `deps` object guardCommand / sizeDispatch / verifyDone expect. */
export function makeDeps(env, opts = {}) {
  const upstream = resolveUpstream(env);
  if (!upstream) return { ask: null, jevAvailable: false, upstream: null };
  return {
    jevAvailable: true,
    upstream: upstream.name,
    ask: (state, questions) => askUpstream(upstream, state, questions, opts),
  };
}
