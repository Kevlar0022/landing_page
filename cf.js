async function slack(url, text) {
  if (!url) return;
  await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ text }),
  }).catch(() => {});
}

export default {
  async fetch(req, env, ctx) {
    const origin = req.headers.get("Origin") || "";
    const allowedOrigin = "https://kevlar0022.github.io";

    const corsHeaders =
      origin === allowedOrigin
        ? {
            "Access-Control-Allow-Origin": allowedOrigin,
            "Access-Control-Allow-Methods": "POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type",
            "Vary": "Origin",
          }
        : { "Vary": "Origin" };

    const reply = (body, status = 200) =>
      new Response(body, { status, headers: corsHeaders });

    // Handle CORS preflight
    if (req.method === "OPTIONS") {
      if (origin !== allowedOrigin) return reply("Forbidden", 403);
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    if (origin !== allowedOrigin) return reply("Forbidden", 403);
    if (req.method !== "POST") return reply("Method Not Allowed", 405);

    const ip = req.headers.get("CF-Connecting-IP") || "0.0.0.0";
    const now = Date.now();

    // ---- basic IP rate limit (10/min) ----
    const key = `rl:${ip}:${Math.floor(now / 60000)}`;
    const count = (await env.RATE_KV.get(key)) || "0";
    const next = Number(count) + 1;
    await env.RATE_KV.put(key, String(next), { expirationTtl: 120 });
    if (next > 10) return reply("Too Many Requests", 429);

    // ---- parse body ----
    const body = await req.json().catch(() => null);
    if (!body) return reply("Bad Request", 400);

    const email = (body.email || "").toLowerCase().trim();
    const honeypot = (body.company || "").trim(); // hidden field on your form
    const startedAt = Number(body.startedAt || 0); // ms timestamp from page load

    // Honeypot filled => bot
    if (honeypot) { ctx.waitUntil(slack(env.SLACK_WEBHOOK, "error: honeypot")); return reply("OK"); }

    // Too-fast submit => likely bot (tune threshold)
    if (startedAt && now - startedAt < 1200) { ctx.waitUntil(slack(env.SLACK_WEBHOOK, "error: too fast")); return reply("OK"); }

    // basic email sanity (keep it light)
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      ctx.waitUntil(slack(env.SLACK_WEBHOOK, "error: invalid email"));
      return reply("OK");
    }

    // ---- Turnstile verify ----
    const token = body.turnstileToken;
    if (!token) { ctx.waitUntil(slack(env.SLACK_WEBHOOK, "error: no token")); return reply("OK"); }

    const form = new FormData();
    form.append("secret", env.TURNSTILE_SECRET);
    form.append("response", token);
    form.append("remoteip", ip);

    const verify = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      body: form,
    }).then(r => r.json());

    if (!verify.success) { ctx.waitUntil(slack(env.SLACK_WEBHOOK, "error: turnstile")); return reply("OK"); }

    // ---- call Kit (server-side, key stays secret) ----
    const kitRes = await fetch(`https://api.kit.com/v4/subscribers`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Kit-Api-Key": env.KIT_API_KEY,
      },
      body: JSON.stringify({ email_address: email }),
    });
    if (!kitRes.ok) { ctx.waitUntil(slack(env.SLACK_WEBHOOK, `error: kit ${kitRes.status}`)); return reply("KIT_ERROR", 500); }

    ctx.waitUntil(slack(env.SLACK_WEBHOOK, "success"));

    // Always return generic OK to avoid email enumeration
    return reply("OK");
  },
};