# SECURITY-MIGRATION-VALIDATION.md

Security-posture audits for the Vercel → Cloudflare Workers migration —
trust models, threat reasoning, and the decisions behind them. Raw HTTP
probe evidence (status codes, headers observed) lives in
`LOCAL-TEST-RESULTS.md`; this document is the "why is this actually safe"
companion to it. Evidence classification: **CLAUDE-VERIFIED** (executed
myself, this session) vs. **INFERRED** (reasoned from docs/architecture,
not directly executed) vs. **SOURCE-VERIFIED** (confirmed against a named
vendor's own documentation). Unmarked claims are CLAUDE-VERIFIED.

---

## 1. Client-IP trust model (Stage 4 Sec8)

### 1.1 What's being trusted, and why

Four rate limiters in `api/_lib/security.js` — `globalIpRateLimit`,
`adminIpRateLimit`, `intentIpRateLimit`, `submissionIpRateLimit` — all key
their Redis bucket off a single shared function, `getIp(req)`:

```js
function getIp(req) {
  const xff = req.headers['x-forwarded-for'];
  if (xff) return xff.split(',')[0].trim().slice(0, 45);
  return (req.headers['x-real-ip'] || req.socket?.remoteAddress || '0.0.0.0').slice(0, 45);
}
```

This function is **original, unmodified application code** — identical on
Vercel and Cloudflare. It trusts `x-forwarded-for`'s leftmost entry first.
On Vercel, Vercel's own edge is the only thing that can populate that
header credibly for internet traffic. On Cloudflare, the equivalent
edge-populated header is `CF-Connecting-IP`, not `X-Forwarded-For` — so
without intervention, a malicious client could set its own
`X-Forwarded-For` directly and `getIp()` would trust it unconditionally
(Cloudflare does not itself block or rewrite an inbound `X-Forwarded-For`
before a Worker sees it the way it does for `CF-Connecting-IP`).

`workers/lib/node-compat.js#toNodeRequest()` closes this gap **additively**
(original `getIp()` untouched) by overwriting `x-forwarded-for` with
`cf-connecting-ip` whenever the latter is present, before `getIp()` ever
runs:

```js
if (headers['cf-connecting-ip']) {
  headers['x-forwarded-for'] = headers['cf-connecting-ip'];
}
```

Because `getIp()` checks `x-forwarded-for` first, this makes Cloudflare's
edge-verified value win over anything the client itself supplied in either
header — confirmed end-to-end (both modules together, not just in
isolation) by `workers/lib/ip-trust-model.test.js` (6 cases: cf-connecting-
ip wins over a spoofed XFF, wins over a spoofed multi-hop XFF chain, falls
through correctly when absent, doesn't invent a value it wasn't given, the
`0.0.0.0` fallback is reached safely with no `req.socket` to throw on, and
IPv6 values survive the 45-char cap unmodified).

### 1.2 Is CF-Connecting-IP actually unspoofable? — the honest answer

**For a Cloudflare Worker specifically (not a traditional reverse-proxied
origin), yes, structurally — but this is INFERRED from Cloudflare's
documented architecture and the near-universal pattern every Cloudflare-
fronted application relies on, not a single explicit "we strip client-
supplied CF-Connecting-IP" sentence I could locate and quote verbatim.**

Two things are worth being precise about, because the general internet
advice on this header is more hedged than that:

- **The common caveat doesn't apply to Workers the way it applies to a
  traditional origin.** Nginx/Apache-behind-Cloudflare setups have a real,
  well-documented spoofing risk: if an attacker discovers the origin's real
  IP and can reach it *directly*, bypassing Cloudflare's proxy entirely,
  nothing stops them from sending a forged `CF-Connecting-IP` straight to
  that origin — the standard mitigation is firewalling the origin to only
  accept connections from Cloudflare's published IP ranges. **A Cloudflare
  Worker has no such bypass**: it isn't a separately-addressable origin
  sitting behind Cloudflare, it *is* Cloudflare edge compute. There is no
  direct IP to firewall around, because there is no direct path to the
  Worker that doesn't go through Cloudflare's own request-handling first.
- Cloudflare's own docs consistently describe the header as something
  "Cloudflare's edge infrastructure" attaches when forwarding traffic
  (SOURCE-VERIFIED against `developers.cloudflare.com/fundamentals/
  reference/http-headers/` and `.../http-request-headers/`), not as a
  pass-through of an arbitrary client-supplied header of the same name.

**What IS empirically confirmed, and matters for how to read every other
result in this document:** local `wrangler dev` does **not** reproduce this
protection at all. A real local probe —

```
curl http://127.0.0.1:8787/... -H "CF-Connecting-IP: 9.9.9.9"
  -> Worker saw cf-connecting-ip: 9.9.9.9  (passed through unchanged)

curl http://127.0.0.1:8787/... (no header set)
  -> Worker saw cf-connecting-ip: 127.0.0.1  (Wrangler's own local default)
```

— confirms Wrangler's local dev server injects a default `CF-Connecting-IP`
for unlabeled requests but does **not** strip or override a client-supplied
one, because there is no real Cloudflare edge in front of local dev to do
that stripping. This means: **no amount of local testing can verify the
production spoof-resistance guarantee** — only that this code correctly
implements its side of the contract (prefer `cf-connecting-ip` when
present, degrade safely when absent). The actual security property is
inherited entirely from Cloudflare's production edge, exactly as it is for
every application that uses this pattern. This is not a gap introduced by
this migration; it's an inherent limit of what `wrangler dev` can prove,
worth stating plainly rather than letting a passing local test imply more
than it does.

### 1.3 Residual, pre-existing behavior (not migration-introduced)

If `cf-connecting-ip`, `x-forwarded-for`, and `x-real-ip` are all absent —
not expected for genuine internet traffic reaching a Worker through
Cloudflare, but not proven impossible for every edge case either —
`getIp()` falls back to the literal string `'0.0.0.0'`. Every such request
would collapse into the same rate-limit bucket. This fallback is
**identical, original code**, unchanged from what already runs on Vercel
today for the same edge case; not something this migration created or
made worse. No action taken; noted for completeness.

---

*Further sections (auth/authorization matrix, cache security, CORS
certification) to be appended as Stage 4's remaining sections are
completed — see LOCAL-TEST-RESULTS.md and the Stage 4 task list for
current status.*
