# Cache Poisoning — SetNX Fill Race vs Legitimate Filler

## When this applies

- CDN / reverse-proxy populates its response cache with a one-shot atomic write that "first writer wins":
  - Redis `SET key value NX EX <ttl>` (covers Go [`go-redis`](https://github.com/redis/go-redis) `SetNX`, [`groupcache`](https://github.com/golang/groupcache), [`bigcache`](https://github.com/allegro/bigcache), several FastCGI cache modules).
  - `memcached add` (NOT `set`).
  - nginx `proxy_cache_lock on` with `proxy_cache_lock_timeout`.
  - Cloudflare's "stampede protection" / `cache_reserve`.
- Cache key is derivable by the attacker (URL, sometimes plus a Vary header), but the *body* that gets stored under that key is whatever the *first* request to forward to origin produces.
- The attacker can already inject content into the origin response under a known URL (typically via a related primitive: GET-with-body in a body-parsing backend → see [poisoning-body-args.md](poisoning-body-args.md), unkeyed headers, smuggling). The attacker just can't reach the *target* who triggers the cache fill (a logged-in admin, a bot, the next legitimate user).

The vulnerability is the race between:

1. **Victim's request** → cache miss → backend → origin returns benign content → `SetNX(key, benign)` succeeds → cache holds benign content.
2. **Attacker's poisoning request** → same cache key → backend → origin returns malicious content → `SetNX(key, malicious)` succeeds → cache holds malicious content.

Whichever request's origin response completes first wins the SetNX and locks the cache for the TTL.

## Technique

To make the attacker's poisoning request beat the victim's request, you have three levers:

1. **Predict (or trigger) the victim's request URL** so you know what cache key to race for.
2. **Race with high volume** — fire the poisoning request many times in tight succession around the moment the victim is triggered.
3. **Widen the race window by inflating origin response time for the legitimate query.** This is the often-missed lever: the SetNX winner is determined by which request's *origin processing* finishes first. If you can globally slow the origin path the victim uses (heavy DB inserts, large memory allocations, expensive regex), the victim's request takes 100s of ms, while your raw-socket-pipelined poisoning request still finishes in 30 ms. WAN RTT × 2 of headroom is enough.

Lever 3 turns sub-millisecond races into wide-open windows. It's the difference between "0 wins out of 10,000 attempts" and "wins every time".

## Steps

### 1. Identify the cache-fill mechanism

Read the proxy/CDN source. Look for `SetNX`, `Add`, `proxy_cache_lock`, or any single-writer pattern. Verify by:

```bash
# Two parallel GETs to a fresh cacheable URL; observe X-Cache headers.
curl -sD- 'http://<TARGET>/fresh?nonce=A' &
curl -sD- 'http://<TARGET>/fresh?nonce=A' &
wait
```

If one returns `X-Cache: miss` and the other returns `miss` too (both raced through), the proxy doesn't lock — straightforward stampede. If one returns `miss` and the other `hit` or stalls until the first completes, the proxy uses a fill-lock — this scenario applies.

### 2. Find a way to inject XSS / arbitrary content into the origin response

Without an origin-side reflection or pollution primitive, you can only DoS-replace the cache with the same benign content the victim sees. You need a way to make the origin return *malicious* content for the same cache key. Typical primitives:

- [poisoning-body-args.md](poisoning-body-args.md) — Tornado-style body merge, GET-with-body
- [poisoning-unkeyed-headers.md](poisoning-unkeyed-headers.md) — `X-Forwarded-Host` etc.
- Mass assignment leading to stored XSS in a per-user view
- Cache deception variant where the *cached* path mounts to a *dynamic* origin path

### 3. Identify or trigger the victim's URL

Some targets:

- **Bot trigger endpoint** (`/api/report` style) — visit chosen URL on demand.
- **Predictable URLs** — homepage, admin dashboard, a fixed search.
- **PRNG-derived URLs** — if the bot picks random words, you may need MT state recovery first ([web-app-logic resources](../../race-conditions-resources.md)).

### 4. Widen the race window

Profile origin response time under realistic load. Then look for operations that scale poorly with corpus size or input length and *crank them up*:

- **DB**: bulk-insert N rows (search index, comments, sessions). LIKE / regex / FTS queries scale linearly. Going from 50 rows → 10,000 rows often takes a 30 ms search to 800 ms.
- **Memory**: upload large blobs that get rehydrated in the request path.
- **CPU**: requests that trigger expensive crypto / image / PDF operations server-side.
- **Lock contention**: hold a DB row lock from another session if the framework serializes.

Verify the widening:

```bash
time curl -s 'http://<TARGET>/<victim-path>' -o /dev/null
# Pre-seed: target should drop from ~30ms to several hundred ms.
```

The race window needs to be at least `(attacker RTT + small slop)` longer than `(victim RTT)` for the attacker request to consistently arrive at SetNX-time first.

### 5. Race burst

Run the poisoning request in a tight loop *around* the moment the victim triggers the cache fill:

```python
# Fire poison requests in a hot loop
def poison_loop():
    while True:
        raw_socket_send(POISON_REQUEST_BYTES)  # bypass requests/urllib overhead

# In parallel: trigger victim, then poison hard for the duration of widened window
threading.Thread(target=poison_loop).start()
trigger_victim_bot()  # /api/report or equivalent
time.sleep(WINDOW_SECONDS)
poison_loop.stop()
```

Use raw sockets (or HTTP/1.1 keep-alive pipelining) instead of high-level clients to minimize per-request latency. 30–60 concurrent raw connections is usually enough.

### 6. Verify cache holds the poisoned content

```bash
curl -s 'http://<TARGET>/<victim-path>' | grep -F '<xss-marker>'
```

If `X-Cache: hit` and the marker is present, you won. The next time the victim hits the URL within the TTL, they get the poisoned content.

## Detection signals

- Proxy/CDN source contains `SetNX`, `set ... nx`, or `proxy_cache_lock`.
- Two parallel cache-miss requests don't both touch origin (one waits).
- The benign cached response replaces itself with whatever the first-after-expiry request produces, AND that first response is attacker-controllable.

## Mitigations

- **Don't trust SetNX as a security boundary.** It's a stampede mitigation, not a write-protection mechanism. If two parties can produce different content for the same cache key, attacker wins races for free.
- **Cache key must include every input that affects the body**, including body content (when the backend reads it) and trust-relevant headers.
- **Don't cache responses produced from authenticated handlers** unless the auth state is in the cache key.
- **Cap origin response time** with timeouts before SetNX runs — if origin took longer than `<n>` seconds, refuse to fill the cache.

## Anti-Patterns

- "We rate-limit cache fills" — doesn't help if attacker wins a single race.
- "Cache fills are atomic with SetNX, so no race" — atomic means *one writer wins*. It doesn't say *which* writer.
- "We don't cache `/panel`-style auth paths" — but you cache the public path that the auth path renders content into (cache deception combos).
- "The attacker can't predict the victim's URL" — sometimes true, but if the victim *is the attacker's own admin bot triggered on demand*, prediction is moot.

## Relation to other patterns

- [poisoning-body-args.md](poisoning-body-args.md) — the origin-side primitive that lets you inject malicious content into the origin's response. Combines naturally with this race for end-to-end stored XSS into authenticated sessions.
- [advanced-techniques.md](../race-conditions/advanced-techniques.md) — single-packet attack and last-byte sync further compress the race burst.
- [single-endpoint-collision.md](../race-conditions/single-endpoint-collision.md) — different race shape (TOCTOU within the handler), not cache-fill.
- Confirmed end-to-end against HTB SocratesPanel (Go CDN with `SetNX` + Tornado origin + admin Selenium bot). Inflating `/search` origin time from ~30 ms to ~800 ms (via 10 k DB rows) turned a 0% win rate into ~100% per attempt window.
