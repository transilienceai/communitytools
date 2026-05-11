# Web Cache Deception — Resources

## OWASP / Web Security Academy

- PortSwigger Web Cache Deception — https://portswigger.net/web-security/web-cache-deception
- PortSwigger Delimiter List — https://portswigger.net/web-security/web-cache-deception/wcd-lab-delimiter-list
- OWASP Cache Poisoning — https://owasp.org/www-community/attacks/Cache_Poisoning
- OWASP API Top 10 — relevant for cacheable JSON APIs

## CWE

- CWE-444 — Inconsistent Interpretation of HTTP Requests (HTTP Smuggling, also relevant)
- CWE-348 — Use of Less Trusted Source
- CWE-639 — Authorization Bypass

## Foundational research

- "Gotta cache 'em all: bending the rules of web cache exploitation" — Omer Gil et al. (BlackHat USA)
- "Web Cache Entanglement: Novel Pathways to Poisoning" — James Kettle (PortSwigger Research)
- PortSwigger Research blog — https://portswigger.net/research

## Notable cases

- HackerOne disclosed reports tagged `cache-deception`
- Cloudflare cache-deception incidents
- Akamai cache-deception (multiple)
- AWS CloudFront cache-deception (configuration-dependent)
- Multiple SaaS account-takeover via cache-deception

## Tools

### Burp extensions

- **Web Cache Deception Scanner** (BApp Store)
- **Param Miner** — also flags unkeyed inputs
- **HTTP Request Smuggler** — for smuggling-driven cache deception

### Standalone

- **smuggler** — HTTP smuggling + cache combinations
- **cache-poisoning** scripts (PortSwigger Academy challenges)
- Custom curl + bash for cache-buster sweeps

## Cache infrastructure landscape

- Cloudflare — Cache Deception Armor (defensive)
- Akamai — caching defaults, byte-level rules
- AWS CloudFront — origin cache key configurable
- Fastly — VCL-based caching, very flexible
- Varnish — open-source reverse proxy
- nginx `proxy_cache`
- Apache `mod_cache`

## Cache headers / patterns

- `Cache-Control: max-age=N` — duration
- `X-Cache: hit/miss` — status
- `Age: <seconds>` — time in cache
- `Vary: <header>` — cache-key dimensions
- `CF-Cache-Status: HIT/MISS/EXPIRED/BYPASS` (Cloudflare)
- `X-Cache-Hits: N`

## Key delimiters to test

- `;` (Java Spring matrix)
- `?` (query string)
- `#` → `%23` (fragment)
- `.` (Rails format)
- `%00` (null byte)
- Each printable ASCII / common URL-encoded char (`%21..%7e`)

## Static-extension list (for path-mapping)

```
.js .css .jpg .jpeg .png .gif .ico .svg
.woff .woff2 .ttf .eot .mp4 .mp3 .pdf .xml
robots.txt favicon.ico sitemap.xml humans.txt
```

## Static directories (for path-mapping)

```
/static/    /assets/    /public/    /resources/
/images/    /css/       /js/        /media/
```

## Framework-specific delimiter behavior

- Java Spring — `;matrix=variable.js`
- Ruby on Rails — `.format.json`
- ASP.NET — `data.aspx;param.js`
- Express.js — `?data=1.js`, `#fragment.css`
- PHP — `.php/additional.js`, `.php?id=1.css`

## Detection commands

```bash
# Check cache headers
curl -I https://target.com/ | grep -E "Cache|Age|Vary"

# Monitor cache status
watch -n 2 'curl -I https://target.com/ | grep "X-Cache"'

# Verify cache TTL
sleep 30 && curl -sI https://target.com/foo
```

## Defense / detection

- Cloudflare Cache Deception Armor — automatic content-type vs extension check
- Custom WAF rules (cache only `Content-Type: image/*`)
- Vary headers including all relevant inputs
- `Cache-Control: no-store` on authenticated responses
- Validate response Content-Type matches request expectation

## Practice / labs

- Web Security Academy — Web Cache Deception labs
- Web Security Academy — Web Cache Poisoning labs
- TryHackMe — Web Cache Poisoning rooms

## Bug bounty programs

- HackerOne — almost all SaaS programs (Twitter, Slack, Trello, Asana)
- Cloud-platform programs — Cloudflare, AWS, Akamai
- E-commerce — Shopify, eBay, Target

## Cheat-sheet companions in this repo

- `scenarios/cache/deception-path-mapping.md`
- `scenarios/cache/deception-delimiter.md`
- `scenarios/cache/deception-normalization.md`
- `scenarios/cache/deception-via-smuggling.md`
- `scenarios/cache/poisoning-unkeyed-headers.md`
- `scenarios/cache/poisoning-unkeyed-params.md`
