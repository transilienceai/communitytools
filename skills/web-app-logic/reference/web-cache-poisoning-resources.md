# Web Cache Poisoning — Resources

## Foundational research

- "Practical Web Cache Poisoning" — James Kettle (PortSwigger, BlackHat USA 2018)
- "Web Cache Entanglement: Novel Pathways to Poisoning" — James Kettle
- PortSwigger Research — https://portswigger.net/research/practical-web-cache-poisoning
- DEFCON / BlackHat talks on cache poisoning

## OWASP

- OWASP Cache Poisoning — https://owasp.org/www-community/attacks/Cache_Poisoning
- OWASP API Top 10 (API4 / API8 — caching considerations)
- OWASP Cheat Sheet — Caching

## CWE

- CWE-444 — Inconsistent Interpretation
- CWE-348 — Use of Less Trusted Source
- CWE-565 — Reliance on Cookies

## Notable disclosure cases

- HackerOne disclosed reports tagged `cache-poisoning`
- Multiple bug-bounty payouts on Twitter (X), GitHub, GitLab
- Akamai / Cloudflare cache-poisoning incidents
- HTTP/2 cache poisoning (CL.0 + cache)

## Tools

### Burp extensions

- **Param Miner** — discover unkeyed headers, parameters, cookies (essential)
- **HTTP Request Smuggler** — combines smuggling with cache
- **Auto Repeater** — replay across user sessions
- **Logger++** — track cache hit ratios

### Standalone

- **smuggler.py** — defparam — combines with cache-poisoning
- **race-the-web** — race-condition + cache combinations
- **cache-poisoning** scripts in PortSwigger Academy
- Custom Python with `requests` + threading

## Headers / parameters / cookies to test

### Forwarding

```
X-Forwarded-Host
X-Forwarded-Scheme / X-Forwarded-Proto
X-Forwarded-Server
X-Forwarded-For
Forwarded
```

### URL rewriting

```
X-Original-URL / X-Rewrite-URL
X-Custom-IP-Authorization
X-Original-Path / X-Request-URI
```

### Host overrides

```
X-Host / X-HTTP-Host-Override
X-Backend-Server / X-Cluster-Client-IP
True-Client-IP / CF-Connecting-IP
X-Real-IP / X-ProxyUser-Ip
```

### UTM / tracking

```
utm_source utm_medium utm_campaign utm_content utm_term
gclid fbclid msclkid twclid li_fat_id
tracking_id affiliate_id ref referrer promo coupon_code
callback jsonp cb
```

### Cookies

```
fehost language currency theme variant experiment
session_id _csrf_token
```

## Cache infrastructure landscape

- **Cloudflare** — `CF-Cache-Status` header
- **Akamai** — `X-Cache: TCP_HIT/MISS/...`
- **AWS CloudFront** — `X-Cache: Hit from cloudfront`
- **Fastly** — VCL-based cache; `Vary` important
- **Varnish** — `X-Cache: hit/miss`
- **nginx** `proxy_cache` — `X-Cache: HIT/MISS`
- **Apache** `mod_cache`

## Vulnerable patterns

- `<script src="//<?= $_SERVER['HTTP_X_FORWARDED_HOST'] ?>/script.js">` (PHP)
- `<link rel="canonical" href="<?= $_GET['utm_content'] ?>">` (UTM in canonical)
- `<?= $_GET['callback'] ?>(...)` (JSONP)
- `data = {"host":"<?= $_COOKIE['fehost'] ?>"}` (cookie in JS)
- Rails parameter cloaking — `?safe=ok;callback=evil`

## Mitigations / defensive references

- Include all relevant input in cache key
- Use `Vary` header correctly (cookies, accept-encoding, X-Forwarded-Host, etc.)
- Strip untrusted headers at proxy layer (Cloudflare scrubbing)
- `Cache-Control: no-store, private` on authenticated responses
- Validate Origin / Referer
- Helmet (Express), Spring Security headers, Django SecurityMiddleware
- Avoid JSONP (use CORS instead)

## SIEM detection

- Splunk: `index=web_logs | search status=200 cache-hit | stats count by uri, x_forwarded_host`
- Datadog APM cache analytics
- Akamai mPulse / Cloudflare Analytics

## Attack technique writeups

- PortSwigger Research blog series on cache
- HackerOne disclosed reports
- swisskyrepo/PayloadsAllTheThings — Web Cache Poisoning
- HackTricks Cache Poisoning page
- "Mass Account Takeover via Cache Poisoning" — bug bounty writeups

## Practice / labs

- Web Security Academy — Web Cache Poisoning — https://portswigger.net/web-security/web-cache-poisoning
- TryHackMe — Cache Poisoning rooms

## Bug bounty programs

- HackerOne — most large-scale SaaS programs (cache-poisoning yields high impact)
- Bugcrowd — Tesla, Atlassian
- Intigriti — European fintech
- Self-hosted — Slack, GitLab, Reddit

## Compliance / standards

- PCI DSS 6.5.x (caching of sensitive data)
- HIPAA (sensitive data caching)
- GDPR (Article 5(1)(f), security of personal data)
- SOC 2 Type 2 (caching controls)

## Cheat-sheet companions in this repo

- `scenarios/cache/poisoning-unkeyed-headers.md`
- `scenarios/cache/poisoning-unkeyed-params.md`
- `scenarios/cache/deception-via-smuggling.md` (smuggling + cache combo)

## One-liner test commands

```bash
# Test X-Forwarded-Host poisoning
curl -I https://target.com/?cb=$(date +%s) -H "X-Forwarded-Host: evil.com"

# Continuous monitor
watch -n 2 'curl -sI https://target.com/?cb=$(date +%s) | grep -E "X-Cache|X-Forwarded-Host|Cache-Control"'

# UTM unkeyed test
curl "https://target.com/?utm_content=test123" && \
curl "https://target.com/?utm_content=different"  # check X-Cache: hit
```
