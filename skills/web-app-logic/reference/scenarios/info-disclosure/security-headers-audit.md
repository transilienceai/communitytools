# Comprehensive Security Headers Audit

## When this applies

- MANDATORY for every engagement. Check ALL response headers, not just the "big 3" (HSTS, CSP, CORS).
- Compliance scope (PCI DSS, GDPR) — missing headers are findings even on otherwise hardened apps.

## Technique

Run a full header audit on the main page AND every API endpoint. Flag missing transport, caching, content-security headers and disclose-leaking headers (Server, X-Powered-By).

## Steps

### Transport security

```
□ Strict-Transport-Security (HSTS) — MUST be present on HTTPS sites
  Expected: max-age=31536000; includeSubDomains; preload
  Severity if missing: Medium (High if HTTP port is open)
  NOTE: If HTTP port (80) is closed, severity is reduced — the downgrade attack requires an initial HTTP connection
□ HTTPS enforcement — test if HTTP port 80 is open and redirects to HTTPS
```

### Caching (critical for authenticated/sensitive responses)

```
□ Cache-Control on API responses — MUST be no-store on sensitive data
  Expected: Cache-Control: no-store, no-cache, must-revalidate
  Also check: Pragma: no-cache (for HTTP/1.0 clients)
  Test: check card numbers, PII, financial data, auth tokens in responses
  Severity if missing: Medium (sensitive data persists in browser/proxy cache after logout)
  Compliance: PCI DSS 6.5.3 (insecure data storage)
```

### Information disclosure headers (suppress in production)

```
□ Server — should not reveal product/version (e.g., "Apache/2.4.41" or "Microsoft-IIS/10.0")
  Expected: Suppress entirely or use generic value
□ X-Powered-By — should be removed (e.g., "ASP.NET", "Express", "PHP/7.4")
□ X-AspNet-Version — should be removed
□ X-AspNetMvc-Version — should be removed
□ Api-Supported-Versions — should not be exposed to unauthenticated users
□ X-Generator — should be removed (reveals CMS/framework)
  Severity: Low (aids reconnaissance, not directly exploitable)
```

### Content security

```
□ Content-Security-Policy (CSP) — check for completeness:
  - script-src: no 'unsafe-inline' or 'unsafe-eval'
  - base-uri: MUST be 'self' (missing allows <base> injection for CSP bypass)
  - object-src: MUST be 'none' (prevents Flash/plugin-based attacks)
  - form-action: should restrict form submission targets
  - frame-ancestors: should be 'none' or 'self'
□ X-Content-Type-Options: nosniff — prevents MIME sniffing
□ X-Frame-Options — must be consistent with CSP frame-ancestors
  If CSP has frame-ancestors 'none', X-Frame-Options should be DENY (not SAMEORIGIN — contradiction)
```

### Privacy & referrer

```
□ Referrer-Policy — prevents URL parameter leakage to third parties
  Expected: strict-origin-when-cross-origin (or stricter)
  Impact: OAuth tokens, session IDs, or sensitive parameters in URLs leak via Referer header
□ Permissions-Policy — restricts browser feature access
  Expected: camera=(), microphone=(), geolocation=(), payment=() (restrict unused features)
```

### Vulnerability disclosure

```
□ /.well-known/security.txt — public vulnerability reporting channel
  Informational finding if missing (best practice, not a vulnerability)
```

### Cookie security (check ALL cookies)

```
□ HttpOnly flag — prevents JavaScript access to session cookies
□ Secure flag — ensures cookies only sent over HTTPS
□ SameSite attribute — prevents CSRF (Lax or Strict)
□ Domain scope — should not be set too broadly (e.g., .example.com leaks to subdomains)
□ Cookie names — avoid internal hostname leakage in cookie names (e.g., ARRAffinity cookie revealing Azure app service names)
```

### Quick header audit script

```bash
# Full header audit — run against main page and API endpoints
URL="https://target.com"
echo "=== Security Headers Audit ==="
HEADERS=$(curl -sI "$URL")
for h in "Strict-Transport-Security" "Content-Security-Policy" "X-Content-Type-Options" \
         "X-Frame-Options" "Referrer-Policy" "Permissions-Policy" "Cache-Control"; do
  echo "$HEADERS" | grep -qi "$h" && echo "[PASS] $h" || echo "[MISS] $h"
done
echo "=== Disclosure Headers (should be absent) ==="
for h in "Server:" "X-Powered-By" "X-AspNet-Version" "X-AspNetMvc-Version" "Api-Supported-Versions"; do
  echo "$HEADERS" | grep -qi "$h" && echo "[LEAK] $h: $(echo "$HEADERS" | grep -i "$h")" || echo "[OK] $h not disclosed"
done
```

### Response headers — what to flag

```
□ Server: Apache/2.4.41 (reveals version)
□ X-Powered-By: PHP/7.4.3
□ X-AspNet-Version
□ X-Framework
□ Custom X-* headers
□ Set-Cookie attributes
```

## Verifying success

- Every required header is present with the expected directives.
- No `Server`, `X-Powered-By`, or version-bearing headers leak.
- Sensitive endpoints set `Cache-Control: no-store`.

## Common pitfalls

- HSTS without `includeSubDomains` is incomplete (subdomains can downgrade).
- CSP with `unsafe-inline` is a token CSP — flag as ineffective.
- `X-Frame-Options: SAMEORIGIN` contradicting CSP `frame-ancestors 'none'` is a finding (browsers prefer CSP, but auditors should flag the inconsistency).

## Tools

- curl `-sI` for HEAD-only header retrieval
- securityheaders.com (public scoring service)
- Mozilla Observatory
- nikto (header analysis)
