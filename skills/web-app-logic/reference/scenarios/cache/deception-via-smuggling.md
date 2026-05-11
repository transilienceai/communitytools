# Cache Deception via HTTP Request Smuggling

## When this applies

- Front-end and back-end disagree on `Content-Length` vs `Transfer-Encoding` parsing (CL.TE smuggling).
- Cache stores responses keyed on the FIRST-line URL of each request the cache parses.
- Goal: smuggle a GET for a sensitive endpoint, append the next user's request to it, cache the user's response under the smuggled URL.

## Technique

Send a smuggling payload whose smuggled GET targets `/my-account`. The next request from any user concatenates onto the smuggled GET. The response (with that user's auth context) is cached under the smuggled URL the attacker controls.

## Steps

### Payload

```http
POST / HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 42
Transfer-Encoding: chunked

0

GET /my-account HTTP/1.1
X-Ignore: X
```

### Exploit flow

1. Send smuggling payload
2. Victim's request appends to smuggled GET
3. Victim's response gets cached
4. Access cached response

### Configuration tips

**Repeater Settings:**
- Switch to HTTP/1 (for smuggling)
- Disable automatic redirects
- Show all headers

## Verifying success

- The smuggling proves out (timing or content anomaly on subsequent requests).
- A request to the smuggled URL returns sensitive data that belongs to a DIFFERENT user.
- Cache hit confirmed via `X-Cache: hit` and `Age:` set on the poisoned URL.

## Common pitfalls

- HTTP/2 does not support smuggling in this form — must use HTTP/1.1 in Burp Repeater.
- Modern proxies (Cloudflare, AWS ALB) reject `Content-Length` + `Transfer-Encoding` in the same request — test against direct origin if reachable.
- Race against legitimate user traffic — high-traffic sites poison faster.

## Tools

- Burp Suite Repeater (HTTP/1.1)
- Burp HTTP Request Smuggler BApp
- See `skills/server-side/reference/scenarios/http-smuggling/` for full smuggling reference
