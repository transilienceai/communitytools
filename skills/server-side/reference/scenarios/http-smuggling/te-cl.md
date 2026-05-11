# HTTP Request Smuggling — TE.CL

## When this applies

- Front-end uses `Transfer-Encoding`; back-end uses `Content-Length`.
- Reverse of CL.TE — same impact, different parsing direction.
- Goal: smuggle a request that the front-end forwards completely (chunked), but the back-end truncates at CL.

## Technique

Send a POST with both `Transfer-Encoding: chunked` and `Content-Length: <small>`. Front-end follows TE (forwards full chunks). Back-end follows CL — bytes after CL form the start of the next request.

## Steps

### Basic TE.CL payload

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0


```

### Time-based detection

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Transfer-Encoding: chunked
Content-Length: 6

0

X
```

If vulnerable, application hangs waiting for Content-Length bytes.

### Mechanism

- Front-end recognizes Transfer-Encoding (uses TE)
- Back-end does not (uses CL)
- Front-end forwards full chunked body; back-end reads `Content-Length` bytes and ignores the rest
- The remainder bytes start the next request on that back-end connection

### Impact

- Reverse of CL.TE — same attack capabilities
- Capture user data, bypass front-end security, cache poisoning, XSS amplification

## Verifying success

- Time-based test reveals hang (CL bytes never delivered).
- Differential response (404 / 500) on the second request when smuggling completes.
- Smuggled GET shows up as content in the next user's response.

## Common pitfalls

- CL/TE order matters — some apps prefer the LAST header (TE), some the FIRST (CL).
- Modern proxies often reject both headers — test direct origin.
- Need to count bytes precisely (chunk-size in hex, then chunk data, then `0\r\n\r\n`).

## Tools

- Burp Suite Repeater (HTTP/1.1)
- Burp HTTP Request Smuggler BApp (auto-detects)
- Custom smuggler scripts
