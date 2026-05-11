# HTTP Request Smuggling — Resources

## Foundational research

- "HTTP Desync Attacks: Request Smuggling Reborn" — James Kettle (PortSwigger, BlackHat USA 2019)
- "HTTP/2: The Sequel is Always Worse" — James Kettle (BlackHat USA 2021)
- "Browser-Powered Desync Attacks" — James Kettle (BlackHat USA 2022)
- "HTTP Request Smuggling in 2020: New Variants, New Defenses" — DEFCON 28
- "Smashing the State Machine" — James Kettle (DEFCON 2023)
- PortSwigger Research blog — https://portswigger.net/research

## Standards

- RFC 7230 — HTTP/1.1 Message Syntax (CL/TE rules)
- RFC 9110 — HTTP Semantics
- RFC 9112 — HTTP/1.1 Semantics
- RFC 7540 / RFC 9113 — HTTP/2

## OWASP / CWE

- CWE-444 — Inconsistent Interpretation of HTTP Requests (HTTP Request Smuggling)
- A06:2021 Vulnerable and Outdated Components
- OWASP Web Security Testing Guide — Request Smuggling

## Notable CVEs

- CVE-2019-18277 — HAProxy 2.0.5 (canonical CL.TE)
- CVE-2025-29927 — Next.js middleware bypass (related)
- CVE-2022-26354 — Apache HTTP Server smuggling
- CVE-2021-40438 — Apache mod_proxy SSRF + smuggling
- CVE-2022-26377 — AJP/HTTP smuggling (Tomcat)
- CVE-2022-32149 — Go net/http smuggling
- CVE-2023-32370 — nginx HTTP/2 smuggling
- CVE-2023-44487 — HTTP/2 Rapid Reset (DoS, related class)

## Affected products / typical positions

- HAProxy 2.0.x (older versions)
- nginx + apache combinations
- AWS ALB / API Gateway downstream
- Cloudflare + various origins
- F5 BIG-IP (SSL termination → backend)
- Akamai + origin
- Fastly + origin
- CDN + cache + origin

## Tools

### Burp extensions

- **HTTP Request Smuggler** — auto-detection (CL.TE, TE.CL, TE.TE, H2.CL, H2.TE) — BApp Store
- **Single-Packet Attack** (built into Burp 2023.9+)
- **Repeater Tab Groups** — "Send group in parallel"
- **Active Scan++** — additional smuggling checks

### Standalone

- **smuggler** — defparam — https://github.com/defparam/smuggler
- **h2cSmuggler** — HTTP/2 Cleartext smuggler
- **h2spacex** — raw HTTP/2 socket attacks via Scapy
- **smudger** — alternative smuggling fuzzer

### Custom Python

```python
import socket
s = socket.socket()
s.connect(('target', 80))
s.sendall(b'POST / HTTP/1.1\r\nHost: target\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG')
print(s.recv(4096))
```

## Vulnerability classes

| Type | Front-End | Back-End |
|------|-----------|----------|
| CL.TE | Content-Length | Transfer-Encoding |
| TE.CL | Transfer-Encoding | Content-Length |
| TE.TE | TE (one ignores obfuscated) | TE (other ignores) |
| H2.CL | HTTP/2 → CL injection | HTTP/1.1 |
| H2.TE | HTTP/2 → TE injection | HTTP/1.1 |
| H2 Tunneling | HTTP/2 header CRLF | HTTP/1.1 |
| CL.0 | Content-Length | Ignores CL |
| Pause-based | Stream + pause | Connection-state desync |

## TE obfuscation variants (TE.TE)

```
Transfer-Encoding: xchunked
Transfer-Encoding : chunked
Transfer-Encoding: chunked
Transfer-Encoding: x
Transfer-encoding: identity
Transfer-encoding: chunked
```

## Practice / labs

- Web Security Academy — HTTP Request Smuggling — https://portswigger.net/web-security/request-smuggling
- TryHackMe — Request Smuggling rooms
- Custom CTFs (PortSwigger CTF, Hack The Box CTFs)

## Exploitation patterns (as scenarios in this repo)

1. Bypass front-end security (`scenarios/http-smuggling/exploitation-patterns.md`)
2. Capture user data
3. Cache poisoning
4. XSS amplification
5. Docker network bypass (Pattern 5 in exploitation-patterns)

## Detection / monitoring

- nginx access logs — look for repeated 400 errors after CL/TE pairs
- AWS WAF / Cloudflare Bot Management
- Application Performance Monitoring — anomalous response times
- Splunk: `index=web_logs status=400 | stats count by src_ip`

## Defensive references

- Disable HTTP/1.1 keep-alive on multi-tier deployments where not needed
- Reject requests with both Content-Length AND Transfer-Encoding
- Reject obfuscated TE headers (whitespace, non-`chunked` values)
- Use HTTP/2 end-to-end (still has H2.X risks but smaller surface)
- Front-end + back-end same vendor (reduces parser disagreement)

## Frameworks reference

- HAProxy 2.x — `option http-server-close`, `tune.h2.*`
- nginx — `proxy_http_version 1.1`
- Apache 2.4 — patched in recent versions
- Tomcat / Jetty — patched recent
- AWS ALB / NLB — generally robust
- Envoy — generally robust

## Bug bounty programs (high smuggling yield)

- HackerOne — Twitter (X), Slack, GitHub, GitLab, GitHub Pages
- Bugcrowd — Tesla
- Self-hosted — Slack, Stripe, PayPal

## Cheat-sheet companions in this repo

- `scenarios/http-smuggling/cl-te.md`
- `scenarios/http-smuggling/te-cl.md`
- `scenarios/http-smuggling/te-te-obfuscation.md`
- `scenarios/http-smuggling/h2-downgrade.md`
- `scenarios/http-smuggling/cl-zero-and-pause-based.md`
- `scenarios/http-smuggling/exploitation-patterns.md`
