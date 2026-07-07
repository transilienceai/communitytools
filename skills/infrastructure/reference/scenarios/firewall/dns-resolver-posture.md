# DNS Resolver Posture

## When this applies

- A firewall or perimeter appliance exposes `53/tcp` or `53/udp`.
- You need to distinguish authoritative DNS, recursive DNS, forwarding resolver, and misconfigured open resolver behavior.

## Safety boundaries

- Use single queries or very small bounded query sets.
- Do not perform DNS amplification load testing.
- Do not attempt cache poisoning unless explicitly authorized.

## Core checks

### Recursion over UDP

```bash
dig +time=3 +tries=1 +noall +answer +comments @TARGET example.com A | tee raw/dns-udp-recursion.txt
```

Open recursion indicators:

- `flags: ... rd ra`
- Public third-party answers returned for domains the target is not authoritative for.

### Recursion over TCP

```bash
dig +tcp +time=3 +tries=1 +noall +answer +comments @TARGET example.com A | tee raw/dns-tcp-recursion.txt
```

### Version and hostname disclosure

```bash
dig +time=3 +tries=1 +noall +answer +comments @TARGET version.bind CH TXT
dig +time=3 +tries=1 +noall +answer +comments @TARGET hostname.bind CH TXT
dig +time=3 +tries=1 +noall +answer +comments @TARGET id.server CH TXT
```

### DNSSEC response size

```bash
dig +time=3 +tries=1 +dnssec +bufsize=4096 +stats +comments @TARGET . DNSKEY | tee raw/dns-root-dnskey.txt
```

Record the received message size. Large unauthenticated public responses are amplification-relevant even without running a load test.

### ANY behavior

```bash
dig +time=3 +tries=1 +bufsize=4096 +stats +comments @TARGET isc.org ANY | tee raw/dns-any.txt
```

`NOTIMP`, minimal answers, or refusal reduce classic ANY amplification risk.

### AXFR / IXFR

Use discovered forward or reverse zones. For a PTR-derived reverse zone:

```bash
dig +time=5 +tries=1 @TARGET -x TARGET +short
dig +time=5 +tries=1 @TARGET ZONE AXFR | tee raw/dns-axfr.txt
```

Successful transfer returns SOA plus multiple records and a closing SOA. `Transfer failed` is a negative observation.

## Findings

| Observation | Finding |
|---|---|
| Public third-party recursion over UDP/TCP | Public recursive resolver exposed |
| Large DNSSEC responses to public clients | Amplification-relevant open resolver behavior |
| AXFR succeeds | Zone transfer exposure |
| CHAOS version/hostname disclosed | DNS software/host information disclosure |
| ANY returns large records | Amplification-prone ANY behavior |

## Admin evidence

Request:

- DNS role: authoritative, recursive, forwarding, or firewall DNS proxy.
- Allowed recursion source ranges.
- Response rate limiting configuration.
- DNS logs for test queries.
- Resolver software/version and patch level.
- DNSSEC validation status.

