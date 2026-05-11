# Race Conditions — Resources

## OWASP

- A04:2021 Insecure Design (covers race conditions)
- A01:2021 Broken Access Control (relevant for TOCTOU)
- OWASP Web Security Testing Guide — Race Condition Testing — https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/
- OWASP Cheat Sheet — Concurrency

## CWE

- CWE-362 — Race Condition (TOCTOU)
- CWE-367 — TOCTOU
- CWE-364 — Signal Handler Race Condition
- CWE-366 — Race Condition within a Thread
- CWE-833 — Deadlock

## James Kettle research (PortSwigger)

- "Smashing the state machine: the true potential of web race conditions" (DEFCON 2023, BlackHat USA 2023)
- HTTP/2 Single-Packet Attack
- "Hiding in Plain Sight: Single-Packet Attacks Against HTTP/2"
- PortSwigger Research blog — https://portswigger.net/research

## Notable CVE / disclosure cases

- Web cache poisoning + race conditions (multiple CVEs)
- HackerOne disclosed: Shopify, GitLab, Slack race condition reports
- TOCTOU file upload — CVE-2019-19844 (Django)
- Race condition in user registration — multiple breach reports

## Tools

### Burp extensions

- **Turbo Intruder** — Python scripting engine for race attacks
- **HTTP/2 Single-Packet Attack** (built into Burp 2023.9+)
- **Repeater Tab Groups** — "Send group in parallel (single-packet attack)"
- **Logger++** — timing analysis

### Standalone

- **h2spacex** — raw HTTP/2 socket attacks via Scapy — `pip install h2spacex`
- **Raceocat** — streamlined race condition CLI
- **race-the-web** — race condition fuzzer
- **Apache Bench (ab)** — basic concurrent requests
- **GNU parallel** — multi-process curl
- Custom Python `concurrent.futures.ThreadPoolExecutor`

### Templates

- `race-single-packet-attack.py` (Burp Turbo Intruder)
- `race-last-byte-sync.py` (HTTP/1.1 alternative)

## PortSwigger / labs

- Web Security Academy — Race Conditions — https://portswigger.net/web-security/race-conditions
- TryHackMe — race condition rooms

## Attack technique writeups

- PortSwigger Research — Single-Packet Attack writeup
- HackerOne disclosed reports tagged `race-condition`
- Trail of Bits — concurrency bug reports
- "Race Conditions on the Web" — Snyk
- swisskyrepo/PayloadsAllTheThings — Race Condition

## Detection / monitoring

- Database isolation level monitoring (look for READ UNCOMMITTED)
- Audit logs for duplicate operations (same user, same action, ms apart)
- Splunk / Sentinel queries for repeat operations within 100ms
- Distributed-tracing tools (Jaeger, Zipkin)

## Defensive references

- Atomic database operations (UPDATE ... RETURNING, INSERT ... ON CONFLICT)
- Pessimistic locking (SELECT FOR UPDATE)
- Optimistic locking (version fields, ETags)
- Distributed locks (Redis SETNX, Redlock)
- Idempotency keys (RFC draft)
- Single-threaded message queues for critical paths
- SERIALIZABLE isolation for sensitive tables
- Database-level unique constraints

## Frameworks reference

- Java — `synchronized`, `ReentrantLock`, JPA optimistic locks
- Node — `redlock`, `bull` queue with concurrency=1
- Python — Django `select_for_update()`, Celery single-worker
- Ruby on Rails — `ActiveRecord::Locking::Optimistic`
- PostgreSQL — `BEGIN ISOLATION LEVEL SERIALIZABLE`

## Practice / learning

- "The Little Book of Semaphores"
- Concurrency in Practice (Brian Goetz)
- PortSwigger BSCP — covers race conditions
- HackerOne disclosed reports archive

## Bug bounty programs (high race-condition yield)

- HackerOne — Coinbase, GitLab, Shopify (gift cards, coupons, KYC bypass)
- Bugcrowd — Tesla, Atlassian
- Intigriti — European fintech

## Single-packet attack details

- HTTP/2: all requests in ONE TCP packet → simultaneous server-side processing
- HTTP/1.1: last-byte synchronization (withhold final byte, then release)
- Connection warming: 5 GETs to `/` before attack to reduce latency variance
- Session locking bypass: provision multiple cookies with `curl -c cookies1.txt` etc.
- Gates (Turbo Intruder): `engine.queue(req, gate='race1'); engine.openGate('race1')`

## TOCTOU session race details

- Verify-then-use gap with `READ UNCOMMITTED` isolation
- Three thread pools: flip_admin (write attacker username), flip_valid (restore), check (read protected page)
- See `scenarios/race-conditions/toctou-session.md` for full Python PoC

## Cheat-sheet companions in this repo

- `scenarios/race-conditions/limit-overrun.md`
- `scenarios/race-conditions/multi-endpoint.md`
- `scenarios/race-conditions/single-endpoint-collision.md`
- `scenarios/race-conditions/partial-construction.md`
- `scenarios/race-conditions/timestamp-collision.md`
- `scenarios/race-conditions/file-upload-race.md`
- `scenarios/race-conditions/rate-limit-bypass.md`
- `scenarios/race-conditions/toctou-session.md`
- `scenarios/race-conditions/advanced-techniques.md`
- `scenarios/race-conditions/detection-and-baseline.md`
