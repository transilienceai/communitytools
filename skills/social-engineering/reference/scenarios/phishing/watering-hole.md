# Phishing — Watering Hole

## When this applies

Authorized red-team scenario where direct phishing has been hardened. Compromise a third-party site that the target organization's employees frequently visit and deliver an exploit / cred-capture from there.

**MITRE ATT&CK**: T1189 (Drive-by Compromise).

## Technique

Identify trusted site visited by employees → assess (with permission) and compromise the site or stage content under a friendly banner → inject capture script that runs only against in-scope client IPs / user agents.

## Steps

1. Identify likely watering holes: industry portals, vendor docs, professional forums, trade-association pages.
2. Validate via OSINT (employee blog posts, conference talk decks, web proxy intelligence).
3. With written authorization from the watering-hole owner, stage payload in a sandbox path under their site.
4. Restrict execution to target IP ranges / user-agent patterns to avoid collateral.
5. Capture endpoint info: IP, browser, plugins, session.
6. Validate compromise path then halt; document attack chain.

## Verifying success

- Payload telemetry shows hits from target ASN / corporate IP ranges only.
- Captured browser/OS data correlates with employee population.
- Optional follow-up: deliver second-stage exploit to validate downstream control (only with explicit permission).

## Common pitfalls

- Compromising a third-party site without consent — out of scope; always coordinate.
- Delivery filter too broad → collateral hits from other visitors.
- Endpoint security flags the script before any meaningful capture; pre-test against the target's EDR profile.

## Tools

- Web proxy / NetFlow analysis to confirm site usage
- Sandbox-only payload host (e.g. attacker-controlled subdomain on the watering-hole site)
- Browser-fingerprint / EDR fingerprinting to constrain delivery
