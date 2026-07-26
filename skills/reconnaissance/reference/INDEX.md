# Reconnaissance Reference Index

Reference material for `skills/reconnaissance/`. Start with `reconnaissance-principles.md` for the decision tree, then jump to the relevant scenario.

## Principles

- [reconnaissance-principles.md](reconnaissance-principles.md) - decision tree, archetype-driven triage, output layout.

## Scenarios

| Scenario | Use when |
|----------|----------|
| [scenarios/subdomain-enumeration.md](scenarios/subdomain-enumeration.md) | Given a root domain, need to enumerate subdomains via passive + active sources. |
| [scenarios/port-scanning.md](scenarios/port-scanning.md) | Given an IP or host, need open-port and service inventory. |
| [scenarios/vhost-enumeration.md](scenarios/vhost-enumeration.md) | Suspected name-based virtual hosts behind a single IP. |
| [scenarios/api-endpoint-discovery.md](scenarios/api-endpoint-discovery.md) | Web app exposes a backend API; need to map routes, parameters, swagger. |
| [scenarios/obfuscated-js-deobfuscation.md](scenarios/obfuscated-js-deobfuscation.md) | Client-side bundle is JSFuck/packer/Function-wrapper obfuscated; need to recover hidden routes by intercepting the executor. |

## Focused Technique Files

- [anti-bot-bypass.md](anti-bot-bypass.md) - Cloudflare/Turnstile bypass during authorised testing.
- [waf-edge-bypass.md](waf-edge-bypass.md) - WAF/CDN edge triage (Akamai/Sucuri/Imperva/F5-XC/Vercel/CloudFront), direct-origin discovery (access + High finding), real-browser gentle-serial fallback, and the block-page / soft-404 false-positive traps.

## Deterministic tools

- [`../../../tools/dns_email_posture.py`](../../../tools/dns_email_posture.py) - ingest an apex list → enumerate SPF/DKIM/DMARC(+sp)/MTA-STS/TLS-RPT/BIMI/CAA/DNSSEC/MX/security.txt, run positive+negative controls, and emit pre-scored report_data findings. The email/DNS/TLS posture finding-class assembled consistently instead of per-apex `dig` one-liners.
- [`../../../tools/passive_web_probe.py`](../../../tools/passive_web_probe.py) - allow-list-gated passive probe; also the deterministic WAF/CDN block-page classifier + soft-404 content-diff behind [waf-edge-bypass.md](waf-edge-bypass.md).

## Related Skills

- `skills/osint/` - run alongside subdomain enumeration for repository and employee footprinting.
- `skills/techstack-identification/` - stack fingerprints to guide wordlist and endpoint selection.
- `skills/infrastructure/` - port scanning escalation into protocol-level testing.
