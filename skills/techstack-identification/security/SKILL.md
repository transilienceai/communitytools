---
name: techstack-security
description: Security-posture and third-party SaaS identification — security headers, CSP, HSTS, email auth, security.txt, plus payments/analytics/auth/CRM/support integrations.
---

# Security Posture & Third-Party Tech-Stack

## Scope

Two related lenses on a target:

1. **Security posture** — HTTP security headers, Content Security Policy, HSTS, email auth (SPF/DKIM/DMARC/MTA-STS), `security.txt`, certificate practices.
2. **Third-party / SaaS detection** — payment processors, analytics, customer support, identity providers, CRM/marketing, error monitoring, A/B testing, social/communication SDKs, media CDNs.

The two are coupled: CSP `script-src` and DNS `TXT` verifications reveal third-party services, while third-party domains contribute to the overall security surface.

## Signals (input)

- HTTP response headers — security headers, CSP directives, HSTS
- DNS TXT records — SPF, DKIM, DMARC, SaaS verification tokens
- HTML — meta-tag security policies, embedded widgets/iframes
- Loaded JS / script-src URLs and globals
- `/.well-known/security.txt`, `/security.txt`, `/.well-known/change-password`

## Inferences (output)

- Security score (header coverage, CSP strength, email-auth strength, security.txt presence)
- CSP analysis (unsafe-inline/eval issues, allowed third-party domains)
- Email-auth grade (DMARC policy strength)
- Third-party SaaS catalogue by category, with integration mode (client SDK vs CSP-only vs DNS-only)

## Techniques

See [reference/patterns.md](reference/patterns.md).

## When to use

- Pre-engagement security baseline
- Mapping supply-chain / SaaS exposure
- Identifying integrations that grant pivot opportunities (Auth0, Stripe webhook surface, Sentry DSN leakage, etc.)
- Phase 3 of tech-stack OSINT
