# Security Posture & Third-Party Detection Patterns

Consolidated from `security_posture_analyzer`, `third_party_detector`.

## Security Headers

| Header | Strong setting | Notes |
|--------|----------------|-------|
| Strict-Transport-Security | `max-age>=31536000; includeSubDomains; preload` | preload eligible |
| Content-Security-Policy | restrictive `default-src 'self'` + nonces/hashes | see CSP analysis |
| X-Frame-Options | `DENY` (or `SAMEORIGIN`) | CSP `frame-ancestors` supersedes |
| X-Content-Type-Options | `nosniff` | always set |
| Referrer-Policy | `strict-origin-when-cross-origin` (or stricter) | — |
| Permissions-Policy | comprehensive deny-list | replaces Feature-Policy |
| Cross-Origin-Opener-Policy | `same-origin` | enables COEP isolation |
| Cross-Origin-Embedder-Policy | `require-corp` | + COOP for cross-origin isolation |
| Cross-Origin-Resource-Policy | `same-origin` / `same-site` | — |
| X-XSS-Protection | `0` (legacy header, modern browsers ignore) | — |

Score header presence + strength (e.g. 0-10 each), aggregate to grade A-F.

## CSP Analysis

Parse `Content-Security-Policy` into directives. Flags:

| Issue | Severity |
|-------|----------|
| `'unsafe-inline'` in `script-src` | High — XSS bypass |
| `'unsafe-eval'` | High — code injection risk |
| `script-src *` or wildcard hosts | High |
| Missing `script-src` and `default-src` | High |
| `data:` in `script-src` | Medium |
| No `frame-ancestors` | Medium (clickjacking) |

Strengths: `upgrade-insecure-requests`, `report-uri`/`report-to`, `default-src 'self'`, nonce/hash usage, `frame-ancestors 'none'`.

Extract host allow-list from CSP (`https://([^\s;'\"]+)`) → feed into third-party detection.

Security level: Strong (no issues + 3+ strengths) / Moderate (≤1 issue) / Weak (>1 issue).

## Email Security (DNS)

| Record | Strong | Notes |
|--------|--------|-------|
| SPF | `v=spf1 include:... -all` | hardfail beats softfail (`~all`) |
| DKIM | DKIM1 selector(s) present | check key length ≥ 1024 |
| DMARC | `v=DMARC1; p=reject; rua=...` | `p=quarantine` ok; `p=none` weak |
| MTA-STS | `_mta-sts.<domain>` TXT + policy doc | enforces TLS |

## Discovery Files

```
/.well-known/security.txt
/security.txt
/.well-known/change-password
/humans.txt
```

`security.txt` fields: `Contact:`, `Encryption:`, `Policy:`, `Hiring:`, `Expires:`. Presence is a positive signal; expired = degraded.

## Third-Party Service Catalogue

Detection signals: (a) `<script src=...>` host, (b) JS global, (c) CSP allow-list domain, (d) DNS TXT verification, (e) job-posting mention (lowest confidence).

### Payments

Stripe (`js.stripe.com`, `Stripe`, `api.stripe.com` CSP), PayPal, Square (`squareup.com`), Braintree (`braintreegateway.com`), Adyen, Klarna, Affirm, Plaid (`plaid.com` — banking).

### Analytics & Tracking

Google Analytics (`gtag`, `ga`, `dataLayer`, `google-analytics.com`, `googletagmanager.com`), Segment (`cdn.segment.com`, `analytics`), Mixpanel (`cdn.mxpnl.com`), Amplitude (`cdn.amplitude.com`), Heap (`heap-analytics.com`), Hotjar (`static.hotjar.com`, `hj`), FullStory (`fullstory.com`, `FS`), Pendo (`pendo.io`), PostHog (`posthog.com`).

### Customer Support / Chat

Intercom (`intercom.io`, `Intercom`), Zendesk (`zendesk.com`), Freshdesk, Drift (`drift.com`), HubSpot Chat (`hs-scripts`), Crisp (`crisp.chat`), Tawk.to, LiveChat.

### Authentication / Identity

Auth0 (`auth0.com`), Okta (`okta.com`), Firebase Auth (`firebase.google.com/auth`), Clerk (`clerk.dev`), AWS Cognito (`cognito-idp.<region>.amazonaws.com`), Azure AD / Entra ID (`login.microsoftonline.com`).

### CRM & Marketing

Salesforce, HubSpot (`hs-scripts`, `hubspot.com`), Marketo (`munchkin.js`), Mailchimp, SendGrid (TXT), Pardot, Pipedrive.

### Error & Performance Monitoring

Sentry (`sentry.io`, browser SDK), Datadog RUM (`datadoghq.com`), New Relic (`NREUM` global, `newrelic.com`), Bugsnag, LogRocket, Rollbar.

### A/B Testing & Feature Flags

Optimizely, LaunchDarkly, VWO, Google Optimize, Split.io, Statsig.

### Media / Image / Video CDN

Cloudinary (`cloudinary.com`), imgix (`imgix.net`), Vimeo / `player.vimeo.com`, YouTube embeds, Wistia.

### Social SDK / Communication

Slack widget, Discord widgets, Twitter/X (`platform.twitter.com`), Facebook SDK (`connect.facebook.net`), LinkedIn tracking.

## Confidence by Signal Type

| Signal | Confidence |
|--------|-----------|
| `<script src>` direct host | 90% |
| JS global present | 85% |
| DNS TXT verification | 90% (official) |
| CSP allow-listed domain | 75% (may be unused) |
| Job-posting mention only | 60% |

## CSP-Domain → Service Quick Map

`*.stripe.com` Stripe · `*.google-analytics.com` / `*.googletagmanager.com` GA / GTM · `*.facebook.com` Meta · `*.intercom.io` Intercom · `*.zendesk.com` Zendesk · `*.sentry.io` Sentry · `*.datadog*.com` Datadog · `*.newrelic.com` New Relic · `*.auth0.com` Auth0 · `*.optimizely.com` Optimizely · `*.cloudflare.com` Cloudflare assets.

## Recommendations Output

For each missing/weak header or insecure CSP directive, emit `{priority, item, current, recommended}` so reports can list remediation steps next to detection.
