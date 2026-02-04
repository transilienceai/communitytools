---
name: third-party-detector
description: Identifies third-party services including payments, analytics, auth, CRM, and support
tools: Read, Grep
model: inherit
hooks:
  PostToolUse:
    - matcher: "Read"
      hooks:
        - type: command
          command: "../../../hooks/skills/post_output_validation_hook.sh"
---

# Third-Party Detector Skill

## Purpose

Identify third-party services integrated into the target's technology stack including payments, analytics, authentication, CRM, support, and other SaaS tools.

## Input

Raw signals from Phase 2:
- `javascript_signals` - Third-party script URLs, analytics globals
- `html_signals` - Widget embeds, script tags
- `dns_signals` - Service verification TXT records
- `http_signals` - CSP allowed domains
- `job_signals` - Tool mentions

## Service Categories

### Payment Processing

| Service | Detection Signals | Weight |
|---------|-------------------|--------|
| Stripe | js.stripe.com, Stripe.js, api.stripe.com in CSP | 40 |
| PayPal | paypal.com scripts, PayPal buttons | 35 |
| Square | squareup.com, Square SDK | 35 |
| Braintree | braintreegateway.com | 35 |
| Adyen | adyen.com scripts | 35 |
| Klarna | klarna.com scripts | 30 |
| Affirm | affirm.com scripts | 30 |
| Plaid | plaid.com scripts (banking) | 35 |

### Analytics & Tracking

| Service | Detection Signals | Weight |
|---------|-------------------|--------|
| Google Analytics | google-analytics.com, gtag, ga() | 40 |
| Google Tag Manager | googletagmanager.com, dataLayer | 40 |
| Segment | cdn.segment.com, analytics.js | 40 |
| Mixpanel | cdn.mxpnl.com, mixpanel global | 40 |
| Amplitude | cdn.amplitude.com | 40 |
| Heap | heap-analytics.com | 35 |
| Hotjar | static.hotjar.com, hj global | 35 |
| FullStory | fullstory.com, FS global | 35 |
| Pendo | pendo.io scripts | 35 |
| Posthog | posthog.com, ph global | 35 |

### Customer Support

| Service | Detection Signals | Weight |
|---------|-------------------|--------|
| Intercom | intercom.io, Intercom widget | 40 |
| Zendesk | zendesk.com, zd-chat | 40 |
| Freshdesk | freshdesk.com scripts | 35 |
| Drift | drift.com, Drift widget | 35 |
| HubSpot Chat | hubspot.com, hs-scripts | 35 |
| Crisp | crisp.chat | 30 |
| Tawk.to | tawk.to scripts | 30 |
| LiveChat | livechat.com | 30 |

### Authentication & Identity

| Service | Detection Signals | Weight |
|---------|-------------------|--------|
| Auth0 | auth0.com, Auth0 SDK | 40 |
| Okta | okta.com scripts | 40 |
| Firebase Auth | firebase.google.com/auth | 40 |
| Clerk | clerk.dev scripts | 35 |
| AWS Cognito | cognito-idp patterns | 35 |
| Azure AD | login.microsoftonline.com | 35 |

### CRM & Marketing

| Service | Detection Signals | Weight |
|---------|-------------------|--------|
| Salesforce | salesforce.com patterns | 40 |
| HubSpot | hubspot.com, hs-scripts | 40 |
| Marketo | marketo.com, munchkin | 35 |
| Mailchimp | mailchimp.com scripts | 35 |
| SendGrid | sendgrid.net TXT records | 35 |
| Intercom | intercom.io (CRM features) | 35 |
| Pipedrive | pipedrive.com | 30 |
| Pardot | pardot.com | 35 |

### Error & Performance Monitoring

| Service | Detection Signals | Weight |
|---------|-------------------|--------|
| Sentry | sentry.io, Sentry SDK | 40 |
| Datadog RUM | datadoghq.com RUM | 40 |
| New Relic | newrelic.com, NREUM | 35 |
| Bugsnag | bugsnag.com | 35 |
| LogRocket | logrocket.com | 35 |
| Rollbar | rollbar.com | 35 |

### A/B Testing & Experimentation

| Service | Detection Signals | Weight |
|---------|-------------------|--------|
| Optimizely | optimizely.com | 40 |
| LaunchDarkly | launchdarkly.com | 40 |
| VWO | vwo.com scripts | 35 |
| Google Optimize | optimize.google.com | 35 |
| Split.io | split.io | 35 |
| Statsig | statsig.com | 35 |

### CDN & Media

| Service | Detection Signals | Weight |
|---------|-------------------|--------|
| Cloudinary | cloudinary.com | 35 |
| imgix | imgix.net | 35 |
| Vimeo | vimeo.com, player.vimeo.com | 30 |
| YouTube | youtube.com embeds | 30 |
| Wistia | wistia.com | 30 |

### Social & Communication

| Service | Detection Signals | Weight |
|---------|-------------------|--------|
| Slack | slack.com integrations | 30 |
| Discord | discord.com widgets | 30 |
| Twitter/X | twitter.com widgets, platform.twitter.com | 30 |
| Facebook | facebook.com SDK, connect.facebook.net | 35 |
| LinkedIn | linkedin.com tracking | 30 |

## Detection Logic

```python
def detect_third_party_services(signals):
    results = []

    # JavaScript/Script Tag Detection
    for script_url in signals.javascript_signals.script_urls:
        for service in THIRD_PARTY_SERVICES:
            for pattern in service.script_patterns:
                if pattern in script_url:
                    add_service(results, service.name, service.category, {
                        "type": "script_url",
                        "value": script_url,
                        "weight": service.weight
                    })

    # JavaScript Global Detection
    for global_var in signals.javascript_signals.globals:
        for service in THIRD_PARTY_SERVICES:
            if service.global_var and service.global_var in global_var:
                add_service(results, service.name, service.category, {
                    "type": "js_global",
                    "value": global_var,
                    "weight": service.weight
                })

    # CSP Domain Detection
    if signals.http_signals.csp:
        csp_domains = extract_domains(signals.http_signals.csp)
        for domain in csp_domains:
            for service in THIRD_PARTY_SERVICES:
                if any(pattern in domain for pattern in service.domain_patterns):
                    add_service(results, service.name, service.category, {
                        "type": "csp_domain",
                        "value": domain,
                        "weight": service.weight - 10  # Slightly lower weight
                    })

    # DNS TXT Record Detection
    for txt in signals.dns_signals.txt_records:
        for service in THIRD_PARTY_SERVICES:
            if service.txt_pattern and service.txt_pattern in txt:
                add_service(results, service.name, service.category, {
                    "type": "dns_txt",
                    "value": txt,
                    "weight": service.weight
                })

    # Job Posting Detection
    if signals.job_signals:
        for tech_mention in signals.job_signals.tech_mentions:
            for service in THIRD_PARTY_SERVICES:
                if service.name.lower() in tech_mention.technology.lower():
                    add_service(results, service.name, service.category, {
                        "type": "job_posting",
                        "value": f"Mentioned in job postings",
                        "weight": 20  # Lower weight for job signals
                    })

    return results
```

## Output

```json
{
  "skill": "third_party_detector",
  "results": {
    "technologies": [
      {
        "name": "Stripe",
        "category": "Payment Processing",
        "signals": [
          {
            "type": "script_url",
            "value": "https://js.stripe.com/v3/",
            "weight": 40
          },
          {
            "type": "csp_domain",
            "value": "api.stripe.com in CSP",
            "weight": 30
          }
        ],
        "total_weight": 70,
        "integration_type": "Client-side SDK"
      },
      {
        "name": "Google Analytics 4",
        "category": "Analytics",
        "signals": [
          {
            "type": "script_url",
            "value": "https://www.googletagmanager.com/gtag/js",
            "weight": 40
          },
          {
            "type": "js_global",
            "value": "gtag() function detected",
            "weight": 35
          }
        ],
        "total_weight": 75,
        "tracking_id": "G-XXXXXXXXXX"
      },
      {
        "name": "Intercom",
        "category": "Customer Support",
        "signals": [
          {
            "type": "script_url",
            "value": "https://widget.intercom.io/widget/",
            "weight": 40
          }
        ],
        "total_weight": 40,
        "integration_type": "Chat Widget"
      },
      {
        "name": "Sentry",
        "category": "Error Monitoring",
        "signals": [
          {
            "type": "script_url",
            "value": "https://browser.sentry-cdn.com/",
            "weight": 40
          }
        ],
        "total_weight": 40,
        "integration_type": "Client-side SDK"
      },
      {
        "name": "Auth0",
        "category": "Authentication",
        "signals": [
          {
            "type": "csp_domain",
            "value": "*.auth0.com in CSP",
            "weight": 35
          },
          {
            "type": "job_posting",
            "value": "Auth0 mentioned in job requirements",
            "weight": 20
          }
        ],
        "total_weight": 55
      }
    ],
    "services_by_category": {
      "Payment Processing": ["Stripe"],
      "Analytics": ["Google Analytics 4", "Google Tag Manager"],
      "Customer Support": ["Intercom"],
      "Error Monitoring": ["Sentry"],
      "Authentication": ["Auth0"]
    },
    "integration_summary": {
      "total_services": 5,
      "categories_covered": 5,
      "client_side_integrations": 4,
      "server_side_likely": ["Auth0", "Stripe"]
    }
  }
}
```

## Confidence Notes

Third-party detection confidence varies by signal type:

| Signal Type | Confidence | Notes |
|-------------|------------|-------|
| Script URL | High (90%) | Direct integration |
| JS Global | High (85%) | Library loaded |
| CSP Domain | Medium (75%) | May be unused |
| DNS TXT | High (90%) | Official verification |
| Job Posting | Low (60%) | May be planned/legacy |

## Error Handling

- Missing scripts: May indicate server-side only integration
- Multiple analytics: Common - report all
- Deprecated services: Note if detected
