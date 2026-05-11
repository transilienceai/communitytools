# Business Logic Vulnerabilities — Resources

## OWASP

- OWASP Top 10 (2021) — A04 Insecure Design
- OWASP Top 10 — A05 Security Misconfiguration
- OWASP API Top 10 — API6:2023 Unrestricted Access to Sensitive Business Flows
- OWASP Web Security Testing Guide — Business Logic Testing — https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/
- OWASP Cheat Sheet — Business Logic Security
- OWASP ASVS V11 — Business Logic

## CWE

- CWE-840 — Business Logic Errors
- CWE-841 — Improper Enforcement of Behavioral Workflow
- CWE-639 — Authorization Bypass via User-Controlled Key
- CWE-841 — Workflow Bypass
- CWE-565 — Reliance on Cookies without Validation
- CWE-602 — Client-Side Enforcement of Server-Side Security
- CWE-754 — Improper Check for Unusual Conditions
- CWE-1284 — Improper Validation of Specified Quantity in Input
- CWE-682 — Incorrect Calculation

## Notable disclosure cases

- Coinbase 2025 — $250K bounty, asset-type mismatch in trading API
- Starbucks 2018 — gift-card race condition
- HackerOne — historical reports tagged `business-logic`
- GitHub 2012 — mass assignment public-key upload
- Multiple e-commerce — coupon stacking, negative quantity, integer overflow

## Tools

### Burp extensions

- **Turbo Intruder** — race conditions and rapid logic testing
- **Param Miner** — hidden parameter discovery
- **Logger++** — pattern matching across history
- **Auto Repeater** — replay across roles for vertical privesc
- **Custom Burp extension** — pattern-based passive scan (see `scenarios/business-logic/burp-extension-scanner.md`)

### Standalone

- **OWASP ZAP** — fuzzing and active scan
- **Postman** — workflow testing
- **k6 / artillery** — load + race testing
- **race-the-web** — race condition fuzzer
- **GraphQL Cop** — for GraphQL business-logic flows

### Custom scripts

- Negative quantity calculator (Python)
- Integer overflow generator (Bash + Burp Intruder null payloads)
- Coupon stacker (Python class — see `scenarios/business-logic/coupon-stacking.md`)
- Gift card loop (Python class)

## PortSwigger / labs

- Web Security Academy — Business Logic labs — https://portswigger.net/web-security/logic-flaws
- TryHackMe — Business Logic rooms

## Standards

- PCI DSS 6.5 — Address Common Coding Vulnerabilities
- NIST SP 800-53 — SI-10 Information Input Validation, AC-3 Access Enforcement
- ISO 27001 / ISO 27034
- SOX (financial integrity in business workflows)

## Attack technique writeups

- PortSwigger — Logic Flaws series
- HackerOne — disclosed reports tagged `business-logic`
- Bishop Fox — "Logic Flaws You Find in Bug Bounty"
- NCC Group — "Web Logic Vulnerabilities"
- "OWASP Testing Guide — Business Logic"
- "API6 Lab" — APIsec
- BlackHat / DEFCON talks on logic flaws
- swisskyrepo/PayloadsAllTheThings — Business Logic Testing

## Detection / monitoring

- WAF rules for negative-quantity, large-quantity, repeated-coupon
- Splunk searches for anomalous order totals
- Datadog / NewRelic transaction analytics
- Custom Application Security Monitoring (ASM) signatures

## Frameworks reference

- Stripe / PayPal payment flows
- Shopify checkout / discount stacking
- WooCommerce / Magento order pipelines
- SAP / Salesforce CPQ workflows

## Defensive references

- Validate every business-critical parameter server-side
- Use atomic database operations for race-prone logic (SELECT FOR UPDATE)
- Idempotency keys for state-changing operations
- Approval workflows / two-person integrity for high-value actions
- Cost-based throttling for repeatable flows (gift card, coupon)
- Fraud detection (Sift, Stripe Radar, Riskified)
- Anomaly detection (statistical or ML-based)

## Practice / learning

- TryHackMe — Logic Flaws path
- PicoCTF / RingZer0 — workflow CTF challenges
- BugBountyHunter.com courses
- Burp Suite Certified Practitioner (BSCP) — covers business logic

## Bug bounty programs (high logic-flaw yield)

- HackerOne — Shopify, Coinbase, GitLab, Tesla
- Bugcrowd — Atlassian
- Intigriti — European SaaS
- Self-hosted programs at trading platforms (Binance, Kraken)

## Cheat-sheet companions in this repo

- `scenarios/business-logic/price-manipulation.md`
- `scenarios/business-logic/quantity-manipulation.md`
- `scenarios/business-logic/coupon-stacking.md`
- `scenarios/business-logic/email-domain-bypass.md`
- `scenarios/business-logic/workflow-bypass.md`
- `scenarios/business-logic/gift-card-loop.md`
- `scenarios/business-logic/parameter-pollution.md`
- `scenarios/business-logic/regex-input-validation-bypass.md`
- `scenarios/business-logic/csrf-and-session-bypass.md`
- `scenarios/business-logic/burp-extension-scanner.md`
- See also `scenarios/race-conditions/` for race-prone flows.
