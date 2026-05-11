# Physical — Shoulder Surfing

## When this applies

Authorized in-person assessment to test workspace privacy controls: privacy filters, screen orientation, clean-desk policy, and lock-on-leave behavior. Often paired with a tailgating engagement.

**MITRE ATT&CK**: T1056.002 (GUI Input Capture).

## Technique

Observe screens, keyboards, badges, and printed material in working / public areas. Capture credentials, PINs, sensitive content, and access codes either visually, via reflection, or with discreet camera capture.

## Steps

1. Map observation positions: open desks, lobby, coffee shops near offices, customer-facing kiosks, ATM/POS.
2. Plan transit: walk-by, sit-near, reflection in glass / TV / window.
3. Observe and capture (subject to legal and ROE constraints): note time, observed user/role, screen content.
4. Aggregate captures into a chain of evidence (e.g. credential observed → used to access an authorized test account).
5. Document and debrief; recommend privacy filters, lock-screen timer, badge-out-of-sight policy.

### High-value targets

- Login screens (typed username / password)
- ATM / POS PIN entry
- Credit-card numbers in CRM and ticketing tools
- Confidential documents on screen (M&A, HR, finance)
- System configuration UIs (admin consoles)
- Access codes typed at keypads

## Verifying success

- Captured frames clearly show credential / sensitive data without further inference.
- Observation distance and angle documented (proves real-world viability).
- Optional follow-up: replay captured credential against an authorized test account (do not use captured creds against real users without explicit permission).

## Common pitfalls

- Filming without consent in jurisdictions where it is illegal — confirm legal review.
- Catching unintended people in the frame; redact / blur in evidence storage.
- Building a finding from a single fragment — corroborate before reporting.

## Tools

- Mirrorless / phone camera with discreet mount
- Notepad for written observations (timestamped)
- Privacy filter on tester's own device when reviewing captures in shared spaces
