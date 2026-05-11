# Physical — Dumpster Diving

## When this applies

Authorized OSINT/physical assessment to demonstrate information leakage from discarded paper, hardware, or media. Tests document destruction policy, hardware sanitization workflow, and chain of custody for retired equipment.

## Technique

Search outdoor / nearby trash and recycling for sensitive material that ended up in general waste rather than secure-shred. Optionally extend to discarded electronics: hard drives, USB sticks, optical media.

## Steps

1. Confirm jurisdiction (ownership of the bin, time of pickup, legal scope) and ROE.
2. Approach during low-foot-traffic windows; carry authorization letter.
3. Photograph contents in situ before removal; bag for later analysis.
4. Triage: paperwork, sticky-notes, sealed envelopes, old hardware, optical media.
5. Secure analysis: read contents, image any drives, classify findings.
6. Return materials per ROE (or shred yourself with the client's witness).
7. Report findings + remediation (shred policy, e-waste vendor audit).

### High-value targets

- Printed documents (drafts, internal memos, customer letters)
- Sticky notes (especially around monitors and keyboards) — passwords / hostnames
- Old hardware (HDDs, SSDs, backup tapes, mobile devices)
- Employee directories, organizational charts, network diagrams
- Discarded badges, key cards, parking permits
- Company letterhead and signed templates (BEC fuel)

## Verifying success

- Photographs of high-impact finds (e.g. password sticky note, internal IP map, exec letterhead).
- Image captures of recoverable data on discarded drives (no destructive analysis without explicit permission).
- Inventory list mapped to severity for the report.

## Common pitfalls

- Trespass — confirm bin location is on permitted property.
- Privacy regulations on personal data found incidentally (GDPR / state privacy laws): handle and dispose securely.
- Mixing test material with personal items by accident — strict bagging and labeling.

## Tools

- Gloves, headlamp, sealed evidence bags, marker
- Camera for in-situ documentation
- Forensic imaging kit for any retrieved storage (write-blocker, imager)
- Authorization letter on hand at all times
