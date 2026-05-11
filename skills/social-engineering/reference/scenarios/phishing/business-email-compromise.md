# Phishing — Business Email Compromise (BEC)

## When this applies

Targeting finance, HR, or executive-assistant roles to authorize fraudulent transactions, divert payroll, or extract sensitive data. Authorized BEC simulation tests both detection (mail gateway, anomaly analytics) and human controls (multi-person approval, callback verification).

## Technique

Spoof or impersonate an executive / vendor / attorney via email and request a high-trust action under time pressure: wire transfer, gift card purchase, payroll re-routing, W-2 disclosure, invoice change.

**Variants**: CEO fraud, account compromise (via takeover), attorney impersonation, data theft (HR/payroll), invoice scam.
**MITRE ATT&CK**: T1566.002 (Spearphishing Link/Action).

## Steps

1. OSINT: identify executives, exec assistants, finance approvers, vendor relationships, payment cadence, signing styles.
2. Acquire similar/lookalike domain or compromise an in-domain mailbox (test environment only).
3. Draft email with authentic tone — internal jargon, prior-thread reply chain if possible.
4. Target appropriate role; specify amount/account/urgency consistent with normal operations.
5. Track engagement (reply, callback, transfer initiation).
6. Halt before any real transaction; debrief and document gaps.

### Example email

```
From: ceo@comp4ny.com         (note: similar but lookalike domain)
To:   finance@company.com
Subject: Urgent: Confidential Acquisition

Hi Sarah,

I'm in meetings all day but need you to process an urgent wire transfer for
a confidential acquisition we're closing. Our attorney will send the details
shortly. This is time-sensitive and confidential — please don't discuss with
anyone.

Transfer Details:
  Amount:  $487,500
  To:      Escrow Services LLC
  Account: [details]
  Routing: [details]

Please confirm once completed.
Thanks, John Smith, CEO
```

### Domain spoofing options

- Lookalike domain: `company.com` → `comp4ny.com`, `cornpany.com`
- Subdomain confusion: `company.com.attacker.com`
- IDN homoglyph: `company.com` → `comрany.com` (Cyrillic `р`)
- Display-name spoof: From shows "CEO Name" but address differs
- Compromised mailbox: legitimate sender path (highest success rate)

## Verifying success

- Reply / forwarding to attacker mailbox indicates trust.
- Recipient drafts the wire (capture before transmission) — engagement halts here.
- Callback to "executive" via untrusted channel reveals lack of out-of-band verification.

## Common pitfalls

- Engaging real banking systems or live payment rails — never. Use test endpoints / dummy accounts.
- Targeting individuals not in scope — confirm in writing.
- Skipping debrief — BEC results need careful framing to avoid blaming the recipient.

## Tools

- Lookalike-domain registrars and dnstwist for variant discovery
- Gophish or similar for sending and tracking
- Imitation analysis: SPF/DKIM/DMARC check against the lookalike to demonstrate gap
