# Phishing — SMS (Smishing)

## When this applies

Authorized assessment delivering phishing payloads via SMS. Common when targets use BYOD, the mail gateway is hardened, or the test scenario calls for delivery via mobile channel.

## Technique

SMS message containing a tracked link to a credential-capture page or malicious payload. Common pretexts: parcel delivery, bank fraud alert, account verification, prize win, COVID-style alerts.

**MITRE ATT&CK**: T1566.002 (Spearphishing Link).

## Steps

1. Source target phone numbers (in-scope, written consent / authorization on file).
2. Compose pretext-aligned message with shortened tracking URL.
3. Stand up SMS gateway (Twilio, AWS SNS, or test-account VoIP).
4. Land page captures clicks and forwards to legitimate site to lower suspicion.
5. Send campaign in waves; measure click-through and submit rate.
6. Document, debrief, and run awareness training.

### Sample messages

```
[Company] Security Alert: Unusual activity detected. Verify identity: bit.ly/secure123
USPS: Package held - update shipping info: usps-track.info/pkg/12345
Your bank account is temporarily locked. Click to unlock: secure-bank-login.com
You won a $500 gift card. Claim now: reward-center.net/claim?id=xyz
```

### Twilio sender

```bash
curl -X POST https://api.twilio.com/2010-04-01/Accounts/ACCT_ID/Messages.json \
  --data-urlencode "Body=Your message here" \
  --data-urlencode "From=+15551234567" \
  --data-urlencode "To=+15557654321" \
  -u ACCT_ID:AUTH_TOKEN
```

### Tracking page (skeleton)

```html
<html><head><script>
  fetch('/log', {method:'POST', body: JSON.stringify({
    time: new Date(), userAgent: navigator.userAgent, referrer: document.referrer
  })});
  window.location = 'https://legitimate-site.com';
</script></head></html>
```

## Verifying success

- Tracker logs show click events with timestamps and user-agents.
- If credentials captured, validate with passive auth probe; never use them to alter state.

## Common pitfalls

- Carrier short-code filtering — premium SMS is usually blocked; rotate sender numbers.
- URL shortener bans — pre-warm domains and use direct lookalike domains.
- Test outside business hours when the SOC is thin — coordinate with stakeholders.
- Document carrier delivery receipts to back up reporting numbers.

## Tools

- Twilio, AWS SNS (SMS API)
- bit.ly / TinyURL (or self-hosted shortener with analytics)
- Custom landing page on cloud / VPS
