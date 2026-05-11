# Vishing — Voice Phishing

## When this applies

Authorized assessment using voice calls (often with caller-ID spoofing) to manipulate employees into disclosing credentials, transferring money, or performing privileged actions. Tests verbal verification controls, callback procedures, and security awareness.

**MITRE ATT&CK**: T1598.003 (Spearphishing via Service).

## Technique

Use VoIP / spoofed caller ID to impersonate an authority (IT, HR, executive, vendor) and combine urgency with technical jargon to extract information or trigger an action.

## Steps

1. Research the org: structure, internal terminology, IT helpdesk hours, vendor list, executive-assistant names.
2. Build per-pretext script with talking points, follow-ups, and disengage triggers.
3. Stand up call infra: VoIP service (Twilio, etc.), allowed caller-ID spoofing per local law, recording.
4. Call during business hours; engage with one clear ask per call.
5. Document responses and capture artifacts (recordings, captured info).
6. Debrief; reinforce verification procedures.

### Example scripts

**Tech-support pretext**:
```
"Hello, this is the IT Security Team. We've detected unusual activity on your
account and need to verify your identity. Can you confirm your employee ID
and current password?"

Follow-ups:
- "This is urgent for security purposes."
- "We're seeing attempted unauthorized access."
- "Your account will be locked in 5 minutes if we don't verify."
```

**HR / payroll pretext**:
```
"Hi, this is Jennifer from Payroll. We're updating our direct-deposit system
and need to verify your banking information. Can you confirm your account
and routing numbers?"
```

**Executive impersonation**:
```
"This is [CEO Name]'s office. We need you to process an urgent wire transfer
immediately. I'll send the details via email, but I need you to start the
authorization process now."
```

### Caller-ID spoofing

Use a VoIP provider that permits caller-ID customization for authorized testing. **Caller-ID spoofing is regulated** (e.g. US Truth in Caller ID Act). Confirm legality and authorization before use.

## Verifying success

- Recipient discloses credentials, banking info, or initiates the requested action (capture before any real-world impact).
- Recordings demonstrate verbal control failures (no callback, no challenge question).

## Common pitfalls

- Targeting an out-of-scope individual — verify the call list with the client.
- Bypassing local laws around recording / caller-ID spoofing.
- Pushing too hard and producing a "trauma" interaction; use disengage triggers and provide debrief.

## Tools

- VoIP services (Twilio, etc.) with caller-ID customization
- Recording (with notice / per legal jurisdiction)
- Per-pretext scripts and rebuttal lists
- Post-call debrief template
