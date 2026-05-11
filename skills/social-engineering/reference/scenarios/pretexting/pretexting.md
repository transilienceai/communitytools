# Pretexting

## When this applies

Authorized assessment that uses a fabricated scenario / false identity to elicit information or trigger an action. Pretexting is the supporting layer for many social-engineering scenarios (vishing, phishing, in-person, BEC) but is often run as its own engagement focused on a specific information goal.

**MITRE ATT&CK**: T1598 (Phishing for Information).

## Technique

Build a scenario that gives a believable reason to ask for the target information. Common identities: IT support, HR, vendor / contractor, executive assistant, auditor, law enforcement, facility management.

## Steps

1. **OSINT**: org structure, vocabulary, processes, vendor list, recent events to anchor the scenario.
2. **Develop pretext**: identity, story, supporting facts, expected questions and answers.
3. **Prepare props**: caller ID, email signature, business card, badge, company-branded letterhead, ticket numbers.
4. **Practice delivery** until tone and language feel internal.
5. **Execute** with a single clear ask per interaction.
6. **Document and debrief**: what worked, what triggered suspicion, where verification controls succeeded.

## Sample scenarios

**IT support — credential elicitation**
```
"Hello, this is Michael from IT Support. We're experiencing a critical
security issue affecting all employee accounts. I need to verify your account
details to ensure your data is protected. Can you confirm your username and
temporarily reset your password to 'TempSecure123' so I can run the security
update?"
```

**Executive assistant — document elicitation**
```
"Hi, this is Sarah, Mr. Johnson's assistant. He's in an important meeting
and urgently needs access to the quarterly financial reports. Can you send
them to his personal email? He can't access his work email right now."
```

**Vendor — config elicitation**
```
"This is David from SecureNet Solutions. We're doing maintenance on your
company's VPN and need to verify the current configuration. Can you provide
me with the VPN server address and authentication details?"
```

## Quid pro quo (variant)

Offer a service / benefit in exchange for information or access. Effective when the org doesn't pre-validate vendor relationships.

```
"Hi, this is the IT department. We're calling employees to offer free
software upgrades. We can also help with any computer issues you're having.
To get started, I'll need your login credentials to push the updates to your
account."
```

```
"We're conducting a research study on workplace productivity and offering
$50 gift cards to participants. We'll need to verify your employment and
ask some questions about your work systems and access levels."
```

## Verifying success

- Target provides the targeted information / artifact without out-of-band verification.
- Recordings or transcripts show the absence of a callback / challenge step.
- Captured info is corroborated with what was learned in OSINT (so we know it's real, not invented during the call).

## Common pitfalls

- Asking for too much in one interaction — splits across multiple calls/emails work better.
- Pretext details inconsistent with reality (wrong CEO name, wrong vendor) — kills trust instantly.
- Skipping debrief — pretexting can feel adversarial; restore trust and frame the result as a control finding, not a personal failure.
- Caller-ID spoofing or impersonation across local-law boundaries — confirm legal scope.

## Red flags reviewers should catch

- Request for credentials over phone / email
- Unusual urgency without out-of-band proof
- Request to bypass standard procedure
- Unverified caller identity
- Suspicious timing (after-hours, weekend, just-before-deadline)
- Information inconsistencies across the conversation

## Tools

- VoIP / spoofed caller ID (per local law)
- Email lookalike domain
- Custom letterhead / signature templates
- OSINT outputs (org chart, vendor list, recent press releases)
- Per-pretext script and rebuttal list
