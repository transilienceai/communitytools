# Golden Ticket

## When this applies

- You possess the `krbtgt` account's NT/AES hash for a domain (typically obtained via DCSync after compromising any Domain Admin).
- Goal: forge arbitrary TGTs for any user in the domain, granting persistent domain-wide access.

## Technique

The `krbtgt` hash signs every TGT issued by the KDC. Possessing it lets you forge a TGT for any user (real or fake) with arbitrary group memberships (SID history). The forged TGT is indistinguishable from a legitimate one until the `krbtgt` password is rotated twice.

## Steps

```powershell
# Create golden ticket (requires krbtgt hash)
.\mimikatz.exe
kerberos::golden /domain:domain.com /sid:S-1-5-21... /krbtgt:hash /user:fakeadmin
```

From Linux:

```bash
ticketer.py -nthash <KRBTGT_NT> -domain-sid <DOMAIN_SID> -domain domain.local fakeadmin
export KRB5CCNAME=fakeadmin.ccache
secretsdump.py -k -no-pass dc.domain.local
```

## Verifying success

- `klist` shows the forged TGT for the fake user.
- `secretsdump.py -k -no-pass` against any DC returns DCSync output.

## Common pitfalls

- Golden ticket + SID history across **forest trusts** = BLOCKED unless BOTH forests are compromised. Forest trusts always filter well-known SIDs (EA-519, DA-512, SA-518) regardless of `SIDFilteringQuarantined` setting.
- Krbtgt rotation (twice) invalidates all forged TGTs. Re-extract `krbtgt` hash via DCSync after rotations.
- See `dcsync.md` for the krbtgt extraction method.
- See `unconstrained-delegation.md` for cross-forest TGT capture (the workaround when SID injection is blocked).

## Tools

- mimikatz
- impacket `ticketer.py`
