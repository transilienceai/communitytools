# Service `RequiredPrivileges` Strips SeImpersonate (Pre-Potato Sanity Check)

## When this applies

- Windows foothold, you've found a writable service binary or `Everyone:F` ACL on a service path.
- Goal: BEFORE committing to PrintSpoofer / GodPotato / RoguePotato / JuicyPotatoNG, verify the running worker actually has `SeImpersonatePrivilege`.

## Technique

A service binary or config that is `Everyone:F` is a famous tell — but hardened deployments (XAMPP-on-Windows, custom NSSM wrappers, kiosk apps) routinely set `RequiredPrivileges` on the service so SCM strips SeImpersonate from the spawned process token, defeating every Potato variant regardless of how writable the on-disk binary is.

## Steps

```powershell
# 1. Inspect the registered required privileges (whitelist — anything not listed is removed)
sc qprivs <ServiceName>
reg query "HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>" /v RequiredPrivileges

# 2. Confirm from INSIDE the worker (CGI/RCE context — separate from your interactive shell)
#    If web RCE: drop a tiny CGI/handler that runs `whoami /priv` and read the response.
#    Apache CGI Perl probe (one-liner pwn.cgi):
#      print "Content-Type: text/plain\n\n"; print `whoami /all`;
# 3. If SeImpersonatePrivilege is absent, do NOT burn time on Potato — pivot to:
#    - Stored creds (cmdkey /list, Windows Vault, DPAPI, *.config / web.config)
#    - Service control: can you `sc stop` + replace binary? Often denied even with Everyone:F.
#    - Scheduled tasks running as a higher principal that load from a writable path.
#    - Token theft from a more privileged process (printers, agents, AV daemons).
```

Corollary — **XAMPP / Bitrock-installed stacks on Windows**: `icacls C:\xampp\*` is almost always `Everyone:(F)` by default (Bitrock sets world-writable perms on its install tree). This LOOKS like a slam-dunk privesc, but the Apache and MySQL services are typically wrapped to deny `sc stop` for non-admin users AND have RequiredPrivileges stripping SeImpersonate. Writable-but-unrestartable + de-privileged-worker = no path forward via that service. Always validate stop+start permissions before chasing the binary swap.

## Verifying success

- `whoami /priv` from INSIDE the worker (not your interactive shell) shows `SeImpersonatePrivilege` enabled.
- If absent, you've saved hours of wasted Potato attempts.

## Common pitfalls

- `whoami /priv` lies on filtered tokens — always check from INSIDE the worker via CGI/RCE context.
- XAMPP / Bitrock writable trees look exploitable but aren't due to RequiredPrivileges + sc-stop blocks.

## Tools

- sc qprivs
- reg query
- CGI probe / web RCE drop
