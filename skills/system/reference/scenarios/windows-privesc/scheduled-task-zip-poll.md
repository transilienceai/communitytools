# Scheduled Task ZIP Polling → DLL Sideload

## When this applies

- A scheduled task monitors a directory for ZIP files, extracts them, and loads a DLL.
- The extraction directory or ZIP drop path may be writable by lower-privileged users.
- Goal: drop a malicious ZIP containing a DLL that loads in the task's security context (typically SYSTEM).

## Steps

```bash
# Pattern: A scheduled task monitors a directory for ZIP files, extracts them, and loads a DLL
# The extraction directory or ZIP drop path may be writable by lower-privileged users
# 1. Identify: schtasks /query /fo csv /v — look for tasks running as SYSTEM/admin that reference ZIP/extract
# 2. Check ACLs: icacls "C:\path\to\polling\dir" — look for (W) or (F) for your user/group
# 3. Craft malicious DLL: must export the expected function (e.g. PreUpdateCheck, DllMain)
#    Cross-compile: x86_64-w64-mingw32-gcc -shared -o payload.dll payload.c (match 32/64-bit)
# 4. Package in ZIP with expected filename, drop in monitored directory
# 5. Wait for task cycle — DLL loads in task's security context
# Key: enumerate the expected DLL name and exported functions from the legitimate binary or logs
```

## Verifying success

- After the next task cycle, the DLL's payload executes (file write, reverse shell, etc.).

## Common pitfalls

- 32/64-bit DLL mismatch — the loader process's bitness determines what to compile.
- The DLL must export the function name the loader expects — read the legitimate binary or task logs to find the name.

## Tools

- x86_64-w64-mingw32-gcc (cross-compile)
- schtasks
- icacls
