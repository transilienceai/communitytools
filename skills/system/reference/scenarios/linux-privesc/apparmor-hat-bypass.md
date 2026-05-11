# AppArmor Hat Constraints (post-RCE lateral movement)

## When this applies

- RCE inside a web/app context (`www-data`, etc.) succeeds but specific writes/reads mysteriously fail even when the UNIX user has permission.
- Symptoms: `echo ... > /path` silently fails, `curl file://` returns empty, reads return `Permission denied` despite world-readable files.

## Enumerate

```bash
cat /proc/self/attr/current              # e.g. "apache2//HAT_NAME (enforce)"
grep -r "AAHatName" /etc/apache2/         # locate per-vhost hats
cat /etc/apparmor.d/usr.sbin.apache2     # full profile incl. ^hat sections
aa-status 2>/dev/null
```

## Key profile syntax

- `rk`/`r`/`w`/`wk` — read / write / write+lock (no read). **`wk` means you can CREATE a file but never read it back** — exit codes from `echo > file` misleading.
- `deny /path rwx,` — explicit deny overrides allow
- `^hatname { ... }` — sub-profile, switched per-request via `mod_apparmor` `AAHatName`
- Unlisted paths = denied (in enforce mode)

## Bypass patterns

1. **World-writable shared dirs** (`drwxr-xrwx` on web root, `/var/www/*/skins/`, upload dirs) bypass hat restrictions because they're explicitly permitted in the profile — useful as cross-service file staging when `/tmp` is unavailable.
2. **Find the permitted binary list** — `grep '^\s*/' /etc/apparmor.d/<profile>` — anything allowed `ix`/`Px` is callable. Often `mysqldump`, `curl`, `file_get_contents` (PHP internal) remain.
3. **Template engines run under parent profile**, not hat — SSTI payloads inherit the vhost hat; if the hat denies `/etc/shadow` but parent profile allows it, switching vhost (different host header) may get different permissions.
4. **File writes reported as success can silently vanish** — always verify reads after writes; `tee` returns 0 even when lock prevents read.

## systemd `PrivateTmp=yes` Implication

When a service uses `PrivateTmp=yes` (default for many daemons), its `/tmp` and `/var/tmp` are namespaced to `/tmp/systemd-private-<uuid>-<svc>-*`. Files written to `/tmp` by another service are INVISIBLE to it.

**Check:**

```bash
systemctl cat <service> | grep -E 'PrivateTmp|ReadWritePaths|ProtectSystem'
ls /tmp/systemd-private-*   # per-service tmp dirs (root only)
```

**Impact:** Cross-service file drop via `/tmp` will fail. Use world-writable paths NOT in `/tmp` (web root subdirs, `/var/tmp` is also private if `PrivateTmp=yes`, `/dev/shm` is shared by default).

## Verifying success

- A read after the write returns the expected content (don't trust write exit codes).
- The file appears in `ls` from a different service context.

## Common pitfalls

- `wk` (write+lock no-read) makes write-then-read invisibility silent; verify the file from a different process.
- `tee` returns 0 even when the AppArmor profile rejects the read-back.

## Tools

- aa-status
- /proc/self/attr/current (enumerate current hat)
- systemctl cat (PrivateTmp inspection)
