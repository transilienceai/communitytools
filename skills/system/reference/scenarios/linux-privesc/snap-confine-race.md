# Snap-Confine / systemd-tmpfiles Race Conditions

## When this applies

- Linux foothold; `snap-confine` (SUID root or with capabilities) is present.
- Goal: race the `systemd-tmpfiles` cleanup against snap-confine's mimic creation to swap libraries and gain root.

## Detection

```bash
# Check if snap-confine is SUID or has capabilities
ls -la /usr/lib/snapd/snap-confine
getcap /usr/lib/snapd/snap-confine

# Check snapd version (vuln < 2.74.2 for CVE-2026-3888, < 2.54.3 for CVE-2021-44731)
snap version

# Check tmpfiles cleanup timer (accelerated = lab/CTF hint)
cat /etc/systemd/system/systemd-tmpfiles-clean.timer.d/override.conf 2>/dev/null
cat /usr/lib/tmpfiles.d/tmp.conf | grep -v "^#"
cat /usr/lib/tmpfiles.d/snapd.conf

# Check snap-private-tmp
ls -la /tmp/snap-private-tmp/ 2>/dev/null
```

## Exploitation pattern (CVE-2026-3888)

1. Create snap sandbox (e.g., firefox/snap-store), `cd /tmp`, keep alive with touch loop
2. Wait for `systemd-tmpfiles` to delete `/tmp/.snap` (10-30 days default, 4min in labs)
3. Recreate `.snap` with exchange directory containing modified libraries
4. Destroy saved namespace, then race snap-confine's mimic creation via `SNAPD_DEBUG=1` + AF_UNIX socket backpressure
5. Use `renameat2(RENAME_EXCHANGE)` for atomic directory swap during bind-mount sequence
6. Replaced `ld-linux-x86-64.so.2` gets loaded by SUID snap-confine → root shell
7. Copy SUID bash to `/var/snap/<snap>/common/` → escape sandbox

## Key technical details

- `RENAME_EXCHANGE` (not regular `rename()`) is required — atomic swap visible across mount namespaces
- Socket backpressure via minimized `SO_RCVBUF`/`SO_SNDBUF` enables single-stepping snap-update-ns
- Access snap's `/tmp` from outside via `/proc/<PID>/cwd` of a process that `cd`'d to `/tmp` inside the sandbox
- The mimic binds from `/tmp/.snap/usr/lib/x86_64-linux-gnu/` — swapping this dir changes what gets bind-mounted
- Public exploit: `TheCyberGeek/CVE-2026-3888-snap-confine-systemd-tmpfiles-LPE` on GitHub

## Verifying success

- The replaced `ld-linux-x86-64.so.2` loads when `snap-confine` is invoked → root shell.
- SUID bash dropped at `/var/snap/<snap>/common/bash` returns root with `-p`.

## Common pitfalls

- Lab/CTF environments often accelerate the tmpfiles cleanup timer to ~4 minutes — production may take 10-30 days.
- The race window is narrow; multiple sandbox-keepers + socket backpressure are required for a reliable hit.
- Patched in snapd 2.74.2+ (CVE-2026-3888) and 2.54.3+ (CVE-2021-44731).

## Tools

- snap-confine
- public exploit repos (`TheCyberGeek/CVE-2026-3888-snap-confine-systemd-tmpfiles-LPE`)
