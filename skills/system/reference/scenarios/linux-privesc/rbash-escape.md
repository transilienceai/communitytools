# rbash / Restricted Shell Escape via SSH Port Forwarding

## When this applies

- SSH-in-as-target-user lands in rbash with `cat`/`ls`/`ps` only.
- No interpreter (`python`, `perl`, `bash`, `/bin/sh`) reachable.
- Goal: escape the restricted shell or pivot around it.

## Technique

Don't try to escape in-shell — SSH itself is NOT inside rbash. Use SSH's native features pre-shell-spawn (port forward, SOCKS, ProxyCommand, `-t`-specified commands, SCP).

## Steps

1. **Don't try to escape in-shell** — SSH itself is NOT inside rbash. Use SSH's native features pre-shell-spawn.
2. **Local port forward** to pivot to a loopback-only service as the restricted user:
   ```bash
   ssh -fNT -L LOCAL_PORT:127.0.0.1:REMOTE_PORT user@host
   # then hit the service from attacker localhost
   curl http://127.0.0.1:LOCAL_PORT/
   ```
3. **`ProxyCommand` / `ssh -D`** — SOCKS proxy if multiple internal ports needed.
4. **`ssh user@host -t "cmd"`** — spawn a specific binary directly (bypasses rbash's PATH lockdown sometimes, if `ForceCommand` is not set).
5. **SCP to pull files** — `scp user@host:/path/file .` reads files rbash won't let you `cat`.

## Why it works

rbash only restricts the interactive shell in the child process. Port forwarding, SFTP, SCP, and `-t`-specified commands are handled by sshd before the login shell starts.

## Checklist when stuck in rbash

- [ ] `ss -tlnp` / `netstat` — discover localhost-only services
- [ ] Read systemd service files (`/etc/systemd/system/`, `/lib/systemd/system/`) for daemons running as root
- [ ] SSH `-L` forward to each internal port and attack from attacker box with full tools

## Verifying success

- `curl http://127.0.0.1:LOCAL_PORT/` returns content from the loopback-only service.
- `scp user@host:/etc/shadow .` retrieves the file (if your shell user is in a group that can read it).

## Common pitfalls

- `ForceCommand` in sshd_config can override `-t` cmd specification — verify with `ssh -t user@host -- cmd`.
- Port forwarding doesn't bypass MAC restrictions (SELinux, AppArmor) — those are enforced at the kernel level and apply to all SSH-spawned processes.

## Tools

- ssh (`-L`, `-D`, `-t`, `-fNT`)
- scp
- ProxyCommand
