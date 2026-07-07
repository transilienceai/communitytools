# Check Point Security Gateway

## When this applies

- Target fingerprints as Check Point Security Gateway, Quantum, Gaia, Mobile Access, Remote Access VPN, SVN foundation, or Check Point VPN.
- Common signals include IKE responses, Check Point HTTP headers, or ports such as `264`, `18231-18234`, `18264`, `18190`, `19009`, `500/udp`, and `4500/udp`.

## Common ports

| Port | Purpose / Signal |
|---|---|
| `264/tcp` | Check Point topology / client services on some deployments |
| `500/udp` | IKE/IPsec |
| `4500/udp` | NAT-T IKE/IPsec |
| `18231-18234/tcp/udp` | Check Point VPN / policy / tunnel-related services depending on version/config |
| `18264/tcp` | Check Point SVN foundation HTTP service |
| `18190/tcp` | SmartConsole / management-related service on some deployments |
| `19009/tcp` | Check Point management-related service on some deployments |

Use focused scanning:

```bash
PORTS="264,500,4500,18190,18210,18231,18232,18233,18234,18264,19009"
nmap -Pn -sV --version-light -p "$PORTS" --reason -oA raw/check-point-focused TARGET
```

## SVN foundation (`18264/tcp`)

Fingerprint:

```bash
nmap -Pn -sV --version-all -p 18264 --reason -oA raw/check-point-18264 TARGET
curl --max-time 8 -skiv http://TARGET:18264/ -o raw/cp-18264-body.txt 2>&1 | tee raw/cp-18264-headers.txt
```

Signals:

- `Server: Check Point SVN foundation`
- `Check Point SVN foundation httpd`
- Uniform `404 Not Found` on benign paths

This confirms product surface, not vulnerability.

## CVE-2024-24919 safe handling

CVE-2024-24919 is an information disclosure issue affecting Internet-connected Check Point gateways when Remote Access VPN or Mobile Access is enabled on affected versions.

Safe remote checks:

```bash
curl --max-time 8 -skI http://TARGET:18264/clients/MyCRL
curl --max-time 8 -skiv http://TARGET:18264/clients/MyCRL -o raw/cp-mycrl-body.txt
curl --max-time 8 -skiv -X POST http://TARGET:18264/clients/MyCRL -H 'Content-Type: application/octet-stream' --data-binary '' -o raw/cp-mycrl-empty-post.txt
```

Do not send traversal or file-read payloads unless exploit validation is explicitly authorized. A `404` response to benign probes does not prove patched status; it only means benign probing did not demonstrate exploitability.

Required admin evidence:

- Exact gateway version and build.
- Jumbo Hotfix Take / installed hotfixes.
- Remote Access VPN and Mobile Access blade state.
- Logs for suspicious `/clients/MyCRL` requests.
- Vendor advisory applicability confirmation.

## CVE-2026-50751 safe handling

This class of Check Point VPN advisory concerns deprecated IKEv1 Remote Access behavior on affected deployments.

Safe remote checks:

```bash
ike-scan -M --retry=1 --timeout=5000 TARGET | tee raw/cp-ikev1.txt
ike-scan -M --nat-t --retry=1 --timeout=5000 TARGET | tee raw/cp-natt.txt
ike-scan --ikev2 -M --retry=1 --timeout=5000 TARGET | tee raw/cp-ikev2.txt
ike-scan -M --aggressive --id=test --retry=1 --timeout=5000 TARGET | tee raw/cp-aggressive.txt
```

Interpretation:

- IKEv1 or NAT-T notify responses prove exposed VPN/IKE surface.
- IKEv2 `INVALID_MAJOR_VERSION` can suggest the tested IKEv2 proposal was not accepted, but does not alone prove vulnerable IKEv1 Remote Access.
- No Aggressive Mode handshake means no PSK material was observed.

Required admin evidence:

- Whether IKEv1 Remote Access is enabled.
- VPN communities and encryption domain.
- IKE proposal list.
- Authentication method and MFA.
- Gateway hotfix status.

## Weak transform checks

Bounded weak transform probes are acceptable when allowed and non-DoS:

```bash
ike-scan -M --trans=1,1,1,1 --retry=1 --timeout=5000 TARGET | tee raw/cp-des-md5-dh1.txt
ike-scan -M --trans=1,2,1,1 --retry=1 --timeout=5000 TARGET | tee raw/cp-des-sha1-dh1.txt
ike-scan -M --trans=5,1,1,2 --retry=1 --timeout=5000 TARGET | tee raw/cp-3des-md5-dh2.txt
```

Only report weak-suite acceptance if a handshake completes. Notify-only responses are exposure evidence, not acceptance.

## Admin evidence checklist

Ask for:

- `show version all` or equivalent Gaia/SmartConsole version evidence.
- Jumbo Hotfix Accumulator Take.
- Installed hotfix list.
- Enabled blades: IPsec VPN, Remote Access VPN, Mobile Access, Threat Prevention.
- VPN community settings and IKE proposal list.
- Remote Access authentication method, MFA, user/group access.
- Management access source restrictions.
- Logs for `/clients/MyCRL`, IKE, VPN auth failures, and the testing source IP.

