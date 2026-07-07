# Management Plane Exposure

## When this applies

- A firewall, VPN gateway, or network appliance is in scope.
- You need to determine whether admin interfaces or vendor control services are reachable from the current vantage point.

## What to check

| Surface | Examples |
|---|---|
| Shell/admin | SSH `22`, Telnet `23`, serial-over-IP, vendor CLIs |
| Web admin | HTTP/HTTPS on `80`, `443`, `4443`, `8080`, `8443`, `9443`, `10443` |
| Remote desktop | RDP `3389`, VNC `5900` |
| SNMP | UDP `161/162`, especially v1/v2c |
| APIs | REST/XML-RPC/JSON-RPC management APIs |
| Vendor services | Check Point, Fortinet, Palo Alto, Cisco, Juniper, SonicWall-specific ports |

## Safe TCP checks

```bash
PORTS="22,23,80,81,443,4443,5000,5001,8000,8008,8080,8081,8443,8834,9000,9443,10000,10443,18190,19009"
nmap -Pn -sV --version-light -p "$PORTS" --reason -oA raw/mgmt-tcp TARGET
```

For each discovered HTTP service:

```bash
curl --max-time 8 -skI http://TARGET:PORT/ | tee raw/http-TARGET-PORT-headers.txt
curl --max-time 8 -skI https://TARGET:PORT/ | tee raw/https-TARGET-PORT-headers.txt
nmap -Pn -p PORT --script http-headers,http-title,http-server-header,http-methods -oA raw/http-safe-TARGET-PORT TARGET
```

## Safe SNMP check

Only perform a single default-community check when allowed. Do not brute-force community strings unless explicitly authorized.

```bash
snmpget -v2c -c public -t 2 -r 0 TARGET 1.3.6.1.2.1.1.1.0 | tee raw/snmp-public-sysdescr.txt
```

If `public` responds, stop and report. Further enumeration may expose sensitive process args, interfaces, routes, and installed software; get explicit approval before expanding.

## HTTP behavior checks

For an exposed management-like HTTP service:

```bash
for method in OPTIONS TRACE HEAD GET; do
  curl --max-time 8 -skiv -X "$method" http://TARGET:PORT/ -o raw/body-$method.txt 2>&1 | tee raw/headers-$method.txt
done
```

Flag:

- TRACE echo behavior.
- Server/product headers.
- Login pages exposed to public sources.
- Plain HTTP management.
- Missing or weak security headers on management interfaces.

## Evidence required from administrators

Packet probes cannot prove account hygiene or authorization controls. Request:

- Admin account list, roles, MFA status, and last login.
- Allowed management source ranges.
- Jump-host/session-recording requirements.
- SNMP version and allowed managers.
- API keys/tokens inventory and rotation policy.
- Management-plane logs for the test window.

