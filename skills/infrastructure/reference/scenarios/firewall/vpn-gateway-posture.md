# VPN Gateway Posture

## When this applies

- The appliance exposes VPN/IPsec/remote-access services.
- You need safe, non-bruteforce evidence for IKE/IPsec posture and CVE preconditions.

## Safety boundaries

- Do not crack PSKs.
- Do not brute-force group names, usernames, passwords, MFA, or certificates.
- Do not run malformed-packet, fragmentation, or DoS checks unless explicitly authorized.
- Treat notify-only responses as exposure evidence, not proof of weak-suite acceptance.

## IKE/IPsec probes

Install `ike-scan` if unavailable and approved by local environment.

### IKEv1 main mode

```bash
ike-scan -M --retry=1 --timeout=5000 TARGET | tee raw/ikev1-main.txt
```

### NAT-T

```bash
ike-scan -M --nat-t --retry=1 --timeout=5000 TARGET | tee raw/ikev1-natt.txt
```

### IKEv2

```bash
ike-scan --ikev2 -M --retry=1 --timeout=5000 TARGET | tee raw/ikev2.txt
```

### Aggressive Mode

Use a generic ID only. Do not enable PSK cracking output.

```bash
ike-scan -M --aggressive --id=test --retry=1 --timeout=5000 TARGET | tee raw/ike-aggressive.txt
```

If Aggressive Mode returns a handshake with hash material, stop and report. Do not run `--pskcrack` unless explicitly authorized.

### Weak transform probes

Use small, bounded probes and record whether the gateway completes a handshake or only returns notify messages.

```bash
ike-scan -M --trans=1,1,1,1 --retry=1 --timeout=5000 TARGET | tee raw/ike-des-md5-dh1.txt
ike-scan -M --trans=1,2,1,1 --retry=1 --timeout=5000 TARGET | tee raw/ike-des-sha1-dh1.txt
ike-scan -M --trans=5,1,1,2 --retry=1 --timeout=5000 TARGET | tee raw/ike-3des-md5-dh2.txt
ike-scan -M --trans=7/256,2,1,14 --retry=1 --timeout=5000 TARGET | tee raw/ike-aes256-sha1-dh14.txt
```

Interpretation:

| Result | Interpretation |
|---|---|
| Completed handshake | Proposal accepted; report weak crypto if transform is weak |
| Notify-only response | Gateway is reachable, but weak-suite acceptance is not proven |
| No response | Service not observed from this vantage point |

## TLS-based VPN portals

For SSL VPN or web portals:

```bash
nmap -Pn -sV -p PORT --script ssl-cert,ssl-enum-ciphers,http-headers,http-title -oA raw/vpn-portal TARGET
openssl s_client -connect TARGET:PORT -servername HOST </dev/null | tee raw/vpn-portal-tls.txt
```

## Admin evidence

Request:

- Enabled VPN blades/features.
- IKEv1 allow/deny setting.
- IKE/IPsec proposal list.
- Remote Access VPN and Mobile Access status.
- Authentication method: certificates, SAML, LDAP, local users, MFA.
- VPN user/group access rules.
- Gateway version and hotfix level.
- VPN auth logs for the test window.

