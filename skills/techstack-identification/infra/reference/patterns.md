# Infrastructure Detection Patterns

Consolidated from `cloud_infra_detector`, `cdn_waf_fingerprinter`, `dns_intelligence`, `tls_certificate_analysis`, `devops_detector`, `domain_discovery`, `subdomain_enumeration`, `certificate_transparency`, `ip_attribution`.

## Asset Discovery Pipeline

1. **Domain discovery**: web search (`"<company>" official website`), TLD probe in priority order `.com .io .co .org .net .ai .dev .app`, `whois <domain>` for registrant match. Validate via title/meta/social-link congruence.
2. **Subdomain enumeration** (passive only):
   - `crt.sh`: `GET https://crt.sh/?q=%25.<domain>&output=json` → parse `name_value` (newline-separated SANs)
   - Search dorks: `site:*.<domain> -www`
   - Wordlist probe (DNS-only, no brute SSL handshakes): `api app dev staging test beta www mail admin portal docs status blog cdn static assets auth sso git ci jenkins build deploy grafana prometheus shop store crm jira slack mobile v1 v2 v3 graphql`
   - Passive DNS: VirusTotal / SecurityTrails / DNSDumpster (if API keys available)
3. **IP attribution**: `dig +short A`/`AAAA`, follow CNAME chains, then `whois <ip>` (extract `OrgName/NetName/CIDR/Country`), then ASN via `dig <reversed>.origin.asn.cymru.com TXT`. Match IP to cloud-range JSONs.

## DNS Records — Tech Mapping

### MX (email)

| Pattern | Service |
|---------|---------|
| `aspmx.l.google.com`, `googlemail.com` | Google Workspace |
| `mail.protection.outlook.com` | Microsoft 365 |
| `pphosted.com` / `mimecast.com` | Proofpoint / Mimecast |
| `mailgun.org`, `sendgrid.net`, `amazonses.com` | Mailgun / SendGrid / AWS SES |
| `mx.zoho.com`, `secureserver.net`, `emailsrvr.com` | Zoho / GoDaddy / Rackspace |

### TXT (verifications & email auth)

`google-site-verification=`, `MS=ms*` (M365), `facebook-domain-verification=`, `atlassian-domain-verification=`, `stripe-verification=`, `docusign=`, `slack-domain-verification=`, `zendesk-domain-verification=`, `hubspot-developer-verification=`, `apple-domain-verification=`, `amazonses:`, `pardot`, `1password-site-verification=`, `have-i-been-pwned-verification=`, `status-page-domain-verification=`, plus `v=spf1`, `v=DMARC1`, `DKIM1`.

### NS (DNS provider)

`cloudflare.com`, `awsdns` (Route 53), `azure-dns.com`, `googledomains.com` / `dns.google` / `ns-cloud-*` (GCP), `digitalocean.com`, `domaincontrol.com` (GoDaddy), `dynect.net` (Oracle Dyn), `nsone.net` (NS1), `ultradns.com`, `constellix.com`.

### CNAME (CDN / hosting / SaaS)

`cloudfront.net` (CloudFront), `azureedge.net`, `akamaiedge.net` / `edgekey.net` / `edgesuite.net` / `akamaized.net`, `fastly.net` / `fastlylb.net`, `cdn.cloudflare.net`, `netlify.app`, `vercel.app` / `vercel-dns.com`, `herokuapp.com`, `pages.dev`, `firebaseapp.com` / `web.app`, `myshopify.com`, `squarespace.com`, `wixsite.com`, `ghost.io`, `webflow.io`, `zendesk.com`, `salesforce.com`.

### SRV (enterprise services)

`_sipfederationtls._tcp` → MS Teams/Skype, `_xmpp-server._tcp` → XMPP, `_caldav/_carddav._tcp` → CalDAV/CardDAV, `_ldap._tcp` → LDAP.

## Cloud Provider Attribution

| Provider | IP-range source | ASN | Headers | CNAME | Cert issuer |
|----------|-----------------|-----|---------|-------|-------------|
| AWS | `https://ip-ranges.amazonaws.com/ip-ranges.json` | AS16509, AS14618 | `X-Amz-*`, `Via: CloudFront` | `cloudfront.net`, `elasticbeanstalk.com`, `s3.amazonaws.com` | Amazon |
| GCP | `https://www.gstatic.com/ipranges/cloud.json` | AS15169, AS396982 | `X-Goog-*`, `X-GUploader-UploadID` | `googleapis.com`, `appspot.com`, `run.app` | Google Trust Services / GTS |
| Azure | MS ServiceTags (weekly JSON) | AS8075 | `X-Azure-*`, `X-MS-*` | `azurewebsites.net`, `azure-api.net`, `blob.core.windows.net` | Microsoft |
| Cloudflare | `https://www.cloudflare.com/ips-v4` (and `-v6`) | AS13335 | `CF-RAY`, `Server: cloudflare` | `*.cloudflare.com`, `pages.dev` | Cloudflare |
| Fastly | — | AS54113 | `X-Served-By: cache-*`, `Fastly-Debug-Digest`, `X-Timer` | `fastly.net` | — |
| Akamai | — | AS20940, AS16625 | `X-Akamai-*`, `Akamai-Origin-Hop` | `akamaiedge.net` | — |
| DO / Linode / Vultr / Heroku / Vercel / Netlify | — | AS14061 / AS63949 / AS20473 / via AWS / AS209242 / AS205948 | DO/Linode generic; `X-Vercel-Id`; `X-NF-*` | `do.co` / — / — / `herokuapp.com` / `vercel.app` / `netlify.app` | — |

PaaS implies underlying cloud (Heroku/Vercel → AWS, Railway → GCP, etc.).

## CDN / WAF / Bot Management

| Product | Headers / Cookies | CNAME / IP |
|---------|-------------------|-----------|
| Cloudflare (CDN+WAF+DDoS+Bot) | `CF-RAY`, `CF-Cache-Status`, `Server: cloudflare`, cookies `__cfduid`, `cf_clearance`, `__cf_bm` | `*.cloudflare.com` |
| Akamai | `X-Akamai-*` | `akamaiedge.net`, `edgekey.net` |
| Fastly | `X-Served-By: cache-*`, `X-Cache`, `X-Timer` | `fastly.net` |
| AWS CloudFront | `X-Amz-Cf-Id`, `X-Amz-Cf-Pop`, `Via: CloudFront` | `cloudfront.net` |
| Azure CDN / Front Door | `X-Azure-Ref` | `azureedge.net` |
| Imperva / Incapsula | `X-Iinfo`, cookies `incap_ses_*`, `visid_incap_*`, `nlbi_*` | — |
| Sucuri | `X-Sucuri-ID` | `sucuri.net` |
| F5 BIG-IP | cookie `BIGipServer*` | — |
| Barracuda / FortiWeb | cookies `barra_counter_session` / `FORTIWAFSID` | — |
| ModSecurity | Apache + WAF reaction patterns | — |
| PerimeterX / DataDome / Shape / Kasada / Arkose | cookies `_px*` / `datadome` / Shape JS / Kasada JS / Arkose challenges | — |

JARM fingerprints (TLS) cross-validate CDN/WAF — examples: Cloudflare `29d29d15d29d29d00042d42d000000cd19c7d2c21d91e77fcb9e7a8d6d1d8c`, CloudFront `29d29d00029d29d00042d43d00041d44609a5a9a88e797f466e878a82e8365`, Fastly `29d29d15d29d29d00029d29d29d29dcd19c7d2c21d91e77fcb9e7a8d6d1d8c`, Akamai `2ad2ad0002ad2ad0002ad2ad2ad2adce7a321c3e485c38c0e28d4e78968ed7`.

## TLS / Certificate Analysis

```bash
echo | openssl s_client -connect <host>:443 -servername <host> 2>/dev/null \
  | openssl x509 -noout -text
echo | openssl s_client -connect <host>:443 -servername <host> 2>/dev/null \
  | openssl x509 -noout -ext subjectAltName
nmap --script ssl-enum-ciphers -p 443 <host>
```

Issuer → tech: `Amazon` (AWS ACM), `Cloudflare`, `Google Trust Services` / `GTS` (GCP), `Let's Encrypt` (automated mgmt), `DigiCert` / `Sectigo` / `Comodo` (commercial), `ZeroSSL`.

Certificate Transparency: query `https://crt.sh/?q=%25.<domain>&output=json` (max 10 req/min). Extract `name_value` SANs → subdomain feed. Detect naming patterns: `^(prod|staging|dev|test|qa|uat)-`, `^(us|eu|apac|asia|emea|latam)-`, `^(api|app|web|cdn|static|assets)-`, `(\d+)$`. Wildcard certs (`CN: *.<domain>`) → flag scope.

Posture signals: TLS 1.3-only (modern), TLS 1.0/1.1 enabled (legacy/risk), short validity + Let's Encrypt (automation), wildcard SANs (dynamic subdomains), EV certificate (financial/enterprise).

## DevOps Stack from Repos / Subdomains / Job Posts

CI/CD config files: `.github/workflows/*.yml` (GitHub Actions), `.gitlab-ci.yml`, `Jenkinsfile`, `.circleci/config.yml`, `.travis.yml`, `azure-pipelines.yml`, `bitbucket-pipelines.yml`, `.drone.yml`, `cloudbuild.yaml`, `buildspec.yml` (CodeBuild).

Containers: `Dockerfile`, `docker-compose.yml`, `Containerfile` (Podman). Orchestration: `kubernetes/*`, `kustomization.yaml`, `Chart.yaml` (Helm), `docker-stack.yml` (Swarm), `*.nomad`, ECS task defs.

IaC: `*.tf` + `.terraform/` (Terraform), `Pulumi.yaml`, `*.cfn.yml` / `template.yaml` (CloudFormation), `cdk.json` (AWS CDK), `ansible.cfg`/`playbook.yml`, Chef cookbooks, Puppet manifests.

Build tools: `webpack.config.js`, `vite.config.js`, `rollup.config.js`, `turbo.json`, `nx.json`, `lerna.json`, `pnpm-workspace.yaml`.

Monitoring/observability subdomains: `grafana.*`, `prometheus.*`, `kibana.*`, `argocd.*`, `vault.*`, `jenkins.*`, `ci.*`. Tools: Prometheus, Grafana, Datadog, New Relic, Sentry (DSN in code), PagerDuty, OpsGenie. Secrets: HashiCorp Vault, AWS Secrets Manager, Doppler, 1Password (`op://`).

Maturity ladder: Basic (no CI/CD) → Intermediate (CI/CD + Docker) → Advanced (K8s + IaC + monitoring) → Cloud-native (GitOps + service mesh + multi-cloud).

## Rate / Error

- DNS: 30/min, no zone transfers, public resolvers only
- WHOIS: 5/min
- crt.sh: 10/min, exp-backoff on 429/503
- Cloud range JSON: cache 24h
- TLS connections: 10/min/domain
- Continue with partial results on any single failure
