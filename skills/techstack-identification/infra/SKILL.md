---
name: techstack-infra
description: Infrastructure tech-stack identification — cloud providers, CDN/WAF, DNS services, TLS/CT, DevOps tooling, plus asset discovery (domains, subdomains, IPs).
---

# Infrastructure Tech-Stack Identification

## Scope

Identify the hosting and operational layer: cloud providers (AWS/GCP/Azure/DO/Linode/Vultr), PaaS (Heroku/Vercel/Netlify/Render/Railway/Fly), CDN (Cloudflare/Akamai/Fastly/CloudFront/Azure CDN), WAF (Imperva/Sucuri/F5/Fortinet), DNS provider, certificate authority, DevOps tooling (CI/CD, IaC, containers, orchestration), and the asset inventory (root domain, subdomains, IPs, certificates) that the rest of the engagement consumes.

## Signals (input)

- IP attribution (cloud IP ranges, ASN, WHOIS)
- DNS records: A, AAAA, MX, TXT, NS, CNAME, SRV
- TLS certificate metadata (issuer, SAN, validity, JARM)
- CT logs (crt.sh)
- HTTP headers tagging cloud/CDN/WAF
- Repository config files (`*.tf`, `Dockerfile`, `.github/workflows/*`, `Chart.yaml`, etc.)
- Asset inventory feeds — initial domain, subdomain enumeration, IP map

## Inferences (output)

- Primary cloud provider + region(s)
- PaaS / serverless / container orchestration
- CDN, WAF, DDoS / bot-management products
- DNS service, email provider, SaaS verifications (TXT)
- Certificate issuer & posture (automation, wildcard, validity window)
- DevOps stack: CI/CD platform, containerization, IaC, monitoring, secret mgmt
- Asset list: validated primary domain, all subdomains, IPs with cloud attribution

## Techniques

See [reference/patterns.md](reference/patterns.md).

## When to use

- First step of every tech-stack engagement (asset inventory feeds all other domains)
- Identifying CDN/WAF before choosing exploitation paths
- CVE matching by server stack version
- Supply-chain / SaaS exposure mapping (DNS verifications)
