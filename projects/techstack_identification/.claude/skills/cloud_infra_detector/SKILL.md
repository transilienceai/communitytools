---
name: cloud-infra-detector
description: Detects cloud providers (AWS, Azure, GCP) and PaaS platforms
tools: Read, Grep
model: inherit
hooks:
  PostToolUse:
    - matcher: "Read"
      hooks:
        - type: command
          command: "../../../hooks/skills/post_output_validation_hook.sh"
---

# Cloud Infrastructure Detector Skill

## Purpose

Detect cloud providers, PaaS platforms, and serverless services from IP attribution, DNS records, HTTP headers, and other signals.

## Input

Raw signals from Phase 2:
- `ip_signals` - Cloud provider IP range matches, ASN data
- `dns_signals` - CNAME delegations, TXT verification records
- `http_signals` - Cloud-specific headers
- `tls_signals` - Certificate issuers (ACM, GCP, etc.)
- `repository_signals` - IaC files, CI/CD configs

## Technology Categories

### Major Cloud Providers

| Provider | Detection Signals | Weight |
|----------|-------------------|--------|
| AWS | IP ranges, X-Amz-*, CloudFront headers, ACM certs | 40-45 |
| Google Cloud | IP ranges, X-Goog-*, GTS certs, cloud.google.com | 40-45 |
| Microsoft Azure | IP ranges, Azure headers, Azure certs | 40-45 |
| DigitalOcean | IP ranges (AS14061), do.co CNAME | 35-40 |
| Linode | IP ranges (AS63949) | 35-40 |
| Vultr | IP ranges (AS20473) | 35-40 |
| Oracle Cloud | IP ranges, Oracle headers | 35-40 |
| IBM Cloud | IP ranges, IBM headers | 35-40 |

### PaaS Platforms

| Platform | Detection Signals | Implies | Weight |
|----------|-------------------|---------|--------|
| Heroku | herokuapp.com CNAME, Heroku headers | AWS | 40 |
| Vercel | vercel.app CNAME, X-Vercel-Id header | AWS | 40 |
| Netlify | netlify.app CNAME, X-NF-* headers | AWS/GCP | 40 |
| Render | onrender.com CNAME | AWS/GCP | 35 |
| Railway | railway.app CNAME | GCP | 35 |
| Fly.io | fly.dev CNAME | - | 35 |
| Platform.sh | platform.sh CNAME | - | 35 |
| Google App Engine | appspot.com | GCP | 40 |
| AWS Elastic Beanstalk | elasticbeanstalk.com | AWS | 40 |
| Azure App Service | azurewebsites.net | Azure | 40 |

### Serverless Platforms

| Platform | Detection Signals | Implies | Weight |
|----------|-------------------|---------|--------|
| AWS Lambda | lambda-url headers, API Gateway | AWS | 35 |
| Cloudflare Workers | workers.dev, CF-Worker header | Cloudflare | 40 |
| Vercel Functions | Vercel + /api/ routes | Vercel | 35 |
| Netlify Functions | Netlify + /.netlify/functions/ | Netlify | 35 |
| Google Cloud Functions | cloudfunctions.net | GCP | 35 |
| Azure Functions | azurewebsites.net/api | Azure | 35 |

### Container Orchestration

| Platform | Detection Signals | Weight |
|----------|-------------------|--------|
| Kubernetes | k8s patterns, Helm charts in repo | 30 |
| Amazon EKS | eks.amazonaws.com | 35 |
| Google GKE | container.googleapis.com | 35 |
| Azure AKS | azmk8s.io | 35 |
| Docker Swarm | docker-compose patterns | 25 |

### Managed Services

| Service | Detection Signals | Provider | Weight |
|---------|-------------------|----------|--------|
| AWS S3 | s3.amazonaws.com, X-Amz-* | AWS | 35 |
| AWS CloudFront | cloudfront.net CNAME | AWS | 40 |
| AWS RDS | rds.amazonaws.com | AWS | 30 |
| Google Cloud Storage | storage.googleapis.com | GCP | 35 |
| Azure Blob | blob.core.windows.net | Azure | 35 |
| Firebase | firebaseapp.com, web.app | GCP | 40 |

## Detection Logic

```python
def detect_cloud_infrastructure(signals):
    results = []

    # IP-based Cloud Detection
    for ip_data in signals.ip_signals:
        if ip_data.cloud_provider:
            results.append({
                "name": ip_data.cloud_provider,
                "category": "Cloud Provider",
                "signals": [
                    {
                        "type": "ip_attribution",
                        "value": f"IP {ip_data.ip} in {ip_data.cloud_provider} range",
                        "region": ip_data.region
                    }
                ],
                "total_weight": 40
            })

    # CNAME-based PaaS Detection
    for cname in signals.dns_signals.cname_records:
        for paas in PAAS_PATTERNS:
            if paas.pattern in cname.target:
                results.append({
                    "name": paas.name,
                    "category": "PaaS",
                    "signals": [
                        {
                            "type": "dns_cname",
                            "value": f"CNAME → {cname.target}"
                        }
                    ],
                    "implies": paas.implies,
                    "total_weight": paas.weight
                })

    # Header-based Detection
    for header, value in signals.http_signals.headers.items():
        # AWS Headers
        if header.startswith('X-Amz-'):
            add_if_not_exists(results, "AWS", "Cloud Provider", {
                "type": "http_header",
                "value": f"{header}: {value}"
            }, 35)

        # Vercel Header
        if header == 'X-Vercel-Id':
            add_if_not_exists(results, "Vercel", "PaaS", {
                "type": "http_header",
                "value": f"X-Vercel-Id present"
            }, 40)

        # Netlify Headers
        if header.startswith('X-NF-'):
            add_if_not_exists(results, "Netlify", "PaaS", {
                "type": "http_header",
                "value": f"{header} present"
            }, 35)

    # Certificate Issuer Detection
    for cert in signals.tls_signals:
        if "Amazon" in cert.issuer:
            add_if_not_exists(results, "AWS Certificate Manager", "Managed Service", {
                "type": "certificate",
                "value": f"Issuer: {cert.issuer}"
            }, 35)
            add_if_not_exists(results, "AWS", "Cloud Provider", {
                "type": "certificate",
                "value": "ACM certificate implies AWS infrastructure"
            }, 30)

        if "Google Trust Services" in cert.issuer:
            add_if_not_exists(results, "Google Cloud", "Cloud Provider", {
                "type": "certificate",
                "value": "GTS certificate implies GCP infrastructure"
            }, 30)

    # Repository IaC Detection
    if signals.repository_signals:
        for file in signals.repository_signals.files:
            if "terraform" in file.lower():
                # Parse terraform for provider
                results.append({
                    "name": "Terraform",
                    "category": "IaC",
                    "signals": [{"type": "repository", "value": f"File: {file}"}],
                    "total_weight": 25
                })

            if "cloudformation" in file.lower() or file.endswith('.cfn.yml'):
                results.append({
                    "name": "AWS CloudFormation",
                    "category": "IaC",
                    "implies": ["AWS"],
                    "signals": [{"type": "repository", "value": f"File: {file}"}],
                    "total_weight": 30
                })

    return results
```

## Output

```json
{
  "skill": "cloud_infra_detector",
  "results": {
    "technologies": [
      {
        "name": "AWS",
        "category": "Cloud Provider",
        "signals": [
          {
            "type": "ip_attribution",
            "value": "IP 52.84.123.45 in AWS CloudFront range",
            "region": "us-east-1",
            "weight": 40
          },
          {
            "type": "certificate",
            "value": "ACM certificate detected",
            "weight": 30
          }
        ],
        "total_weight": 70,
        "services_detected": ["CloudFront", "ACM"]
      },
      {
        "name": "Vercel",
        "category": "PaaS",
        "signals": [
          {
            "type": "dns_cname",
            "value": "CNAME → cname.vercel-dns.com",
            "weight": 35
          },
          {
            "type": "http_header",
            "value": "X-Vercel-Id header present",
            "weight": 40
          }
        ],
        "total_weight": 75,
        "implies": ["AWS"]
      },
      {
        "name": "Terraform",
        "category": "IaC",
        "signals": [
          {
            "type": "repository",
            "value": "terraform/ directory found",
            "weight": 25
          }
        ],
        "total_weight": 25
      }
    ],
    "infrastructure_summary": {
      "primary_cloud": "AWS",
      "hosting_platform": "Vercel",
      "cdn": "Vercel Edge Network (AWS-backed)",
      "container_orchestration": null,
      "infrastructure_as_code": "Terraform"
    },
    "regions_detected": ["us-east-1", "us-west-2"]
  }
}
```

## Cloud-Specific Signals

### AWS
```
Headers: X-Amz-Cf-Id, X-Amz-Request-Id, X-Amz-Bucket-Region
CNAME: cloudfront.net, elasticbeanstalk.com, s3.amazonaws.com
ASN: AS16509, AS14618
Certificate: Amazon, AWS
```

### Google Cloud
```
Headers: X-Goog-*, X-GUploader-UploadID
CNAME: googleapis.com, appspot.com, run.app
ASN: AS15169, AS396982
Certificate: Google Trust Services
```

### Microsoft Azure
```
Headers: X-Azure-*, X-MS-*
CNAME: azurewebsites.net, azure-api.net, blob.core.windows.net
ASN: AS8075
Certificate: Microsoft
```

## Error Handling

- Multiple cloud providers: Report all with confidence
- PaaS on cloud: Report both PaaS and underlying cloud
- Uncertain attribution: Lower confidence, flag for correlation
