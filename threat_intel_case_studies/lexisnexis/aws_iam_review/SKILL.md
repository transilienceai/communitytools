---
name: aws-iam-reviewer
description: Comprehensive AWS IAM security review skill that audits identities, policies, roles, credentials, cross-service resource policies, IAM Identity Center, and organizational controls against AWS best practices and compliance frameworks (CIS Benchmark, NIST 800-53, PCI DSS, SOC 2)
tools: Bash, Read
model: inherit
---

# AWS IAM Security Reviewer

## Operations
- review
- audit
- assess
- validate
- scan

## Supported Input Types
- live_aws_account (via AWS CLI / boto3)
- exported_iam_config (JSON/CSV files)
- policy_documents (JSON)
- credential_reports (CSV)
- CloudTrail event logs (JSON)

## Capabilities
- identity_audit
- credential_lifecycle_review
- policy_language_analysis
- role_trust_evaluation
- privilege_escalation_detection
- access_analyzer_review
- cross_service_resource_policy_analysis
- iam_identity_center_review
- compliance_framework_mapping
- organizational_controls_audit
- monitoring_coverage_assessment
- automated_data_collection

## Limitations
- cannot_perform_live_penetration_testing
- cannot_detect_realtime_credential_compromise (use GuardDuty)
- requires_read_only_iam_permissions_for_live_review
- cross_account_requires_access_to_all_accounts
- credential_report_has_4h_generation_cooldown
- service_specific_resource_policies_require_per_service_permissions

## Requirements
- AWS CLI v2 (for live review) or exported config files (for offline review)
- Python >= 3.10 (for scripted analysis)
- boto3 (for programmatic access)
- jq (for JSON processing in shell)

---

## Purpose

AWS IAM is the foundational security layer for all AWS environments. Misconfigurations in IAM can lead to privilege escalation, unauthorized access, data breaches, and compliance failures. This skill provides a structured, exhaustive review methodology covering every IAM surface area -- from root account protection to policy language evaluation to cross-service resource policies to organizational guardrails.

## Scope of Review

This skill covers **nine major audit domains**:

1. **Identity & Authentication Review** -- Users, groups, federation, MFA, IAM Identity Center
2. **Credential Lifecycle Review** -- Access keys, passwords, rotation, staleness
3. **Policy Analysis** -- Managed, inline, resource-based, session policies, policy language
4. **Role & Trust Review** -- Cross-account, service-linked, instance profiles, role chaining
5. **Cross-Service Resource Policy Analysis** -- S3, KMS, Lambda, SQS, SNS, Secrets Manager
6. **Advanced Access Controls** -- ABAC, permissions boundaries, session policies
7. **Access Analyzer & Findings** -- External, unused, and internal access analysis
8. **Organizational Controls** -- SCPs, RCPs, multi-account guardrails
9. **Monitoring & Logging** -- CloudTrail, alerting, credential reports

---

## 1. IAM Core Concepts Reference

### 1.1 Identity Types

| Identity | Description | Credential Type | Best Practice |
|----------|-------------|----------------|---------------|
| **Root User** | Initial account identity with unrestricted access | Email + password + MFA | Never use for daily tasks; enable MFA; delete access keys |
| **IAM Users** | Individual identities for people or services | Password and/or access keys | Prefer federation for humans; use roles for services |
| **IAM Groups** | Collections of IAM users | None (container only) | Attach policies to groups, not individual users |
| **IAM Roles** | Assumable identities with temporary credentials | Temporary via STS | Primary mechanism for granting access to services and cross-account |
| **Federated Identities** | External identities (SAML 2.0, OIDC) | Temporary via STS | Recommended for all human access via IAM Identity Center |
| **Identity Providers** | External IdP configurations (SAML, OIDC) | N/A | Required for federation; validate provider metadata |
| **IAM Identity Center Users** | Centrally managed users/groups for SSO | Temporary via SSO portal | AWS-recommended approach for all human access |

### 1.2 Policy Types

| Policy Type | Attached To | Managed/Inline | Use Case |
|-------------|-------------|----------------|----------|
| **AWS Managed Policy** | Users, Groups, Roles | Managed (by AWS) | Common permission sets; may be overly broad |
| **Customer Managed Policy** | Users, Groups, Roles | Managed (by customer) | Precise, reusable permission control |
| **Inline Policy** | Single User, Group, or Role | Inline | Strict 1:1 relationships; harder to audit at scale |
| **Resource-Based Policy** | Resources (S3, SQS, KMS, Lambda, SNS, etc.) | Always inline | Cross-account access; public access control |
| **Permissions Boundary** | Users, Roles | Managed | Caps maximum permissions for delegated administration |
| **Session Policy** | STS sessions | Inline or managed ARNs | Further limits permissions during role assumption |
| **SCP (Service Control Policy)** | AWS Organizations OUs/Accounts | Managed | Maximum permissions guardrail for entire accounts |
| **RCP (Resource Control Policy)** | AWS Organizations OUs/Accounts | Managed | Maximum permissions guardrail for resources |
| **Permission Set** | IAM Identity Center | Managed | Defines access for SSO users across accounts |

### 1.3 Authentication vs Authorization

```
Authentication: Matching credentials to a principal (IAM user, federated user, IAM role)
Authorization:  Evaluating policies to determine if authenticated principal can perform the action
```

**Policy Evaluation Logic:**

```
1. Explicit Deny in ANY policy  -->  DENY  (always wins, evaluation stops)
2. If SCP exists:        must have Allow in SCP         (otherwise implicit deny)
3. If RCP exists:        must have Allow in RCP         (otherwise implicit deny)
4. If Permissions Boundary exists: must have Allow in boundary (otherwise implicit deny)
5. If Session Policy exists:       must have Allow in session  (otherwise implicit deny)
6. Identity-Based Policy:  Allow here grants access
7. Resource-Based Policy:  Allow here grants access INDEPENDENTLY of identity-based policy
   (same-account: resource-based Allow is sufficient on its own)
   (cross-account: BOTH resource-based AND identity-based must Allow)
```

**Important nuance:** Resource-based policies that specify an IAM principal ARN (not `*`) in the same account grant access directly, even without a matching identity-based policy. This is different from all other policy types which only intersect.

### 1.4 Eventual Consistency

IAM replicates data globally. Changes (creating users, roles, policies) may take time to propagate across all regions. Critical security changes should be verified before assuming they are active.

---

## 2. IAM Policy Language Deep Dive

### 2.1 Policy Document Structure

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "OptionalStatementIdentifier",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
      "Action": ["s3:GetObject", "s3:PutObject"],
      "Resource": ["arn:aws:s3:::my-bucket/*"],
      "Condition": {
        "StringEquals": {
          "aws:PrincipalOrgID": "o-exampleorgid"
        }
      }
    }
  ]
}
```

### 2.2 Policy Elements Reference

| Element | Required | Description | Security Notes |
|---------|----------|-------------|----------------|
| `Version` | Recommended | Must be `"2012-10-17"` | Older version `"2008-10-17"` lacks policy variables and condition support |
| `Statement` | Yes | Array of permission rules | Review each statement independently |
| `Sid` | Optional | Statement ID for readability | Use descriptive IDs for audit trail |
| `Effect` | Yes | `"Allow"` or `"Deny"` | Explicit Deny always wins |
| `Principal` | Conditional | Who the policy applies to (resource-based only) | `"*"` = public access -- CRITICAL finding |
| `NotPrincipal` | Conditional | Everyone except listed (mutually exclusive with Principal) | Dangerous with Allow -- can grant unintended access |
| `Action` | Yes | API actions being allowed/denied | `"*"` = all actions -- CRITICAL finding |
| `NotAction` | Conditional | All actions except listed (mutually exclusive with Action) | Can accidentally allow sensitive actions |
| `Resource` | Conditional | ARNs the statement applies to | `"*"` = all resources -- CRITICAL finding |
| `NotResource` | Conditional | All resources except listed (mutually exclusive with Resource) | Can accidentally expose sensitive resources |
| `Condition` | Optional | Circumstances when statement applies | Missing conditions = unrestricted access context |

### 2.3 Condition Operators

```
String Operators:
  StringEquals, StringNotEquals, StringEqualsIgnoreCase
  StringLike, StringNotLike  (supports * and ? wildcards)

Numeric Operators:
  NumericEquals, NumericNotEquals
  NumericLessThan, NumericLessThanEquals
  NumericGreaterThan, NumericGreaterThanEquals

Date Operators:
  DateEquals, DateNotEquals
  DateLessThan, DateLessThanEquals
  DateGreaterThan, DateGreaterThanEquals

Boolean:
  Bool  (e.g., "aws:SecureTransport": "true")

IP Address:
  IpAddress, NotIpAddress  (CIDR notation)

ARN:
  ArnEquals, ArnNotEquals, ArnLike, ArnNotLike

Existence:
  Null  (check if condition key exists: "true" = key absent, "false" = key present)

Set Operators (prefix modifiers):
  ForAllValues:   ALL values in the request key must match a condition value
  ForAnyValue:    ANY value in the request key must match a condition value
  IfExists        Only evaluate if key exists in request context
```

### 2.4 Critical Global Condition Keys

| Condition Key | Description | Security Use |
|---------------|-------------|-------------|
| `aws:SourceIp` | Request source IP address | Restrict access to corporate IPs |
| `aws:VpcSourceIp` | Source IP within VPC | Restrict to VPC endpoints |
| `aws:SourceVpc` | VPC ID for VPC endpoint requests | Restrict to specific VPCs |
| `aws:SourceVpce` | VPC endpoint ID | Restrict to specific endpoints |
| `aws:MultiFactorAuthPresent` | Whether MFA was used | Require MFA for sensitive operations |
| `aws:MultiFactorAuthAge` | Seconds since MFA authentication | Enforce recent MFA (e.g., < 3600s) |
| `aws:CurrentTime` | Current UTC time | Time-based access restrictions |
| `aws:SecureTransport` | Whether request used TLS | Enforce HTTPS-only access |
| `aws:PrincipalTag/tag-key` | Tag on the requesting principal | ABAC authorization |
| `aws:RequestTag/tag-key` | Tag in the API request | Control tag-based resource creation |
| `aws:ResourceTag/tag-key` | Tag on the target resource | ABAC authorization |
| `aws:TagKeys` | All tag keys in the request | Enforce required/forbidden tags |
| `aws:PrincipalOrgID` | Organization ID of the principal | Restrict to organization members |
| `aws:PrincipalAccount` | Account ID of the principal | Cross-account restrictions |
| `aws:RequestedRegion` | AWS region of the API call | Restrict to approved regions |
| `aws:CalledVia` | Services that made the request on behalf | Control service chaining |
| `sts:ExternalId` | External ID passed during AssumeRole | Prevent confused deputy attacks |
| `aws:PrincipalIsAWSService` | Whether principal is an AWS service | Restrict to service or non-service principals |
| `aws:SourceOrgID` | Organization ID of the calling service | Restrict cross-service access to your org |

### 2.5 Policy Variables

Dynamic values resolved at evaluation time:

```
${aws:username}          -- IAM user name
${aws:userid}            -- Unique ID of the principal
${aws:PrincipalTag/team} -- Tag value from the principal
${aws:CurrentTime}       -- Current timestamp
${s3:prefix}             -- S3 key prefix from request
${ec2:ResourceTag/Name}  -- EC2 resource tag value
```

**Common pattern** -- user-specific S3 access:
```json
{
  "Effect": "Allow",
  "Action": ["s3:GetObject", "s3:PutObject"],
  "Resource": "arn:aws:s3:::company-bucket/home/${aws:username}/*"
}
```

---

## 3. IAM Best Practices Checklist

### 3.1 Identity Best Practices

```python
def review_identity_best_practices(aws_account):
    """
    Review identity configuration against AWS best practices.

    Steps:
    1. Check root user security:
       - MFA enabled on root account (CRITICAL if missing)
       - No active access keys for root user (CRITICAL if present)
       - Root not used for everyday tasks (check CloudTrail for root API calls)
       - Root email uses a distribution list, not a personal address
       - Hardware MFA device preferred over virtual MFA for root

    2. Check user authentication:
       - All IAM users have MFA enabled
       - Federation configured for human users (IAM Identity Center or external IdP)
       - Service accounts use IAM roles, not IAM users with long-term keys
       - Console-only users have no access keys
       - API-only users have no console password

    3. Check group organization:
       - Policies attached to groups, not individual users
       - Users organized into groups by function/team
       - No orphaned users (users not in any group)
       - Groups follow least-privilege principle

    4. Check password policy:
       - Minimum password length >= 14 characters
       - Require uppercase, lowercase, numbers, symbols
       - Do NOT enforce periodic password rotation (see note below)
       - Password reuse prevention (remember >= 24 passwords)
       - Allow users to change their own passwords

    NOTE on password rotation: NIST SP 800-63B (2017) and updated CIS
    Benchmarks recommend AGAINST mandatory periodic password rotation.
    Forced rotation leads to weaker passwords (predictable patterns).
    Instead, require rotation only when compromise is suspected, and
    enforce MFA as the primary second factor.

    Returns: list of findings with severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)
    """
```

### 3.2 Credential Best Practices

```python
def review_credential_hygiene(aws_account):
    """
    Review credential lifecycle and hygiene.

    Steps:
    1. Generate and analyze credential report:
       - Identify users with password_last_used > 90 days
       - Identify access keys with access_key_last_used_date > 90 days
       - Identify access keys never rotated (access_key_last_rotated > 90 days)
       - Identify users with 2 active access keys
       - Check X.509 certificates for activity and rotation

    2. Review access key usage:
       - Each access key should be used regularly or deactivated
       - Keys should be rotated at least every 90 days
       - No access keys should exist for root user
       - Keys should be region-appropriate (not used across all regions unexpectedly)

    3. Review MFA configuration:
       - All users with console access have MFA enabled
       - Prefer phishing-resistant MFA (FIDO2 security keys, passkeys)
       - Virtual MFA as minimum acceptable standard
       - MFA required for sensitive operations via policy conditions

    4. Identify stale identities:
       - Users not logged in for 90+ days
       - Roles not assumed for 90+ days
       - Access keys not used for 90+ days
       - Recommend removal or deactivation

    Returns: credential_report_analysis with per-user findings
    """
```

### 3.3 Least Privilege Best Practices

```python
def review_least_privilege(aws_account):
    """
    Review permissions for least-privilege adherence.

    Steps:
    1. Identify overly permissive policies:
       - Policies with "Action": "*" (admin access)
       - Policies with "Resource": "*" (unrestricted resource scope)
       - Policies with "Effect": "Allow" + "Action": "service:*" (full service access)
       - Policies granting iam:*, sts:*, organizations:* without conditions

    2. Review managed policy usage:
       - Identify usage of AdministratorAccess, PowerUserAccess, IAMFullAccess
       - Count users/roles attached to overly broad managed policies
       - Recommend customer-managed alternatives with tighter scope

    3. Use Access Analyzer findings:
       - Review unused access findings (actions, roles, access keys, passwords)
       - Generate least-privilege policies from CloudTrail access logs
       - Validate existing policies with Access Analyzer policy checks (100+ checks)

    4. Review service-specific permissions:
       - Check for broad s3:*, ec2:*, lambda:* grants
       - Verify read-only vs read-write separation
       - Check for data exfiltration paths (s3:GetObject on sensitive buckets)

    Returns: list of overprivileged identities with remediation recommendations
    """
```

---

## 4. IAM Identity Center (SSO) Review

```python
def review_iam_identity_center(aws_account):
    """
    Review IAM Identity Center (formerly AWS SSO) configuration.

    IAM Identity Center is AWS's recommended approach for managing human
    access to AWS accounts and applications. It provides centralized
    identity management, temporary credentials, and audit-friendly
    access patterns.

    Steps:
    1. Verify Identity Center is enabled:
       - Check if Identity Center instance exists
       - Verify the identity source (Identity Center directory, Active Directory, or external IdP)
       - Confirm the delegated administrator account (if using Organizations)

    2. Review identity source configuration:
       - If using external IdP: verify SAML/SCIM configuration
       - If using AD Connector: verify directory trust and connectivity
       - If using built-in directory: check if migration to external IdP is planned

    3. Review Permission Sets:
       - List all permission sets and their attached policies
       - Identify permission sets with AdministratorAccess or PowerUserAccess
       - Verify permission sets use least-privilege policies
       - Check session duration settings (default vs custom)
       - Review inline policies within permission sets
       - Check permissions boundaries on permission sets

    4. Review account assignments:
       - Map which users/groups have access to which accounts via which permission sets
       - Identify users with admin access across multiple accounts
       - Verify assignments follow principle of least privilege
       - Check for dormant assignments (granted but never used)

    5. Review MFA configuration:
       - MFA enforcement mode (required vs optional)
       - Allowed MFA types (FIDO2 preferred over TOTP)
       - Context-aware (adaptive) MFA settings
       - MFA device registration policy

    6. Review authentication settings:
       - Session duration configuration
       - Access portal URL and customization
       - Multi-account sign-in behavior

    Returns: identity_center_assessment with findings and recommendations
    """
```

---

## 5. IAM Roles Deep Dive

### 5.1 Role Trust Policy Review

```python
def review_role_trust_policies(aws_account):
    """
    Review all IAM role trust policies for security issues.

    Steps:
    1. Enumerate all roles and their trust policies

    2. Check for overly broad trust:
       - Principal: "*" (anyone can assume -- CRITICAL)
       - Principal: {"AWS": "*"} (any AWS account -- CRITICAL)
       - Principal: {"AWS": "arn:aws:iam::ACCOUNT:root"} with no conditions
       - Missing sts:ExternalId for cross-account roles

    3. Review cross-account trust:
       - Identify all roles trusting external accounts
       - Verify each trusted account is known and authorized
       - Check for sts:ExternalId condition on cross-org roles
       - Verify MFA conditions where appropriate

    4. Review service trust:
       - Verify service principals are appropriate for the role's purpose
       - Check for overly broad service trust (multiple unrelated services)
       - Review service-linked roles and their associated services
       - Verify aws:SourceArn / aws:SourceAccount conditions on service roles

    5. Review federation trust:
       - SAML provider trust configurations
       - OIDC provider trust configurations (GitHub Actions, GitLab CI, etc.)
       - Verify audience (aud) and subject (sub) conditions on OIDC
       - Check for overly broad OIDC subject claims (e.g., missing repo/branch filters)

    6. Check for confused deputy vulnerabilities:
       - Cross-account roles without sts:ExternalId
       - Service roles without aws:SourceArn or aws:SourceAccount conditions
       - Resource-based policies without aws:SourceOrgID or aws:PrincipalOrgID

    Returns: role_trust_analysis with per-role findings
    """
```

### 5.2 Instance Profile Review

```python
def review_instance_profiles(aws_account):
    """
    Review EC2 instance profiles and their attached roles.

    Steps:
    1. List all instance profiles
    2. Identify instance profiles not attached to running instances
    3. Review permissions of attached roles for least privilege
    4. Check for overly permissive instance roles (admin access)
    5. Verify no sensitive operations (iam:*, sts:AssumeRole to admin roles)
    6. Check for IMDS v2 enforcement (HttpTokens: required) on instances
       - IMDSv1 allows SSRF attacks to steal role credentials
       - Flag any instances still using IMDSv1

    Returns: instance_profile_findings
    """
```

### 5.3 Role Chaining Analysis

```python
def analyze_role_chaining(aws_account):
    """
    Map and analyze role chaining paths for privilege escalation.

    Steps:
    1. For each role, identify which other roles it can assume
       (via sts:AssumeRole permissions in its policies)
    2. Build a directed graph of role-to-role assumption paths
    3. Identify privilege escalation chains:
       - Low-privilege role -> ... -> Admin role
       - Cross-account chains that bypass boundaries
    4. Check session duration limits (chained sessions max 1 hour)
    5. Identify transitive session tag propagation risks
    6. Flag circular assumption paths

    Returns: role_chain_graph with escalation_paths highlighted
    """
```

---

## 6. Cross-Service Resource Policy Analysis

```python
def review_cross_service_resource_policies(aws_account):
    """
    Review resource-based policies across key AWS services.

    Resource-based policies are attached directly to resources and can
    grant access independently of identity-based policies (same-account).
    They are a critical and often-overlooked attack surface.

    IMPORTANT: Resource-based policies with "Principal": "*" make
    resources publicly accessible. This is the #1 cause of S3 data
    breaches.

    Steps:
    1. S3 Bucket Policies:
       - List all buckets with bucket policies
       - Flag policies with "Principal": "*" (public access -- CRITICAL)
       - Flag policies missing aws:SecureTransport condition (HTTP allowed)
       - Check S3 Block Public Access settings (account and bucket level)
       - Verify cross-account access is intentional and scoped
       - Check for s3:GetObject on sensitive data buckets

    2. KMS Key Policies:
       - List all KMS keys and their key policies
       - Flag keys with overly broad key administrators
       - Verify key policies restrict key usage to intended principals
       - Check for kms:* grants to broad principals
       - Verify key rotation is enabled for symmetric keys
       - Review grants (separate from key policies) for excessive access

    3. Lambda Function Policies:
       - List all Lambda resource-based policies
       - Flag policies allowing invocation from external accounts
       - Verify lambda:InvokeFunction is scoped to intended triggers
       - Check for overly broad event source mappings

    4. SQS Queue Policies:
       - List all SQS queues with access policies
       - Flag policies with "Principal": "*"
       - Verify cross-account send/receive is intentional
       - Check for sqs:* grants

    5. SNS Topic Policies:
       - List all SNS topics with access policies
       - Flag policies with "Principal": "*"
       - Verify subscription and publish permissions are scoped
       - Check for sns:* grants

    6. Secrets Manager Resource Policies:
       - List all secrets with resource policies
       - Flag policies granting cross-account access
       - Verify secretsmanager:GetSecretValue is tightly scoped
       - Check for broad access to production secrets

    7. ECR Repository Policies:
       - Flag repositories with cross-account pull/push
       - Verify ecr:GetDownloadUrlForLayer is scoped

    8. STS AssumeRole (via trust policies):
       - Already covered in Section 5.1 but cross-reference here

    Returns: per_service_resource_policy_findings
    """
```

---

## 7. Advanced Access Controls

### 7.1 ABAC (Attribute-Based Access Control) Review

```python
def review_abac_implementation(aws_account):
    """
    Review ABAC implementation and tagging discipline.

    Key concepts:
    - ABAC uses tags on principals (aws:PrincipalTag) and resources
      (aws:ResourceTag) for authorization decisions
    - Replaces many RBAC policies with fewer tag-based policies
    - Scales automatically: new resources get access via tags, not policy updates

    Steps:
    1. Identify ABAC policies (policies using PrincipalTag, ResourceTag conditions)
    2. Review tagging consistency:
       - Are all resources tagged with required attributes?
       - Are all principals (users/roles) tagged appropriately?
       - Is there a tag governance policy?
    3. Check ABAC policy coverage:
       - Are tag conditions applied to both allow and deny statements?
       - Are aws:TagKeys conditions used to prevent tag manipulation?
       - Are aws:RequestTag conditions used for resource creation?
    4. Verify tag immutability:
       - Who can modify tags on principals? (iam:TagUser, iam:TagRole)
       - Who can modify tags on resources?
       - Are there SCPs preventing unauthorized tag changes?

    Returns: abac_assessment with gaps and recommendations
    """
```

### 7.2 Permissions Boundary Review

```python
def review_permissions_boundaries(aws_account):
    """
    Review permissions boundary configurations.

    Key concepts:
    - Permissions boundaries cap the maximum permissions for users/roles
    - Effective permissions = identity-based policy INTERSECT permissions boundary
    - Critical for delegated administration (allowing users to create roles safely)
    - Resource-based policies that specify an IAM user ARN directly are NOT
      limited by the boundary (same-account only)

    Steps:
    1. Identify all users/roles with permissions boundaries attached
    2. Identify users/roles WITHOUT boundaries that should have them:
       - Users with iam:CreateUser or iam:CreateRole permissions
       - Users who can iam:AttachUserPolicy or iam:AttachRolePolicy
       - Any delegated admin scenarios
    3. Review boundary policies for appropriate scope:
       - Are boundaries too permissive (effectively no restriction)?
       - Are boundaries too restrictive (blocking legitimate work)?
    4. Check for boundary bypass:
       - Can any user modify their own boundary?
       - Can any user create roles without boundaries?
       - Are there iam:DeleteUserPermissionsBoundary permissions?
       - Can a user create a role with a different (weaker) boundary?
    5. Verify boundary enforcement in delegation workflows:
       - iam:CreateRole with condition: iam:PermissionsBoundary required
       - iam:AttachRolePolicy scoped to non-admin policies
       - iam:PutRolePermissionsBoundary restricted to prevent boundary swap

    Returns: permissions_boundary_findings
    """
```

### 7.3 Session Policy Review

```python
def review_session_policies(aws_account):
    """
    Review session policy usage and configuration.

    Key concepts:
    - Session policies are passed during AssumeRole, AssumeRoleWithSAML,
      AssumeRoleWithWebIdentity, or GetFederationToken
    - They further limit (never grant) permissions
    - Effective = session policy AND role's identity-based policy AND boundary
    - Up to 10 managed session policies can be passed via PolicyArns
    - One inline session policy can be passed via Policy parameter

    Steps:
    1. Check CloudTrail for AssumeRole calls with Policy or PolicyArns parameters
    2. Review session policy content for appropriate restrictions
    3. Verify session policies are used for:
       - Limiting federated user sessions
       - Restricting cross-account access scope
       - Providing least-privilege for specific tasks
    4. Check maximum session duration settings on roles
       - Default: 1 hour; max configurable: 12 hours
       - Role chaining always limits to 1 hour regardless of setting

    Returns: session_policy_assessment
    """
```

---

## 8. IAM Access Analyzer

### 8.1 Access Analyzer Setup Review

```python
def review_access_analyzer_setup(aws_account):
    """
    Verify IAM Access Analyzer is properly configured.

    Analyzer types:
    - ACCOUNT: Analyzes resources accessible outside your account
    - ORGANIZATION: Analyzes resources accessible outside your organization
    - ACCOUNT_UNUSED_ACCESS: Finds unused permissions and credentials (per account)
    - ORGANIZATION_UNUSED_ACCESS: Org-wide unused access analysis

    Steps:
    1. Verify analyzers exist and are ACTIVE (not Failed or Disabled):
       - External access analyzer in ALL active regions (regional resource)
       - Unused access analyzer (not region-specific but still regional resource)
    2. Check analyzer type:
       - Prefer ORGANIZATION type if AWS Organizations is used
       - Ensure ACCOUNT type exists at minimum in every active region
    3. Review service-linked role:
       - AWSServiceRoleForAccessAnalyzer must exist
       - Role must have appropriate permissions (auto-managed by AWS)
    4. Verify automated finding notifications:
       - EventBridge rules for new findings
       - SNS or Lambda integration for alerting

    Returns: analyzer_setup_status per region
    """
```

### 8.2 Access Analyzer Findings Review

```python
def review_access_analyzer_findings(aws_account):
    """
    Review and categorize Access Analyzer findings.

    Finding types:
    - External access: Resources accessible outside your account/organization
    - Unused access: Unused roles, access keys, passwords, permissions

    Steps:
    1. List all active findings (status: ACTIVE)
    2. Categorize by severity and resource type:
       - PUBLIC access findings (CRITICAL)
       - Cross-account access findings (HIGH)
       - Unused admin permissions (HIGH)
       - Unused access keys > 90 days (MEDIUM)
       - Unused passwords > 90 days (MEDIUM)
       - Unused standard permissions (LOW)
    3. For each finding, determine:
       - Is the access intentional? (archive if yes, with justification)
       - What is the blast radius of the exposure?
       - What is the remediation action?
    4. Check finding resolution workflow:
       - Are findings being regularly reviewed?
       - Is there an SLA for finding remediation?
       - Are resolved findings tracked?
       - Are archived findings periodically re-reviewed?

    Returns: categorized_findings with remediation_actions
    """
```

### 8.3 Policy Validation with Access Analyzer

```python
def validate_policies_with_analyzer(policies):
    """
    Use Access Analyzer's 100+ policy validation checks.

    Check categories:
    - SECURITY_WARNING: Policy grants overly broad access
    - ERROR: Policy syntax or logic errors
    - WARNING: Non-best-practice patterns
    - SUGGESTION: Improvements for clarity

    Key checks include:
    - Wildcards in actions or resources
    - Missing Version element
    - Empty conditions
    - Redundant or conflicting statements
    - NotPrincipal misuse (with Allow effect)
    - Missing constraints on sensitive actions (iam:*, sts:*)
    - Unsupported action/resource combinations
    - Deprecated or invalid condition keys
    - Pass role without resource constraint

    Steps:
    1. Submit each policy document for validation via
       aws accessanalyzer validate-policy
    2. Collect and categorize all findings
    3. Prioritize SECURITY_WARNING and ERROR findings
    4. Generate remediation guidance for each finding

    Returns: policy_validation_results per policy
    """
```

---

## 9. Organizational Controls (AWS Organizations)

### 9.1 SCP Review

```python
def review_service_control_policies(aws_org):
    """
    Review Service Control Policies for organizational guardrails.

    Key concepts:
    - SCPs set maximum permissions for principals in member accounts
    - SCPs do NOT grant permissions, only restrict them
    - SCPs do NOT affect the management account or service-linked roles
    - Effective permissions = SCP AND identity-based AND resource-based

    Steps:
    1. Verify SCPs are enabled in the organization
    2. Review SCP inheritance hierarchy (Root -> OUs -> Accounts)
    3. Check for essential deny SCPs:
       - Deny access to unused AWS regions
       - Deny disabling CloudTrail
       - Deny disabling GuardDuty / SecurityHub
       - Deny leaving the organization
       - Deny root user actions (except break-glass scenarios)
       - Deny creation of IAM users (if federation is the standard)
       - Deny public S3 bucket creation
       - Deny unencrypted EBS/RDS/S3 creation
       - Deny disabling S3 Block Public Access
       - Deny modifying IAM Access Analyzer
    4. Check for overly broad SCPs:
       - SCPs that effectively allow everything (just "Allow *")
       - Missing deny statements for critical operations
    5. Verify no SCP conflicts:
       - Child deny overriding necessary parent allows
       - Unintended permission restrictions
    6. Verify management account protection:
       - SCPs don't apply to management account -- what other guardrails exist?
       - Is the management account used minimally?

    Returns: scp_analysis with gap_assessment
    """
```

### 9.2 RCP Review

```python
def review_resource_control_policies(aws_org):
    """
    Review Resource Control Policies for resource-level guardrails.

    Key concepts:
    - RCPs control maximum permissions on resources across accounts
    - Complement SCPs (which control principal permissions)
    - Prevent resources from being made public or shared externally

    Steps:
    1. Verify RCPs are enabled
    2. Review RCP content for:
       - Deny public access to resources (S3, SQS, SNS, Lambda, etc.)
       - Restrict cross-account resource sharing to org members only
       - Enforce encryption requirements on resources
       - Deny resource policy changes that would make resources public
    3. Verify RCP coverage across all OUs
    4. Check for unintended restrictions (blocking legitimate cross-account patterns)

    Returns: rcp_analysis
    """
```

---

## 10. Monitoring and Logging

### 10.1 CloudTrail IAM Event Review

```python
def review_iam_monitoring(aws_account):
    """
    Review monitoring and logging for IAM events.

    Critical IAM events to monitor:
    - ConsoleLogin (especially failed attempts and root logins)
    - CreateUser, DeleteUser
    - CreateRole, DeleteRole
    - AttachUserPolicy, AttachRolePolicy, PutUserPolicy, PutRolePolicy
    - DetachUserPolicy, DetachRolePolicy, DeleteUserPolicy, DeleteRolePolicy
    - CreateAccessKey, DeleteAccessKey, UpdateAccessKey
    - AssumeRole (especially cross-account and from unusual source IPs)
    - DeactivateMFADevice, DeleteVirtualMFADevice
    - CreateSAMLProvider, UpdateSAMLProvider
    - CreateOpenIDConnectProvider, UpdateOpenIDConnectProvider
    - UpdateAccountPasswordPolicy, DeleteAccountPasswordPolicy
    - CreatePolicy / CreatePolicyVersion (check for admin permissions)
    - PutRolePermissionsBoundary, DeleteRolePermissionsBoundary
    - Any root user activity (all events by root)

    Steps:
    1. Verify CloudTrail is enabled in all regions (multi-region trail)
    2. Verify CloudTrail logs are sent to a centralized, protected S3 bucket
       - Bucket policy prevents deletion or modification
       - Bucket has versioning enabled
       - Logs are encrypted (SSE-KMS preferred)
    3. Check for CloudWatch Alarms or EventBridge rules on critical IAM events
    4. Verify CloudTrail log file integrity validation is enabled
    5. Check for CloudTrail Insights (anomaly detection) enablement
    6. Verify Access Analyzer findings trigger notifications
    7. Check CloudTrail log retention (S3 lifecycle vs Athena queryability)

    Returns: monitoring_assessment with coverage_gaps
    """
```

### 10.2 Credential Report Analysis

```python
def analyze_credential_report(report_csv):
    """
    Parse and analyze the IAM Credential Report.

    Report columns:
    - user, arn, user_creation_time
    - password_enabled, password_last_used, password_last_changed,
      password_next_rotation
    - mfa_active
    - access_key_1_active, access_key_1_last_rotated,
      access_key_1_last_used_date, access_key_1_last_used_region,
      access_key_1_last_used_service
    - access_key_2_active, access_key_2_last_rotated,
      access_key_2_last_used_date, access_key_2_last_used_region,
      access_key_2_last_used_service
    - cert_1_active, cert_1_last_rotated
    - cert_2_active, cert_2_last_rotated

    Analysis rules:
    - CRITICAL: Root user (<root_account>) has active access keys
    - CRITICAL: Root user MFA not active
    - HIGH: User with password_enabled=true but mfa_active=false
    - HIGH: Access key active but access_key_last_used_date > 90 days ago
    - HIGH: Access key never rotated and access_key_last_rotated > 90 days ago
    - MEDIUM: password_last_used > 90 days ago (stale user)
    - MEDIUM: Two active access keys for one user
    - LOW: Certificate active but cert_last_rotated > 365 days
    - INFO: User creation time patterns (identify bulk creation)

    Limitations:
    - Only includes the first 2 access keys per user
    - Does not include service-specific credentials (CodeCommit, SES SMTP, etc.)
    - Can be generated at most once every 4 hours
    - Does not include IAM Identity Center users

    Returns: per_user_findings sorted by severity
    """
```

---

## 11. Common Misconfigurations & Attack Patterns

### 11.1 Critical Misconfigurations

| # | Misconfiguration | Severity | Detection Method | Remediation |
|---|-----------------|----------|-----------------|-------------|
| 1 | `"Action": "*", "Resource": "*"` (wildcard admin) | CRITICAL | Policy scan | Scope to specific actions and resources |
| 2 | Root user with active access keys | CRITICAL | Credential report | Delete root access keys immediately |
| 3 | Root user without MFA | CRITICAL | Credential report | Enable hardware MFA on root |
| 4 | `"Principal": "*"` in resource-based policy | CRITICAL | Access Analyzer | Add conditions or restrict to specific principals |
| 5 | S3 bucket policy with public read/write | CRITICAL | S3 + Access Analyzer | Remove public access; enable Block Public Access |
| 6 | OIDC trust without subject condition | CRITICAL | Trust policy scan | Add `sub` / `repo` condition to prevent any repo assuming role |
| 7 | Cross-account role without ExternalId | HIGH | Trust policy scan | Add `sts:ExternalId` condition |
| 8 | Users without MFA | HIGH | Credential report | Enforce MFA via policy or Identity Center |
| 9 | Access keys unused > 90 days | HIGH | Credential report | Deactivate and delete |
| 10 | EC2 instances using IMDSv1 | HIGH | EC2 describe-instances | Enforce IMDSv2 (`HttpTokens: required`) |
| 11 | KMS key policy with overly broad admin | HIGH | KMS key policy scan | Restrict key administrators to specific roles |
| 12 | Inline policies on users (not groups) | MEDIUM | Policy scan | Move to group-attached managed policies |
| 13 | Missing permissions boundaries for delegated admins | MEDIUM | IAM scan | Implement boundaries for all delegation scenarios |
| 14 | No SCPs in multi-account setup | MEDIUM | Org config check | Implement essential deny SCPs |
| 15 | Missing CloudTrail IAM event monitoring | MEDIUM | CloudTrail check | Enable alarms on critical IAM events |
| 16 | Weak password policy | MEDIUM | Account settings | Enforce strong requirements (>= 14 chars) |
| 17 | NotAction misuse (accidental allow) | MEDIUM | Policy analysis | Replace with explicit Action lists |
| 18 | NotPrincipal with Allow effect | MEDIUM | Policy analysis | Use `Principal` with explicit list + `Condition` |
| 19 | Service role without SourceArn/SourceAccount | MEDIUM | Trust policy scan | Add confused deputy prevention conditions |

### 11.2 Privilege Escalation Paths

```
Common IAM privilege escalation techniques to detect and prevent:

Direct IAM Manipulation:
1.  iam:CreatePolicyVersion         -- Create new policy version with admin permissions
2.  iam:SetDefaultPolicyVersion     -- Switch to a more permissive policy version
3.  iam:AttachUserPolicy            -- Attach AdministratorAccess to self
4.  iam:AttachRolePolicy            -- Attach AdministratorAccess to a role you can assume
5.  iam:PutUserPolicy               -- Add inline admin policy to self
6.  iam:PutRolePolicy               -- Add inline admin policy to role you can assume
7.  iam:PutGroupPolicy              -- Add inline admin policy to a group you belong to
8.  iam:AddUserToGroup              -- Add self to admin group
9.  iam:CreateLoginProfile          -- Create console access for an API-only user
10. iam:UpdateLoginProfile           -- Change another user's password
11. iam:CreateAccessKey              -- Create access key for another (more privileged) user
12. iam:UpdateAssumeRolePolicy       -- Modify trust policy to allow self-assumption of admin role
13. iam:DeleteRolePermissionsBoundary -- Remove boundary to expand a role's effective permissions

PassRole + Service Exploitation:
14. iam:PassRole + lambda:CreateFunction + lambda:InvokeFunction
    -- Create Lambda with admin role, invoke it to run privileged code
15. iam:PassRole + lambda:UpdateFunctionCode
    -- Modify existing Lambda that already has a privileged role
16. iam:PassRole + ec2:RunInstances
    -- Launch EC2 instance with admin role, access via IMDS
17. iam:PassRole + cloudformation:CreateStack
    -- Deploy CloudFormation stack that creates admin resources
18. iam:PassRole + glue:CreateDevEndpoint
    -- Create Glue endpoint with admin role, SSH to it
19. iam:PassRole + sagemaker:CreateNotebookInstance
    -- Create notebook with admin role, execute code
20. iam:PassRole + codebuild:CreateProject + codebuild:StartBuild
    -- Run build with admin role

Service Exploitation (without PassRole):
21. ssm:SendCommand or ssm:StartSession on instances with admin roles
    -- Execute commands on EC2 instances that have privileged instance profiles
22. sts:AssumeRole to an admin role (if trust policy allows)
23. lambda:UpdateFunctionConfiguration + lambda:InvokeFunction
    -- Change Lambda env vars to exfiltrate credentials from existing privileged function
24. iam:CreateServiceLinkedRole
    -- Some service-linked roles have broad permissions

Detection approach:
- Scan all policies for these dangerous action combinations
- Check if any non-admin user/role has these permissions
- Build a privilege escalation graph from current permissions
- Flag any non-admin principal that can reach admin in <= 2 steps
```

### 11.3 Confused Deputy Prevention

```
Confused deputy attack:
  A trusted service is tricked into performing actions on behalf of an
  attacker who shouldn't have access. The service has permissions the
  attacker lacks, and the attacker exploits the trust relationship.

  Example: An attacker discovers a cross-account role ARN. They configure
  their own AWS service to assume that role, gaining access intended only
  for the legitimate service.

Prevention conditions to verify:
  aws:SourceArn      -- Restrict to specific source resource ARNs
  aws:SourceAccount  -- Restrict to specific source account
  aws:SourceOrgID    -- Restrict to your organization
  sts:ExternalId     -- Require external ID for cross-account assumption

Checks:
1. All service roles should have aws:SourceArn or aws:SourceAccount
   conditions in their trust policies
2. All cross-account roles should have sts:ExternalId conditions
3. Resource-based policies should restrict Principal to specific ARNs,
   not just account roots
4. OIDC trust policies (GitHub Actions, GitLab CI) should have
   StringEquals/StringLike conditions on the sub claim
```

---

## 12. Compliance Framework Mapping

### 12.1 CIS AWS Foundations Benchmark v3.0 (IAM Controls)

| CIS Control | Description | Review Section |
|-------------|-------------|---------------|
| 1.1 | Maintain current contact details | Identity review |
| 1.2 | Ensure security contact information is registered | Identity review |
| 1.4 | Ensure no root user access key exists | Credential report (CRITICAL) |
| 1.5 | Ensure MFA is enabled for root user | Credential report (CRITICAL) |
| 1.6 | Ensure hardware MFA for root user | Credential report (HIGH) |
| 1.7 | Eliminate use of root user for admin tasks | CloudTrail monitoring |
| 1.8 | Ensure IAM password policy requires minimum length >= 14 | Password policy |
| 1.9 | Ensure IAM password policy prevents password reuse | Password policy |
| 1.10 | Ensure MFA is enabled for all IAM users with console password | Credential report (HIGH) |
| 1.11 | Do not setup access keys during initial user creation | Credential report |
| 1.12 | Ensure credentials unused for 45+ days are disabled | Credential report (HIGH) |
| 1.13 | Ensure there is only one active access key per user | Credential report (MEDIUM) |
| 1.14 | Ensure access keys are rotated every 90 days or less | Credential report (HIGH) |
| 1.15 | Ensure IAM users receive permissions only through groups | Policy analysis (MEDIUM) |
| 1.16 | Ensure IAM policies with admin privileges are not attached | Policy analysis (CRITICAL) |
| 1.17 | Ensure a support role has been created for AWS Support | Role review (LOW) |
| 1.19 | Ensure IAM Identity Center is used for AWS access | Identity Center review |
| 1.20 | Ensure Access Analyzer is enabled in all regions | Access Analyzer setup |

### 12.2 NIST 800-53 Rev 5 Mapping

| NIST Control | Description | Review Section |
|-------------|-------------|---------------|
| AC-2 | Account Management | Identity review, credential report |
| AC-3 | Access Enforcement | Policy analysis, SCPs |
| AC-5 | Separation of Duties | Role review, permissions boundaries |
| AC-6 | Least Privilege | Least privilege review, Access Analyzer |
| AC-6(1) | Authorize Access to Security Functions | Admin policy review |
| AC-6(5) | Privileged Accounts | Root user, admin role review |
| AC-6(10) | Prohibit Non-Privileged Users from Executing Privileged Functions | Privilege escalation review |
| AC-17 | Remote Access | Federation, MFA review |
| IA-2 | Identification and Authentication | MFA, Identity Center review |
| IA-2(1) | Multi-Factor Authentication | MFA enforcement check |
| IA-4 | Identifier Management | User lifecycle, stale identities |
| IA-5 | Authenticator Management | Password policy, key rotation |
| AU-2 | Audit Events | CloudTrail IAM monitoring |
| AU-3 | Content of Audit Records | CloudTrail event detail |
| AU-6 | Audit Review, Analysis, and Reporting | Access Analyzer findings |

### 12.3 PCI DSS v4.0 Mapping

| PCI Requirement | Description | Review Section |
|----------------|-------------|---------------|
| 7.1 | Processes for restricting access by need-to-know | Least privilege review |
| 7.2 | Access limited to system components needed for job | Policy analysis, SCPs |
| 7.3 | Access to cardholder data restricted by roles | Role review, ABAC |
| 8.2 | User ID management | Identity review, credential report |
| 8.3 | Strong authentication (MFA) | MFA configuration review |
| 8.3.6 | MFA for all non-console admin access | MFA enforcement check |
| 8.4 | MFA for remote access | Federation, Identity Center |
| 8.6 | Application/system account management | Service role review |
| 10.1 | Audit trail established | CloudTrail monitoring |

### 12.4 SOC 2 Trust Services Criteria Mapping

| Criteria | Description | Review Section |
|----------|-------------|---------------|
| CC6.1 | Logical access security (provisioning, modification, removal) | Identity review, credential lifecycle |
| CC6.2 | Authorized access based on need | Least privilege, policy analysis |
| CC6.3 | Role-based access aligned with job function | Group/role review, permissions boundaries |
| CC6.6 | Restrict system access to authorized users | MFA, federation, trust policies |
| CC7.1 | Detection and monitoring | CloudTrail, Access Analyzer |
| CC7.2 | Anomaly detection and response | Access Analyzer findings, CloudTrail Insights |

---

## 13. Review Execution Workflow

### 13.1 Automated Data Collection

```python
def collect_iam_data(aws_account):
    """
    Automated data collection for IAM review.
    Runs all necessary AWS CLI commands and saves output.

    This function should be run FIRST before any analysis.
    All outputs saved to ./iam_review_data/ directory.

    Steps:
    1. Create output directory:
       mkdir -p ./iam_review_data

    2. Account-level data:
       aws iam get-account-summary > account_summary.json
       aws iam get-account-password-policy > password_policy.json
       aws iam get-account-authorization-details > auth_details.json
         ^^^ This is the MOST IMPORTANT command. It returns ALL users,
             groups, roles, and policies (managed + inline) in one call.

    3. Credential report:
       aws iam generate-credential-report  (may need to wait/retry)
       aws iam get-credential-report --output text --query Content | base64 -d > cred_report.csv

    4. Access Analyzer:
       aws accessanalyzer list-analyzers > analyzers.json
       For each analyzer:
         aws accessanalyzer list-findings --analyzer-arn ARN > findings_REGION.json

    5. Organizations (if applicable):
       aws organizations describe-organization > org.json
       aws organizations list-policies --filter SERVICE_CONTROL_POLICY > scps.json
       For each SCP:
         aws organizations describe-policy --policy-id ID > scp_ID.json

    6. Cross-service resource policies:
       aws s3api list-buckets > buckets.json
       For each bucket:
         aws s3api get-bucket-policy --bucket NAME > bucket_policy_NAME.json
         aws s3api get-public-access-block --bucket NAME > public_block_NAME.json
       aws kms list-keys > kms_keys.json
       For each key:
         aws kms get-key-policy --key-id ID --policy-name default > kms_policy_ID.json
       aws lambda list-functions > lambda_functions.json
       For each function:
         aws lambda get-policy --function-name NAME > lambda_policy_NAME.json
       aws sqs list-queues > sqs_queues.json
       For each queue:
         aws sqs get-queue-attributes --queue-url URL --attribute-names Policy > sqs_policy.json
       aws sns list-topics > sns_topics.json
       For each topic:
         aws sns get-topic-attributes --topic-arn ARN > sns_attrs_ARN.json

    7. CloudTrail verification:
       aws cloudtrail describe-trails > trails.json
       aws cloudtrail get-trail-status --name TRAIL > trail_status.json

    8. IAM Identity Center (if enabled):
       aws sso-admin list-instances > sso_instances.json
       For each instance:
         aws sso-admin list-permission-sets --instance-arn ARN > permission_sets.json

    Returns: path to iam_review_data directory
    """
```

### 13.2 Full IAM Security Review Procedure

```python
def execute_full_iam_review(aws_account_or_config):
    """
    Execute a comprehensive IAM security review.

    Input: AWS account access (CLI configured) OR exported IAM configuration files

    Phase 1 -- Discovery & Data Collection:
        1. Run collect_iam_data() to gather all IAM configuration
        2. Parse get-account-authorization-details for the full picture
        3. Parse credential report for user/key analysis
        4. Collect Access Analyzer findings
        5. Collect cross-service resource policies

    Phase 2 -- Identity Review:
        1. Run review_identity_best_practices()
        2. Run review_credential_hygiene()
        3. Run analyze_credential_report()
        4. Identify all admin-level users/roles
        5. Run review_iam_identity_center() (if applicable)

    Phase 3 -- Policy Review:
        1. Run review_least_privilege()
        2. Run validate_policies_with_analyzer()
        3. Scan for all 19 critical misconfigurations (Section 11.1)
        4. Check for privilege escalation paths (Section 11.2)

    Phase 4 -- Role Review:
        1. Run review_role_trust_policies()
        2. Run review_instance_profiles()
        3. Run analyze_role_chaining()
        4. Check confused deputy prevention

    Phase 5 -- Cross-Service Resource Policies:
        1. Run review_cross_service_resource_policies()
        2. Correlate with Access Analyzer external access findings

    Phase 6 -- Advanced Controls:
        1. Run review_abac_implementation()
        2. Run review_permissions_boundaries()
        3. Run review_session_policies()

    Phase 7 -- Organizational Controls:
        1. Run review_service_control_policies()
        2. Run review_resource_control_policies()

    Phase 8 -- Monitoring:
        1. Run review_iam_monitoring()
        2. Verify Access Analyzer setup in all regions

    Phase 9 -- Report Generation:
        1. Aggregate all findings by severity
        2. Map findings to compliance frameworks (CIS, NIST, PCI DSS, SOC 2)
        3. Generate executive summary
        4. Create detailed findings (see Section 14)
        5. Provide prioritized remediation roadmap

    Returns: comprehensive_iam_security_report
    """
```

### 13.3 Quick IAM Health Check

```python
def execute_quick_iam_check(aws_account_or_config):
    """
    Rapid IAM health check focusing on critical issues only.
    Designed to complete in under 5 minutes.

    Checks (in priority order):
    1. Root user: MFA enabled? Access keys exist?
    2. Credential report: Any users without MFA?
    3. Policy scan: Any "Action": "*", "Resource": "*"?
    4. Trust policies: Any "Principal": "*"?
    5. Access Analyzer: Any active CRITICAL/HIGH findings?
    6. Password policy: Meets minimum standards?
    7. S3: Any buckets with public policies?
    8. CloudTrail: Is it enabled in all regions?

    Returns: quick_health_summary with PASS/FAIL per check
    """
```

---

## 14. Severity Classification

| Severity | Description | SLA Recommendation |
|----------|-------------|-------------------|
| **CRITICAL** | Immediate risk of unauthorized access, data breach, or account compromise. Examples: root keys, public access, wildcard admin policies, OIDC trust without subject filter | Remediate within 24 hours |
| **HIGH** | Significant security weakness that could be exploited. Examples: missing MFA, stale credentials, overly broad cross-account trust, IMDSv1 on EC2 | Remediate within 7 days |
| **MEDIUM** | Security improvement needed but not immediately exploitable. Examples: inline policies, missing boundaries, weak password policy, missing SCPs | Remediate within 30 days |
| **LOW** | Best practice deviation with minimal direct risk. Examples: unused certificates, suboptimal group structure, missing support role | Remediate within 90 days |
| **INFO** | Informational finding for awareness. Examples: user creation patterns, service usage statistics, IAM quota utilization | Review during next audit cycle |

---

## 15. Report Output Format

The review generates a structured report:

```
IAM Security Review Report
==========================

1. Executive Summary
   - Overall risk rating (Critical/High/Medium/Low)
   - Total findings by severity
   - Top 5 priority remediation items
   - Compliance posture summary

2. Scope
   - Account(s) reviewed
   - Date of review
   - Data sources used
   - Compliance frameworks assessed

3. Findings (grouped by domain)
   3.1 Identity & Authentication
   3.2 IAM Identity Center
   3.3 Credentials
   3.4 Policies
   3.5 Roles & Trust
   3.6 Cross-Service Resource Policies
   3.7 Advanced Controls
   3.8 Organizational Controls
   3.9 Monitoring & Logging

4. Each Finding Contains:
   - ID: IAM-XXXX
   - Title: Brief description
   - Severity: CRITICAL | HIGH | MEDIUM | LOW | INFO
   - Domain: Which review domain
   - Description: What was found
   - Evidence: Specific resources, policy excerpts, CLI output
   - Impact: What could happen if not remediated
   - Remediation: Step-by-step fix instructions with CLI commands
   - Compliance: Mapped CIS/NIST/PCI/SOC2 controls
   - Reference: AWS documentation link

5. Remediation Roadmap
   - Phase 1 (Immediate / 24h): Critical findings
   - Phase 2 (This week): High findings
   - Phase 3 (This month): Medium findings
   - Phase 4 (This quarter): Low findings

6. Compliance Summary
   - CIS Benchmark pass/fail matrix
   - NIST 800-53 control coverage
   - PCI DSS requirement status

7. Appendices
   - Full credential report analysis
   - Complete policy inventory
   - Role trust policy matrix
   - Privilege escalation path diagram
   - Cross-service resource policy inventory
```

### 15.1 Sample Finding

```
Finding ID: IAM-0042
Title: Cross-account role lacks ExternalId condition
Severity: HIGH
Domain: Roles & Trust

Description:
  IAM role "CrossAccountDataAccess" trusts account 987654321098 but
  does not require an sts:ExternalId in the trust policy Condition
  block. This makes the role vulnerable to confused deputy attacks.

Evidence:
  Role ARN: arn:aws:iam::123456789012:role/CrossAccountDataAccess
  Trust Policy:
    {
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::987654321098:root"},
      "Action": "sts:AssumeRole"
    }

Impact:
  Any principal in account 987654321098 (or any service that account
  trusts) can assume this role. If the trusted account is compromised
  or is a third-party vendor, the attacker gains access to resources
  in your account with this role's permissions.

Remediation:
  Add an ExternalId condition to the trust policy:
    aws iam update-assume-role-policy --role-name CrossAccountDataAccess \
      --policy-document '{
        "Version": "2012-10-17",
        "Statement": [{
          "Effect": "Allow",
          "Principal": {"AWS": "arn:aws:iam::987654321098:root"},
          "Action": "sts:AssumeRole",
          "Condition": {
            "StringEquals": {
              "sts:ExternalId": "UNIQUE-SECRET-VALUE-HERE"
            }
          }
        }]
      }'

Compliance:
  - CIS AWS Benchmark: 1.16
  - NIST 800-53: AC-3, AC-6
  - SOC 2: CC6.1

Reference:
  https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html
```

---

## 16. AWS CLI Commands Reference

Key AWS CLI commands used during review:

```bash
# =============================================================
# MOST IMPORTANT: Full IAM dump in one command
# =============================================================
aws iam get-account-authorization-details > auth_details.json
# Returns ALL users, groups, roles, policies (managed + inline)
# This single command provides ~80% of the data needed for review

# =============================================================
# Identity Discovery
# =============================================================
aws iam get-account-summary
aws iam list-users
aws iam list-groups
aws iam list-roles
aws iam list-instance-profiles
aws iam list-saml-providers
aws iam list-open-id-connect-providers
aws iam get-account-password-policy

# =============================================================
# Credential Analysis
# =============================================================
aws iam generate-credential-report
aws iam get-credential-report --output text --query Content | base64 -d
aws iam list-mfa-devices --user-name USERNAME
aws iam list-access-keys --user-name USERNAME
aws iam get-access-key-last-used --access-key-id AKIAXXXXXXXX
aws iam list-service-specific-credentials --user-name USERNAME

# =============================================================
# Policy Analysis
# =============================================================
aws iam list-policies --scope Local
aws iam list-attached-user-policies --user-name USERNAME
aws iam list-user-policies --user-name USERNAME
aws iam list-attached-group-policies --group-name GROUPNAME
aws iam list-group-policies --group-name GROUPNAME
aws iam list-attached-role-policies --role-name ROLENAME
aws iam list-role-policies --role-name ROLENAME
aws iam get-policy-version --policy-arn ARN --version-id VERSION
aws iam get-user-policy --user-name USERNAME --policy-name POLICYNAME
aws iam get-role-policy --role-name ROLENAME --policy-name POLICYNAME
aws iam get-group-policy --group-name GROUPNAME --policy-name POLICYNAME

# =============================================================
# Role Analysis
# =============================================================
aws iam get-role --role-name ROLENAME    # Includes trust policy
aws iam list-role-tags --role-name ROLENAME
aws iam get-role --role-name ROLENAME --query 'Role.AssumeRolePolicyDocument'

# =============================================================
# Permissions Boundaries
# =============================================================
aws iam get-user --user-name USERNAME --query 'User.PermissionsBoundary'
aws iam get-role --role-name ROLENAME --query 'Role.PermissionsBoundary'

# =============================================================
# Access Analyzer
# =============================================================
aws accessanalyzer list-analyzers
aws accessanalyzer list-findings --analyzer-arn ARN --filter '{"status": {"eq": ["ACTIVE"]}}'
aws accessanalyzer validate-policy \
  --policy-document file://policy.json \
  --policy-type IDENTITY_POLICY

# =============================================================
# Cross-Service Resource Policies
# =============================================================
# S3
aws s3api get-bucket-policy --bucket BUCKET
aws s3api get-public-access-block --bucket BUCKET
aws s3control get-public-access-block --account-id ACCOUNT_ID

# KMS
aws kms list-keys
aws kms get-key-policy --key-id KEY_ID --policy-name default
aws kms list-grants --key-id KEY_ID

# Lambda
aws lambda get-policy --function-name FUNCTION

# SQS
aws sqs get-queue-attributes --queue-url URL --attribute-names Policy

# SNS
aws sns get-topic-attributes --topic-arn ARN

# Secrets Manager
aws secretsmanager get-resource-policy --secret-id SECRET

# ECR
aws ecr get-repository-policy --repository-name REPO

# =============================================================
# Organization
# =============================================================
aws organizations describe-organization
aws organizations list-policies --filter SERVICE_CONTROL_POLICY
aws organizations describe-policy --policy-id p-XXXXXXXX
aws organizations list-targets-for-policy --policy-id p-XXXXXXXX

# =============================================================
# IAM Identity Center
# =============================================================
aws sso-admin list-instances
aws sso-admin list-permission-sets --instance-arn ARN
aws sso-admin describe-permission-set --instance-arn ARN --permission-set-arn PS_ARN
aws sso-admin list-account-assignments --instance-arn ARN --account-id ACCT --permission-set-arn PS_ARN
aws identitystore list-users --identity-store-id STORE_ID
aws identitystore list-groups --identity-store-id STORE_ID

# =============================================================
# CloudTrail (IAM events)
# =============================================================
aws cloudtrail describe-trails
aws cloudtrail get-trail-status --name TRAIL_NAME
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ConsoleLogin \
  --start-time 2026-01-01T00:00:00Z
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=root
```

---

## 17. IAM Quotas and Limits

Key IAM limits that can impact security architecture:

| Resource | Default Limit | Notes |
|----------|--------------|-------|
| IAM users per account | 5,000 | Use federation for large organizations |
| Groups per account | 300 | |
| Roles per account | 1,000 | Increasable via support |
| Managed policies per account | 1,500 | Customer-managed only |
| Managed policies per user/role/group | 10 | Hard limit; may force inline policies |
| Inline policy size (user) | 2,048 chars | |
| Inline policy size (role) | 10,240 chars | |
| Inline policy size (group) | 5,120 chars | |
| Managed policy size | 6,144 chars | Per policy version |
| Policy versions per managed policy | 5 | Delete old versions before creating new |
| Groups per user | 10 | Hard limit |
| Access keys per user | 2 | |
| MFA devices per user | 8 | |
| Trust policy size | 2,048 chars | Can be limiting for complex trust relationships |
| Role session duration | 1-12 hours | 1 hour max when role-chaining |
| SCP maximum size | 5,120 chars | Can be limiting for complex guardrails |
| SCPs per organization | 1,000 | |
| SCPs attached per OU/account | 5 | |

---

## 18. Limitations

- This skill analyzes IAM configurations and policies; it does not perform live penetration testing
- CloudTrail analysis is limited to available log retention (default 90 days for Event History)
- Some findings require manual verification of business justification
- Cross-account analysis requires access to all relevant accounts
- Real-time credential compromise detection is outside scope (use GuardDuty)
- Credential report has a 4-hour generation cooldown and only shows first 2 access keys per user
- Credential report does not include IAM Identity Center users
- Service-specific resource policies require per-service read permissions
- Policy simulation (aws iam simulate-principal-policy) is not covered but can complement this review

## 19. Requirements

- AWS CLI v2 configured with appropriate IAM permissions, OR
- Exported IAM configuration files (JSON/CSV) for offline analysis
- Required IAM permissions for live review:
  - `iam:Get*`, `iam:List*`, `iam:GenerateCredentialReport`, `iam:GetCredentialReport`
  - `access-analyzer:List*`, `access-analyzer:Get*`, `access-analyzer:ValidatePolicy`
  - `organizations:Describe*`, `organizations:List*` (if reviewing org controls)
  - `sso-admin:List*`, `sso-admin:Describe*`, `identitystore:List*` (if reviewing Identity Center)
  - `s3:GetBucketPolicy`, `s3:GetPublicAccessBlock` (for S3 resource policies)
  - `kms:GetKeyPolicy`, `kms:ListGrants`, `kms:ListKeys` (for KMS policies)
  - `lambda:GetPolicy`, `lambda:ListFunctions` (for Lambda resource policies)
  - `sqs:GetQueueAttributes`, `sqs:ListQueues` (for SQS policies)
  - `sns:GetTopicAttributes`, `sns:ListTopics` (for SNS policies)
  - `secretsmanager:GetResourcePolicy` (for Secrets Manager policies)
  - `cloudtrail:DescribeTrails`, `cloudtrail:GetTrailStatus`, `cloudtrail:LookupEvents`
- Recommended: A dedicated read-only IAM role for security review with the above permissions

## 20. Change Log

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-03-27 | Initial release -- 9-domain IAM review covering identity & authentication, credentials, policy analysis, roles & trust, cross-service resource policies, IAM Identity Center, advanced controls (ABAC, permissions boundaries, session policies), organizational controls (SCPs, RCPs), and monitoring & logging. Includes 24 privilege escalation detection paths, 19 critical misconfiguration checks, compliance mapping (CIS v3.0, NIST 800-53, PCI DSS v4.0, SOC 2), automated data collection workflow, severity classification with SLA recommendations, and structured report output format. |
