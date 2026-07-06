# Cloud Hardening — controls that break each stage

One control per attacker move. Applying these removes the technique rather than only detecting it. Each section mirrors a stage in [detection-signals.md](detection-signals.md).

## Lateral movement

- **Enforce IMDSv2 with a hop limit of 1** on every instance (AWS `HttpTokens=required`, `HttpPutResponseHopLimit=1`). This single setting defeats the SSRF -> metadata -> role-credential path. On Azure and GCP, restrict the metadata endpoint and prefer Workload Identity over long-lived tokens.
- **Scope role trust policies tightly** — no wildcard principals, condition on account or organisation ID — so `AssumeRole` cannot chain freely across accounts.
- **Gate `ssm:SendCommand`** behind least privilege and enable Systems Manager session logging.

## Privilege escalation

- **Least privilege plus permission boundaries** (AWS) cap what any principal can grant, so the self-granting actions (`AttachUserPolicy`, `PutUserPolicy`, `CreatePolicyVersion`, `PassRole`) cannot reach administrator.
- **Service Control Policies (SCPs)** at the organisation level deny the dangerous IAM verbs outright for most accounts.
- Azure: limit who holds Owner or User Access Administrator, and review app-registration owners. GCP: remove `iam.serviceAccountTokenCreator` and `actAs` from identities that do not deploy code.

## Data exfiltration

- **S3 Block Public Access account-wide**, and **deny external snapshot sharing** with an SCP on `ec2:ModifySnapshotAttribute` / `rds:ModifyDBSnapshotAttribute` targeting an external account.
- **Restrict `PutBucketReplication`** destinations to owned accounts only.
- Encrypt snapshots with a customer-managed key the attacker account cannot use, so a shared snapshot is unreadable.

## Defense evasion

- **Make the trail tamper-resistant**: an org-wide CloudTrail that member accounts cannot stop, log-file validation on, and logs delivered to a separate, locked-down logging account.
- **Enable data events plus multi-region and multi-account coverage** so there is no unlogged region and no object-read blind spot.
- **Keep GuardDuty and Detective** (or Defender for Cloud / Security Command Center) on everywhere, alerting on the events in [detection-signals.md](detection-signals.md).

## Verify

Re-run the matching offensive technique from the [`cloud-containers`](../../cloud-containers/reference/INDEX.md) scenarios and confirm it now fails or raises an alert. A control that is not re-tested is an assumption, not a fix.
