# Cloud Detection Signals — per attacker stage

The stealthiest cloud attacks move no bytes across the victim network, so volume-based monitoring sees nothing. Watch the **control-plane API call**, not data-transfer volume.

## Prerequisites (without these, the signals below are invisible)

- **AWS:** an organization-wide CloudTrail delivering to every account and region; **S3 / Lambda data events enabled** (object-level reads are off by default); GuardDuty on in every region; optionally Detective for graph triage.
- **Azure:** Activity Log plus Entra ID sign-in and audit logs shipped to a Log Analytics workspace; Microsoft Defender for Cloud on.
- **GCP:** Cloud Audit Logs with **Data Access logs enabled** (Admin Activity logs are on by default, Data Access logs are not); Security Command Center on.

## AWS — CloudTrail events by stage

| Stage | Alert on | Why it is suspicious |
|---|---|---|
| Lateral movement | `AssumeRole` where the target account differs from the caller account; `SendCommand`; repeated IMDSv1 metadata use | Cross-account role hops and Run-Command pivots are rare in normal operations |
| Privilege escalation | `AttachUserPolicy`, `PutUserPolicy`, `CreateAccessKey` for another principal, `CreatePolicyVersion`, `CreateFunction` or `RunInstances` paired with `PassRole` | All are self-granting permission changes |
| Data exfiltration | `ModifySnapshotAttribute` or `ModifyDBSnapshotAttribute` adding an external account; a new `PutBucketReplication`; a surge in `GetObject` (needs data events) | A copy is shared or replicated out with no network egress |
| Defense evasion | `StopLogging`, `DeleteTrail`, `UpdateTrail`, `DeleteDetector` (GuardDuty); any activity in a region with no trail | Tampering with, or hiding from, the recorders |

## Azure equivalents

- Managed-identity token requests at the IMDS endpoint.
- `Microsoft.Compute/virtualMachines/runCommand/action` (Run Command).
- A new app-registration secret (`Update application – Certificates and secrets`).
- Role-assignment writes: `Microsoft.Authorization/roleAssignments/write`.

## GCP equivalents

- `GenerateAccessToken` or `SignBlob` on a service account.
- `setMetadata` on a compute instance (startup-script or SSH-key injection).
- `setIamPolicy` granting a new principal a role.
- `iam.serviceAccountKeys.create`.

## Principle

Each row above maps one-to-one to an attacker move in the offensive scenarios. Pair every alert with the control in [hardening-controls.md](hardening-controls.md) that removes the underlying technique.
