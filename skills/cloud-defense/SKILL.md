---
name: cloud-defense
description: Detect and break the cloud post-compromise attack chain (AWS / Azure / GCP) — per-stage CloudTrail / Activity-Log / Audit-Log detection signals and the preventive controls that close each step. Use for cloud detection engineering, hardening, remediation write-ups, or blue-team posture review of the lateral-movement -> privilege-escalation -> exfiltration -> evasion chain.
---

# Cloud Defense

The blue-team counterpart to [`cloud-containers`](../cloud-containers/SKILL.md). For each attacker move — lateral movement, privilege escalation, data exfiltration, defense evasion — this skill gives the log event to alert on and the single control that removes the technique. Use it to turn an offensive cloud finding into a concrete detection and remediation.

## When to use

- Writing the remediation / hardening section of a cloud pentest report.
- Cloud detection engineering: deciding which control-plane events to alert on.
- Reviewing an AWS / Azure / GCP account's posture against the post-compromise chain.

## Workflow

1. Confirm the logging prerequisites are in place (org-wide trail, data events, threat detection on) — without them the signals below are invisible.
2. Map each attacker stage to its detection signal — see [reference/detection-signals.md](reference/detection-signals.md).
3. Apply the preventive control that breaks each stage — see [reference/hardening-controls.md](reference/hardening-controls.md).
4. Re-run the matching offensive technique from [`cloud-containers`](../cloud-containers/SKILL.md) to confirm the control holds or the alert fires.

## References

- [reference/INDEX.md](reference/INDEX.md) — router
- [reference/detection-signals.md](reference/detection-signals.md) — per-stage log signals + logging prerequisites
- [reference/hardening-controls.md](reference/hardening-controls.md) — the control that breaks each stage
