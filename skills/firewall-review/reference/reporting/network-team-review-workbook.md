---
name: network-team-review-workbook
description: Customer-collaboration Excel profile for firewall rule audits. Produces one consolidated workbook with a filterable Network Team Review sheet, complete rule inventory, technical evidence, response fields, and an explicit evidence-gap ledger.
---

# Network-Team Review Workbook

Use this profile when the customer routes firewall-review observations to a network team for justification and remediation. The deliverable is one `.xlsx` file; supporting detail belongs on additional worksheets in that same file, not in separate trackers.

This is a reporting profile layered over the current six-sheet renderer. Do not claim the reference renderer natively supports the profile unless its implementation has been updated and verified. If necessary, generate the consolidated workbook as an engagement-specific reporting step from the approved JSONL and normalized-rule data.

## Sheet order

1. **Network Team Review** — primary collaboration sheet; first visible tab.
2. **Executive Summary** — scope, counts, severity, coverage, top actions.
3. **Assessment Guide** — evidence states, severity definitions, response instructions, limitations.
4. **All Rules** — one row for every parsed rule, including rules with no observation.
5. **Device & Benchmark Findings** — configuration/hardening observations kept distinct from rule findings.
6. **Shadow & Duplicate Analysis** — candidate rule relationships with comparison basis and limitations.
7. **PSIRT Advisories** — only when exact product/build evidence and advisory provenance are available.
8. **Evidence Gaps** — runtime, classification, ownership, central-control, identity, and input-completeness gaps.
9. **Discarded / False Positives** — transparent exclusions and reasons.

Omit a conditional sheet only when it is not applicable, and state that in Assessment Guide. Never omit Evidence Gaps.

## Network Team Review row grain

One row equals one observation against one rule. A rule with three distinct observations has three rows. A multi-rule relationship has one primary rule per row plus `Related Rule`; create reciprocal rows only when each rule needs a separate owner response.

Do not merge cells in the data region. Repeat `Vulnerability / Observation` and `Severity` on every row so filters, sorting, exports, and comments remain reliable.

### Required analysis and rule fields

| Column | Requirement |
|---|---|
| `Observation ID` | Stable unique identifier |
| `Vulnerability / Observation` | Client-readable category, such as “Filter Rules Allow To Any Destination Address” |
| `Severity` | Approved risk rating |
| `Evidence State` | Value from the evidence-state contract |
| `Confidence` | High / Medium / Low; independent of severity |
| `Rule Number` | Native policy/rule ID |
| `Name` | Rule name/comment |
| `Active` | Yes/No from configuration; never inferred from hits |
| `Action` | Allow/Deny/Reject/Drop |
| `Source` | Exact source objects/addresses |
| `Destination` | Exact destination objects/addresses |
| `Service` | Exact services/ports/applications |
| `Schedule` | Exact configured schedule or `always` |
| `NAT` | Configured NAT state/type when available |
| `Auth` | Configured identity/auth field; blank means not evidenced, not necessarily absent |
| `UTM Features` | Attached security profiles/features |
| `Log` | Configured logging state/level |
| `Finding Code` | Detector or semantic check ID |
| `Exact Evidence` | Quoted config excerpt, kept within spreadsheet cell limits |
| `Source File / Line` | Traceable source location |
| `Reproduction / PoC` | Repeatable static comparison or validation steps |
| `Rationale` | Rule-specific risk explanation |
| `Recommendation` | Actionable, minimally disruptive remediation |
| `Control Mapping` | Version-pinned control references |
| `Related Rule` | Duplicate/shadow/contradiction counterpart, if applicable |
| `Validation Required` | Runtime or business step needed before change |

### Required network-team response fields

Keep these cells visibly editable and use data validation where appropriate:

- `Network Team Comments / Justification`
- `Business Owner`
- `Business Purpose`
- `Hit Count`
- `Counter Window / Reset Time`
- `Source Environment`
- `Destination Environment`
- `Disposition` — Remediate / Retain with Justification / Accept Risk / False Positive / Needs More Evidence
- `Remediation Owner`
- `Ticket / Change ID`
- `Target Date`
- `Closure Evidence`
- `Review Status` — Open / In Review / Awaiting Evidence / In Progress / Closed

Never pre-fill customer-owned fields with invented names, business purposes, hit counts, classifications, or dates. Use blank cells or `Not provided` according to the customer's preference.

## All Rules coverage sheet

The All Rules sheet proves audit coverage. Include every parsed rule, enabled and disabled, with:

- device/VDOM/context, native rule ID, order, status, action, source, destination, service, schedule, NAT, security profiles, logging, comments, and source line;
- `Assessment Status`: Finding / No static exception detected / Needs runtime evidence / Not assessed;
- observation count and linked Observation IDs;
- parse warnings or unresolved object references.

The report may say “every enabled parsed policy was assessed” only when this sheet reconciles to the parser inventory and no in-scope policy block is deferred.

## Evidence Gaps sheet

Use one row per gap, not one vague limitations paragraph. Columns:

`Gap ID`, `Class`, `Missing Evidence`, `Affected Device/Rules`, `What Can Be Concluded`, `What Cannot Be Concluded`, `How to Close`, `Owner`, `Status`.

At minimum consider traffic/hit data, runtime policy evaluation, environment classification, ownership/tickets, central management/analytics, upstream identity controls, routes/SD-WAN/FQDN state, and export completeness.

## Visual and interaction rules

- Orange or brand-primary header row; high-contrast severity cells.
- Yellow or other clearly distinct fill for customer-editable response fields.
- Freeze the header and identifier columns; enable filters over the full used range.
- Wrap long evidence/recommendation cells; cap widths and enable row auto-height where supported.
- No hidden findings, hidden evidence gaps, or hidden customer-response columns.
- Avoid merged data cells, macros, external links, and volatile formulas.
- Keep formulas for summaries/counts; keep evidence and conclusions as values.

## Workbook QA gate

Before release:

1. Open and round-trip the workbook with a spreadsheet library; fail on corruption.
2. Render representative sheets or inspect them in Excel/LibreOffice for clipping and unreadable widths.
3. Reconcile counts: parsed rules ↔ All Rules; observation rows ↔ summary and severity totals; enabled rules ↔ assessment statuses.
4. Verify every rule observation has rule ID, source citation, evidence state, rationale, recommendation, and validation requirement when applicable.
5. Verify every static quote exists in the supplied input and every input hash matches the manifest.
6. Verify formulas contain no error values after recalculation, validations cover all intended response rows, and filters/freeze panes are present.
7. Scan for customer data copied from another engagement and for unsupported claims listed in the evidence-state contract.
