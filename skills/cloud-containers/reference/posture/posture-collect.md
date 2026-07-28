# Posture collection — identity binding, the evidence tree, partial collection

Read-only collection is the whole factual basis of a posture review. If collection is wrong, every
verdict downstream is wrong in the same direction — usually toward a false pass, because a query
that returns nothing looks exactly like a tenancy with nothing wrong.

## 1. Bind identity to scope — first call, fail closed

**Before any inventory call**, prove which tenancy / subscription / cluster the credential actually
belongs to, and compare it to the authorised scope. Stop if they differ.

This is not ceremony. Cloud CLIs pick up ambient credentials from the environment, and `kubectl`
defaults to whatever `current-context` happens to be — which on a shared workstation may be a
previous engagement's cluster or an internal one. An unbound run is unauthorised enumeration of a
third party, and it is indistinguishable from the authorised run in the output.

| Provider | Assert before collecting | Compare against |
|---|---|---|
| OCI | `oci iam region-subscription list`, and the tenancy OCID the config profile resolves to | the tenancy OCID in scope |
| Azure | `az account show` → `id`, `tenantId` | the subscription + tenant in scope |
| Kubernetes | explicit `--kubeconfig` and `--context`; read the API server URL and CA fingerprint | the cluster endpoint in scope |

Record the asserted identity in the collection tree. A reviewer must be able to see *which* tenancy
produced the evidence without trusting the folder name.

## 2. Read-only means enforced, not intended

Use a credential whose permissions cannot mutate. For OCI that is an Auditor-style policy —
`Allow group <auditors> to read all-resources in tenancy` — not an administrator account that you
have promised to be careful with. Where the platform offers a built-in read role (Azure `Reader`
plus `Security Reader`; Kubernetes a `view`-bound service account), use it.

Restrict the collector itself to a read-only operation allowlist so a mistyped subcommand cannot
write. Least privilege at the credential, and a guard at the tool: either alone is one mistake away
from a change in a client tenancy.

## 3. Enumerate the whole estate

Four traps, each producing a **false pass**. All four have to be handled explicitly by the collector
rather than left to the assessor to remember.

**Compartment / resource-group traversal.** OCI resources live in a compartment tree. A query
scoped to the root compartment returns almost nothing in a real tenancy, and reads as clean. Walk
the subtree — `oci iam compartment list --compartment-id-in-subtree true --all` — or use a
tenancy-wide Advanced Resource Query, which searches the whole tenancy in one call:

```
oci search resource structured-search --query-text "query <type> resources where <predicate>"
```

Prefer the query where one exists: fewer calls, and no traversal gap to get wrong.

**Regional resources.** Many resources exist per-region, and a single-region collection silently
misses every other region. Enumerate subscribed regions first, then loop. A tenancy subscribed to
three regions where you collected one is 2/3 unassessed, reported as assessed.

**Inherited vs explicitly set.** An absent setting may be inheriting a safe default — or an unsafe
one. Collect the *effective* value. "Key not present" is not evidence of anything on its own.

**Identity domains vs legacy IAM.** An OCI tenancy may use identity domains or legacy IAM, and the
user, group and policy surface differs between them. Detect which is in use before collecting
identity evidence, and record the answer; an identity-domain tenancy assessed with legacy
assumptions produces confidently wrong IAM verdicts.

## 4. The evidence tree

One file per service per scope unit. Every record carries the resource id (OCID / ARN / uid), the
call that produced it, and a collection timestamp. Raw responses, unedited — the assessor reads
these, and a reviewer must be able to re-derive any verdict from them.

```
collect/
  identity.json          asserted tenancy/subscription/cluster + the assertion calls
  regions.json           subscribed regions actually collected
  scope.json             compartments / resource groups / namespaces enumerated
  <region>/<service>.json
  _errors.json           every call that failed, with the reason
```

## 5. Partial collection is a first-class outcome

A collection that hit an access-denied, a throttle, or an unsubscribed region is **not** a
collection with fewer results. It is a collection with unknown regions, and the difference decides
whether a control can be assessed at all.

- Never let a failed call become an empty result. Record it in `_errors.json` with the scope unit,
  the call and the reason.
- A control whose evidence is missing because collection failed is `REQUIRES_MANUAL_REVIEW`, never
  `MET` and never `NOT_APPLICABLE`.
- Report the collection completeness alongside the verdicts: *n* of *m* compartments, *r* of *s*
  regions, and every error. A posture report that does not state its own coverage is not evidence.

## 6. Determinism

Collection output should be replayable: the same tenancy state produces the same tree, so an
assessment can be re-run without touching the client environment, and a fixture can stand in for a
live tenancy in tests. Sort collections by resource id and keep the timestamp in a dedicated field
rather than interleaved through the records.
