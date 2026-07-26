# OData deep authorization — $metadata enumeration + $filter/$orderby cross-tenant BOLA

OData endpoints (`/odata/`, `.svc/`, `$metadata`) expose a typed, queryable data model — and their authorization is frequently enforced only at the *entity-set* level, not per-row, so `$filter`/`$orderby`/`$expand` become BOLA/BOPLA primitives. This is a headline-grade class that a generic REST pass misses because the query surface is in the OData operators, not the path.

## 1. Enumerate the model ($metadata)

```
GET /odata/$metadata            # the full EDMX: every EntitySet, EntityType, property, NavigationProperty
GET /odata/                     # the service document: the exposed entity sets
```

`$metadata` is the map: it names every entity set (`Orders`, `Accounts`, `Users`...), every property (including ones the UI never shows), and every `NavigationProperty` (the `$expand` join graph). Pull it first — it tells you exactly which sets to probe and which properties to `$filter`/`$orderby` on.

## 2. Per-role access matrix over the entity sets

As the LOWEST-privilege role (e.g. a plain client user), request each entity set directly:

```
GET /odata/Orders
GET /odata/Accounts?$top=1
```

A set that returns real data to a role that should not see it (or returns *other tenants'* rows) is a broken-object-level / broken-function-level authorization finding. Test **every** set from `$metadata`, not just the ones the client app calls.

## 3. $filter / $orderby as a BOLA + data-inference primitive

Even when the set is "protected", the operators leak:

- **Cross-tenant `$filter`:** `?$filter=TenantId eq <other-tenant-guid>` or `?$filter=OwnerId eq <victim-id>` — if the server filters by your identity only *implicitly* (row-level security absent), an explicit filter to another tenant's key returns their rows.
- **`$orderby` boolean-inference (blind):** where row *contents* are hidden but *existence*/ordering is not, `?$orderby=SecretProperty asc` vs `desc` changes the returned order — a blind oracle over a property you can't select. Combine with `$top=1` to binary-search a value.
- **`$select` over-read:** `?$select=Ssn,Salary` pulls properties the UI omits but the API serializes.
- **`$expand` lateral read:** `?$expand=Owner($select=Email)` traverses a NavigationProperty into a related entity whose *direct* set is protected — authorization is often missing on the expanded path.
- **`$count`/`$filter` enumeration:** `?$count=true&$filter=startswith(Name,'a')` enumerates record counts per prefix even when rows are withheld.

## 4. Injection through OData operators

`$filter` is a mini-expression language mapped onto a backend query — probe for injection where the provider naively concatenates:

- `?$filter=Name eq 'x' or 1 eq 1` returning all rows = the filter is not parameterised (authz-bypass + possible SQLi behind it).
- `?$orderby=<col>` reflected into `ORDER BY` → a boolean-blind SQLi oracle (common where a search/keyword parameter is concatenated into the ordering clause).
- Function calls (`substringof`, `cast`) that error verbosely → provider + backend fingerprint.

## Verify & score

- A cross-tenant `$filter` returning another tenant's real rows is a **High** BOLA (customer-plane isolation break) — capture the request + the foreign-tenant row as evidence.
- A blind `$orderby` oracle is real but score at the demonstrated inference (per `severity-calibration.md` enabler-vs-demonstrated).
- Confirm on the LOWEST-privilege token; run the full entity-set matrix so a clean result is an *evidenced* negative, not an untested gap.

## Tie-in

Drive the per-role matrix + operator battery with the reusable `tools/auth_replay_harness.py` (per-role/cross-tenant token store + mutate/read battery). Pair with [`owasp-bola-bopla.md`](owasp-bola-bopla.md) for the object-level authz mindset and [`sql-injection-advanced.md`](../../../../injection/reference/sql-injection-advanced.md) when `$filter`/`$orderby` reflect into SQL.
