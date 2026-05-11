# IDOR — Action / Write / Indirect

## When this applies

- Endpoint performs a state-changing action on an object referenced by ID (`/order/1001/archive`, `POST /api/transfer {"from": 123}`).
- Authorization is missing or only checks "is authenticated" (not "owns this object").
- You want to modify, archive, delete, or transfer state on resources you don't own.

## Technique

Action IDORs are often more impactful than read IDORs — they perform privileged operations on other users' objects. Test ALL endpoints that modify state, not just read endpoints. The result of the action may surface in a DIFFERENT view (your archive list, your dashboard).

**Action/Write IDOR:**
```
/order/1001/archive → /order/1099/archive            # Archive someone else's order
/order/1001/delete → /order/1099/delete               # Delete someone else's order
/user/123/update → /user/124/update                   # Modify another user's profile
POST /api/transfer {"from": 123} → {"from": 124}     # Transfer from another account
```

**Indirect IDOR (consequences visible elsewhere):**
When an action IDOR succeeds, the result may appear in a DIFFERENT view:
- Archive another user's order → it appears in YOUR archive list
- Assign a task to yourself from another project → visible in YOUR task list
- Transfer funds from another account → balance shown on YOUR dashboard

## Steps

1. Enumerate every state-changing endpoint (POST/PUT/PATCH/DELETE) that takes an object identifier.
2. Replace your own object ID with another user's ID (use IDOR-read first to discover valid IDs).
3. Send the request and check both the immediate response AND your own dashboards/archive/history pages — the consequence may appear in your view.

```bash
# Action IDOR — archive another user's order
curl -s -b "$COOKIE" -X POST "https://target.com/order/1099/archive"

# Then check YOUR archive list
curl -s -b "$COOKIE" "https://target.com/account/archive"
```

```bash
# Transfer-from IDOR
curl -s -b "$COOKIE" -X POST "https://target.com/api/transfer" \
  -H "Content-Type: application/json" \
  -d '{"from": 124, "to": 123, "amount": 100}'
```

## Verifying success

- The state change persists when you re-query the resource (object is archived/deleted/transferred).
- The result appears in a secondary view (archive list, history, dashboard) that belongs to YOU.
- No 403/401 returned despite acting on a foreign-owned object.

## Common pitfalls

- The immediate response may be empty / 204 No Content — always check the consequence in a secondary view.
- Some apps require following multi-step flows for the action — try skipping straight to the final step (see `multi-step-bypass.md`).
- Endpoints with the same name but different HTTP methods may have different authorization (GET protected, POST not — see `method-bypass.md`).

## Tools

- Burp Suite Repeater
- Burp Suite Comparer (diff archive list before/after)
- curl
- Browser DevTools (Network tab to capture state-change requests)
