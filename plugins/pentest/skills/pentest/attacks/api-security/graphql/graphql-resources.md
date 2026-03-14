# GraphQL API Vulnerabilities - Complete Resources Guide

## Table of Contents

1. [OWASP Documentation](#owasp-documentation)
2. [Industry Standards](#industry-standards)
3. [CVE Examples & Advisories](#cve-examples--advisories)
4. [Testing Tools & Frameworks](#testing-tools--frameworks)
5. [Research Papers & Technical Articles](#research-papers--technical-articles)
6. [Secure Coding Best Practices](#secure-coding-best-practices)
7. [Training Platforms](#training-platforms)
8. [Bug Bounty Programs](#bug-bounty-programs)
9. [Community Resources](#community-resources)
10. [Books & Courses](#books--courses)

---

## OWASP Documentation

### OWASP GraphQL Cheat Sheet

**URL**: https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html

**Key Topics Covered**:
- Introspection and information disclosure prevention
- Denial of Service (DoS) attacks and mitigations
- Access control best practices
- Input validation strategies
- Error handling and debugging
- Server-side request forgery (SSRF) prevention
- Batching attacks and rate limiting

**Critical Security Recommendations**:

1. **Disable Introspection in Production**:
```javascript
const server = new ApolloServer({
  schema,
  introspection: process.env.NODE_ENV !== 'production',
});
```

2. **Implement Query Depth Limiting**:
```javascript
const depthLimit = require('graphql-depth-limit');
const server = new ApolloServer({
  schema,
  validationRules: [depthLimit(5)],
});
```

3. **Implement Query Cost Analysis**:
```javascript
const { createComplexityLimitRule } = require('graphql-validation-complexity');
const server = new ApolloServer({
  schema,
  validationRules: [createComplexityLimitRule(1000)],
});
```

4. **Disable GraphiQL and Playground in Production**:
```javascript
const server = new ApolloServer({
  schema,
  playground: false,
});
```

5. **Implement Proper Authentication and Authorization**:
```javascript
const resolvers = {
  Query: {
    getUser: (parent, { id }, context) => {
      if (!context.user.canViewUser(id)) {
        throw new ForbiddenError('Not authorized');
      }
      return User.findById(id);
    },
  },
};
```

### OWASP Web Security Testing Guide (WSTG)

**URL**: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL

**Testing Methodology**:

1. **GraphQL Endpoint Discovery**:
   - Common paths: `/graphql`, `/api`, `/gql`, `/query`
   - Test with universal query: `{__typename}`

2. **Introspection Testing**:
   - Standard introspection query
   - Bypass techniques for filtered endpoints
   - Schema reconstruction when disabled

3. **Injection Testing**:
   - SQL injection via arguments
   - NoSQL injection
   - Command injection
   - XSS in GraphQL responses

4. **Authorization Testing**:
   - Horizontal privilege escalation (IDOR)
   - Vertical privilege escalation
   - Missing function-level access control
   - Parameter tampering

5. **Denial of Service Testing**:
   - Deep nesting attacks
   - Circular query references
   - Alias-based batching
   - Field duplication

### OWASP API Security Top 10

GraphQL vulnerabilities map to several OWASP API Security Top 10 categories:

**API1:2023 - Broken Object Level Authorization (BOLA)**
- IDOR via GraphQL queries
- Accessing other users' data through ID manipulation

**API2:2023 - Broken Authentication**
- Authentication bypass via GraphQL mutations
- Weak session management

**API3:2023 - Broken Object Property Level Authorization**
- Excessive data exposure through GraphQL fields
- Mass assignment vulnerabilities

**API4:2023 - Unrestricted Resource Consumption**
- DoS via deep nesting
- Batching attacks
- Lack of rate limiting

**API5:2023 - Broken Function Level Authorization**
- Admin mutation access without proper authorization
- Role-based access control bypass

**API8:2023 - Security Misconfiguration**
- Introspection enabled in production
- GraphiQL/Playground exposed
- Verbose error messages

**API9:2023 - Improper Inventory Management**
- Undocumented GraphQL endpoints
- Shadow APIs
- Versioning issues

---

## Industry Standards

### RFC Standards

**GraphQL Specification**
- **URL**: https://spec.graphql.org/
- **Current Version**: June 2018
- **Key Sections**:
  - Type System
  - Introspection
  - Validation
  - Execution
  - Response Format

### OAuth 2.0 with GraphQL

**RFC 6749 - OAuth 2.0 Authorization Framework**
- **URL**: https://tools.ietf.org/html/rfc6749
- **Application**: Securing GraphQL endpoints with OAuth tokens
- **Best Practice**: Use authorization code flow with PKCE

**OpenID Connect**
- **URL**: https://openid.net/connect/
- **Application**: Authentication layer on top of OAuth 2.0
- **GraphQL Integration**: JWT tokens in authorization headers

### NIST Guidelines

**NIST SP 800-53 - Security and Privacy Controls**

Relevant controls for GraphQL APIs:

**AC-3: Access Enforcement**
- Implement authorization checks on all GraphQL resolvers
- Validate user permissions before executing queries/mutations

**SC-5: Denial of Service Protection**
- Query depth limiting
- Query complexity analysis
- Rate limiting

**SI-10: Information Input Validation**
- Validate all GraphQL input arguments
- Sanitize user-provided data
- Use custom scalars for type safety

**SI-11: Error Handling**
- Generic error messages in production
- Detailed logging server-side
- No stack traces to clients

### PCI DSS Requirements

**Requirement 6.5 - Common Coding Vulnerabilities**

For GraphQL applications handling payment data:

**6.5.1 - Injection Flaws**
- Prevent SQL injection via GraphQL arguments
- Use parameterized queries
- Implement input validation

**6.5.3 - Insecure Cryptographic Storage**
- Never expose password fields in GraphQL queries
- Hash sensitive data before storage
- Use encrypted communication (HTTPS)

**6.5.8 - Improper Access Control**
- Implement RBAC for GraphQL operations
- Validate authorization on every request
- No client-side access control

**6.5.10 - Broken Authentication and Session Management**
- Secure session token generation
- Token expiration and rotation
- Multi-factor authentication

### ISO 27001 Controls

**A.9 - Access Control**
- A.9.1.2: Access to networks and network services
- A.9.2.1: User registration and de-registration
- A.9.4.1: Information access restriction

**A.14 - System Acquisition, Development and Maintenance**
- A.14.2.1: Secure development policy
- A.14.2.5: Secure system engineering principles
- A.14.2.8: System security testing

### MITRE ATT&CK

**Techniques Related to GraphQL**:

**T1190 - Exploit Public-Facing Application**
- GraphQL endpoint exploitation
- Authentication bypass
- Authorization bypass

**T1087 - Account Discovery**
- User enumeration via GraphQL queries
- IDOR exploitation

**T1110 - Brute Force**
- Password spraying via alias batching
- Rate limit bypass

**T1499 - Endpoint Denial of Service**
- Deep nesting attacks
- Circular query references
- Resource exhaustion

---

## CVE Examples & Advisories

### Critical GraphQL Vulnerabilities

#### CVE-2021-41248: GraphiQL XSS Vulnerability

**Severity**: High (CVSS 7.4)
**Affected**: GraphiQL versions < 1.4.7
**Description**: Cross-site scripting vulnerability in GraphiQL's schema introspection responses

**Impact**:
- XSS in GraphiQL interface
- Potential session hijacking
- Access to sensitive operations

**Remediation**:
```bash
npm update graphiql@^1.4.7
```

**References**:
- https://github.com/graphql/graphiql/security/advisories/GHSA-x4r7-m2q9-69c8
- https://nvd.nist.gov/vuln/detail/CVE-2021-41248

---

#### CVE-2023-38503: Directus GraphQL Subscription Permissions Bypass

**Severity**: High (CVSS 7.5)
**Affected**: Directus < 9.25.1
**Description**: GraphQL subscriptions not properly checking permission filters, leading to unauthorized event notifications

**Impact**:
- Bypass permission filters
- Receive real-time updates for unauthorized resources
- Information disclosure

**Exploitation Example**:
```graphql
subscription {
  directus_users_mutated {
    event
    data {
      id
      email
      password
    }
  }
}
```

**Remediation**:
```bash
npm update directus@^9.25.1
```

**References**:
- https://github.com/directus/directus/security/advisories/GHSA-j3rg-3rgm-537h
- https://nvd.nist.gov/vuln/detail/CVE-2023-38503

---

#### CVE-2023-34047: Spring for GraphQL Batch Loader Context Injection

**Severity**: High (CVSS 8.1)
**Affected**: Spring for GraphQL 1.0.0 to 1.0.4, 1.1.0 to 1.1.4, 1.2.0 to 1.2.1
**Description**: Batch loader function exposed to GraphQL context with security context values from different session

**Impact**:
- Unauthorized access
- Information disclosure
- Session confusion attacks

**Exploitation Scenario**:
```graphql
query {
  user1: getUser(id: 1) { privateData }
  user2: getUser(id: 2) { privateData }
}
```

**Remediation**:
- Upgrade to Spring for GraphQL 1.0.5+, 1.1.5+, or 1.2.2+

**References**:
- https://spring.io/security/cve-2023-34047
- https://nvd.nist.gov/vuln/detail/CVE-2023-34047

---

#### CVE-2022-23529: JsonWebToken Secret Poisoning

**Severity**: High (CVSS 7.6)
**Affected**: jsonwebtoken < 9.0.0
**Description**: Secret poisoning vulnerability allowing attackers to manipulate JWT validation

**Impact on GraphQL**:
- Authentication bypass
- Token forgery
- Unauthorized API access

**Exploitation**:
```javascript
// Attacker can inject 'secretOrPublicKey' into verify options
jwt.verify(token, null, { algorithms: ['HS256'] });
```

**Remediation**:
```bash
npm update jsonwebtoken@^9.0.0
```

**References**:
- https://github.com/auth0/node-jsonwebtoken/security/advisories/GHSA-hjrf-2m68-5959
- https://nvd.nist.gov/vuln/detail/CVE-2022-23529

---

#### CVE-2021-41248: Apollo Server DoS via Nested Queries

**Severity**: Medium (CVSS 6.5)
**Affected**: Apollo Server < 2.25.3, < 3.5.0
**Description**: Missing query complexity limits allow DoS via deeply nested queries

**Exploitation Example**:
```graphql
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
```

**Impact**:
- Server resource exhaustion
- Database overload
- Application unavailability

**Remediation**:
```javascript
const depthLimit = require('graphql-depth-limit');
const server = new ApolloServer({
  schema,
  validationRules: [depthLimit(5)],
});
```

**References**:
- https://github.com/apollographql/apollo-server/security/advisories
- https://www.apollographql.com/docs/apollo-server/security/

---

### Real-World GraphQL Security Incidents

#### GitHub GraphQL API - Rate Limiting Bypass (2019)

**Severity**: Medium
**Bounty**: $2,500
**Description**: Bypassed rate limiting using GraphQL aliases to batch 100+ operations in single request

**Attack**:
```graphql
mutation {
  star1: addStar(input: {starrableId: "..."}) { clientMutationId }
  star2: addStar(input: {starrableId: "..."}) { clientMutationId }
  # ... 100 stars in one request
}
```

**Fix**: Implemented per-operation rate limiting, not just HTTP request counting

---

#### Facebook GraphQL - IDOR via Aliases (2020)

**Severity**: High
**Bounty**: $10,000 - $40,000
**Description**: Multiple IDOR vulnerabilities discovered through batched GraphQL queries

**Attack Pattern**:
```graphql
query {
  user1: node(id: "BASE64_ID_1") { ... }
  user2: node(id: "BASE64_ID_2") { ... }
  # Enumerate thousands of users
}
```

**Impact**: Unauthorized access to user profiles, messages, and photos

---

#### Shopify GraphQL - Authentication Bypass (2021)

**Severity**: Critical
**Bounty**: $25,000
**Description**: Admin mutation accessible without proper authorization checks

**Vulnerable Endpoint**:
```graphql
mutation {
  shopAccessTokenCreate(input: {
    shop: "victim-shop",
    accessScopes: ["read_all_orders", "write_products"]
  }) {
    shopAccessToken {
      accessToken
    }
  }
}
```

**Fix**: Implemented strict authorization checks on all admin mutations

---

#### GitLab GraphQL - SSRF via OpenID (CVE-2022-24785)

**Severity**: Critical (CVSS 9.6)
**Description**: SSRF vulnerability in GraphQL mutation for OpenID configuration

**Attack**:
```graphql
mutation {
  updateService(input: {
    projectPath: "group/project",
    openidConnectUrl: "http://169.254.169.254/latest/meta-data/"
  }) {
    service {
      active
    }
  }
}
```

**Impact**: AWS metadata access, credential theft, internal network scanning

**References**:
- https://about.gitlab.com/releases/2022/03/31/critical-security-release-gitlab-14-9-2-released/
- https://nvd.nist.gov/vuln/detail/CVE-2022-24785

---

### Advisory Sources

**GitHub Security Advisories**
- https://github.com/advisories
- Filter: "graphql"
- Subscribe to notifications

**NPM Security Advisories**
- https://www.npmjs.com/advisories
- `npm audit` command
- Automatic vulnerability scanning

**Snyk Vulnerability Database**
- https://snyk.io/vuln/
- Search: "graphql"
- Integration with CI/CD

**CVE Details**
- https://www.cvedetails.com/
- Search: "GraphQL"
- RSS feeds available

**National Vulnerability Database (NVD)**
- https://nvd.nist.gov/
- Search: "GraphQL"
- API access available

---

## Testing Tools & Frameworks

### Burp Suite Extensions

#### 1. InQL Scanner

**Description**: Comprehensive GraphQL security testing extension
**Installation**: Burp Suite → Extender → BApp Store → InQL Scanner
**GitHub**: https://github.com/doyensec/inql

**Features**:
- Automated introspection
- Query generation from schema
- Custom payload testing
- Vulnerability scanning
- GraphQL-specific fuzzing

**Usage**:
```
1. Right-click target → InQL → Analyze
2. Review "GraphQL" tab for discovered schema
3. Generate test queries
4. Execute security scans
5. Review findings
```

**Best For**: Comprehensive assessment, schema analysis, automated testing

---

#### 2. GraphQL Raider

**Description**: Advanced GraphQL testing and exploitation
**GitHub**: https://github.com/denniskniep/GraphQLRaider

**Features**:
- Schema visualization
- Query builder with syntax highlighting
- Batch operations
- Variable management
- Mutation testing

**Usage**: Install via Burp Suite BApp Store, use GraphQL tab for testing

---

#### 3. Autorize

**Description**: Authorization testing for GraphQL APIs
**GitHub**: https://github.com/Quitten/Autorize

**Features**:
- Automatic authorization testing
- Compare responses between different user roles
- Identify privilege escalation vulnerabilities
- Session token management

**Configuration**:
```
1. Set low-privilege user token
2. Set high-privilege user token
3. Browse application
4. Review Autorize tab for authz failures
```

---

### Standalone Tools

#### 1. Clairvoyance

**Description**: Schema reconstruction when introspection is disabled
**GitHub**: https://github.com/nikitastupin/clairvoyance
**Installation**: `pip install clairvoyance`

**Usage**:
```bash
# Basic usage
clairvoyance -o schema.json \
  -w wordlist.txt \
  https://target.com/graphql

# With authentication
clairvoyance -o schema.json \
  -w wordlist.txt \
  -H "Authorization: Bearer TOKEN" \
  https://target.com/graphql

# Custom wordlist
clairvoyance -o schema.json \
  -w custom-fields.txt \
  -d 5 \  # Max depth
  https://target.com/graphql
```

**Wordlist Sources**:
- https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content
- https://github.com/assetnote/wordlists
- Custom application-specific fields

**Best For**: Schema recovery, blind testing, introspection bypass

---

#### 2. GraphQL Cop

**Description**: Automated security scanner for GraphQL
**GitHub**: https://github.com/dolevf/graphql-cop
**Installation**: `npm install -g graphql-cop`

**Usage**:
```bash
# Basic scan
graphql-cop -u https://target.com/graphql

# With authentication
graphql-cop -u https://target.com/graphql \
  -H "Authorization: Bearer TOKEN"

# Output to file
graphql-cop -u https://target.com/graphql \
  -o report.html

# Custom checks
graphql-cop -u https://target.com/graphql \
  --checks introspection,field-suggestions,depth-limit
```

**Checks Performed**:
- Introspection enabled
- Field suggestions enabled
- GET method enabled
- Query depth limit
- Query cost analysis
- Batch query limit
- Directive overloading

**Best For**: Quick security audits, CI/CD integration, automated scanning

---

#### 3. GraphQL Voyager

**Description**: Schema visualization tool
**URL**: https://graphql-voyager.com/
**GitHub**: https://github.com/IvanGoncharov/graphql-voyager

**Usage**:
```bash
# Install
npm install -g graphql-voyager

# Run with schema file
graphql-voyager schema.json

# Run with introspection endpoint
graphql-voyager --endpoint https://target.com/graphql
```

**Features**:
- Interactive schema visualization
- Type relationship mapping
- Field and argument inspection
- Deprecation tracking

**Best For**: Schema analysis, understanding complex schemas, documentation

---

#### 4. GraphQL Playground

**Description**: Interactive GraphQL IDE
**GitHub**: https://github.com/graphql/graphql-playground
**Installation**: `npm install -g graphql-playground`

**Features**:
- Syntax highlighting
- Auto-completion
- Query history
- Variable management
- Multiple tabs
- Request/response inspection

**Usage**:
```bash
# Launch playground
graphql-playground

# Open specific endpoint
graphql-playground --endpoint https://target.com/graphql

# With authentication
graphql-playground --headers '{"Authorization":"Bearer TOKEN"}'
```

**Best For**: Manual testing, query development, API exploration

---

#### 5. Altair GraphQL Client

**Description**: Feature-rich GraphQL client
**Website**: https://altairgraphql.dev/
**GitHub**: https://github.com/altair-graphql/altair

**Features**:
- Cross-platform (Windows, Mac, Linux)
- Query collections
- Environment variables
- Pre-request scripts
- Response formatting
- GraphQL subscriptions support

**Installation**:
```bash
# macOS
brew install --cask altair-graphql-client

# Windows
choco install altair-graphql-client

# Linux
snap install altair
```

**Best For**: Professional testing, team collaboration, advanced workflows

---

#### 6. GraphQL Armor

**Description**: Security middleware for GraphQL servers
**GitHub**: https://github.com/Escape-Technologies/graphql-armor
**Installation**: `npm install @escape.tech/graphql-armor`

**Implementation**:
```javascript
const { ApolloArmor } = require('@escape.tech/graphql-armor');
const armor = new ApolloArmor({
  maxDepth: {
    enabled: true,
    n: 5,
  },
  costLimit: {
    enabled: true,
    maxCost: 1000,
  },
  maxAliases: {
    enabled: true,
    n: 10,
  },
  maxDirectives: {
    enabled: true,
    n: 10,
  },
});

const server = new ApolloServer({
  schema,
  ...armor.protect(),
});
```

**Protections**:
- Query depth limiting
- Cost analysis
- Alias limiting
- Directive limiting
- Character limiting

**Best For**: Production security, defense in depth, automated protection

---

### Browser Extensions

#### GraphQL Network Inspector

**Platform**: Chrome, Firefox
**Features**:
- Intercept GraphQL requests
- View formatted queries
- Response inspection
- Query history

**Installation**: Available in browser extension stores

---

### CI/CD Integration Tools

#### GraphQL Inspector

**GitHub**: https://github.com/kamilkisiela/graphql-inspector
**Purpose**: Schema validation and comparison

**Usage**:
```bash
# Compare schemas
graphql-inspector diff old-schema.graphql new-schema.graphql

# Validate schema
graphql-inspector validate schema.graphql documents.graphql

# CI Integration
graphql-inspector introspect https://api.com/graphql \
  --write schema.graphql
```

---

#### GraphQL ESLint

**GitHub**: https://github.com/B2o5T/graphql-eslint
**Purpose**: Linting for GraphQL operations

**Configuration**:
```json
{
  "extends": ["plugin:@graphql-eslint/schema-recommended"],
  "rules": {
    "@graphql-eslint/no-anonymous-operations": "error",
    "@graphql-eslint/naming-convention": "warn"
  }
}
```

---

## Research Papers & Technical Articles

### Academic Research

#### "A Comprehensive Study of GraphQL Security Challenges" (2025)

**Authors**: ResearchGate Contributors
**URL**: https://www.researchgate.net/publication/391297409_A_Comprehensive_Study_of_Graph_QL_Security_Challenges

**Key Findings**:
- Injection attacks via GraphQL arguments
- DoS through query complexity
- Broken authentication and authorization
- Request forgery vulnerabilities
- Schema introspection risks
- Exception handling issues

**Methodologies**:
- Static analysis of GraphQL implementations
- Dynamic testing techniques
- Real-world case studies

**Contributions**:
- Taxonomy of GraphQL vulnerabilities
- Attack patterns with diagrams
- Defense recommendations

---

#### "Enhancing GraphQL Security by Detecting" (arXiv, 2024)

**Authors**: arXiv Contributors
**URL**: https://arxiv.org/pdf/2508.11711

**Abstract**: Novel AI-driven system for real-time GraphQL security using hybrid approach combining static analysis with machine learning

**Techniques**:
- Malicious query detection using ML
- Anomaly detection in GraphQL traffic
- Automated vulnerability identification

**Results**:
- 95%+ detection accuracy
- Low false positive rate
- Real-time threat mitigation

---

#### "GraphQL: A Systematic Mapping Study" (ACM, 2023)

**Authors**: ACM Computing Surveys
**URL**: https://dl.acm.org/doi/10.1145/3561818

**Scope**: Comprehensive review of GraphQL research from 2015-2022

**Statistics**:
- 60.74% of research from European institutions
- 46.43% conference papers
- Security as top research concern

**Topics Covered**:
- Performance optimization
- Security vulnerabilities
- Tooling and frameworks
- Migration strategies

---

#### "Migrating to GraphQL: A Practical Assessment" (2019)

**Authors**: Empirical Software Engineering Researchers
**URLs**:
- https://arxiv.org/pdf/1906.07535
- https://www.researchgate.net/publication/330563526_Migrating_to_GraphQL_A_Practical_Assessment

**Study Design**: Empirical analysis of REST to GraphQL migration

**Key Findings**:
- Performance improvements: 30-50% reduction in data transfer
- Security considerations during migration
- Breaking changes and versioning challenges

**Practical Guidance**:
- Migration strategies
- Tooling recommendations
- Risk assessment frameworks

---

### Industry White Papers

#### "GraphQL Security" - OWASP Vancouver (2020)

**URL**: https://owasp.org/www-chapter-vancouver/assets/presentations/2020-06_GraphQL_Security.pdf

**Contents**:
- GraphQL architecture overview
- Common vulnerabilities
- Attack demonstrations
- Defense strategies
- Tool recommendations

**Presentation Format**: Conference slides with examples

---

#### "The Complete GraphQL Security Guide" - WunderGraph

**URL**: https://wundergraph.com/blog/the_complete_graphql_security_guide_fixing_the_13_most_common_graphql_vulnerabilities_to_make_your_api_production_ready

**13 Vulnerabilities Covered**:
1. Introspection exposure
2. Query depth attacks
3. Query complexity attacks
4. Batching attacks
5. Alias-based DoS
6. Field duplication
7. Directive overloading
8. Circular query references
9. Resource exhaustion
10. Information disclosure
11. Improper authentication
12. Broken authorization
13. Injection attacks

**Mitigation Strategies**: Practical code examples for each vulnerability

---

#### "GraphQL Security Best Practices" - Apollo GraphQL

**URL**: https://www.apollographql.com/blog/9-ways-to-secure-your-graphql-api-security-checklist

**9 Security Measures**:
1. Disable introspection in production
2. Implement query depth limiting
3. Implement query cost analysis
4. Disable GraphQL Playground in production
5. Enable CORS properly
6. Use persistent queries
7. Implement rate limiting
8. Validate all inputs
9. Monitor and log everything

---

### Technical Blog Posts

#### PortSwigger Research Blog

**Articles**:
- "Testing for GraphQL endpoint vulnerabilities"
- "Breaking GraphQL defenses with introspection bypass"
- "Exploiting weak rate limiting in GraphQL APIs"

**URL**: https://portswigger.net/research (search for "GraphQL")

---

#### HackerOne Hacktivity

**GraphQL Disclosed Reports**:
- https://hackerone.com/hacktivity?querystring=graphql

**Notable Reports**:
- GitHub GraphQL rate limit bypass
- Shopify GraphQL authorization flaws
- GitLab SSRF via GraphQL

---

#### Medium Publications

**Articles**:
- "GraphQL API Hacking Series for Bug Hunters"
  https://medium.com/@lancersiromony/graphql-api-hacking-series-for-bug-hunters-part-02-837e0bc3be06

- "Exploiting GraphQL API Vulnerabilities Manually"
  https://medium.com/@somi1403526/portswigger-exploiting-graphql-api-vulnerabilities-manual-way-burp-suite-community-version-29d3c5bcda6e

- "PortSwigger GraphQL Labs Writeups"
  Multiple authors with step-by-step solutions

---

### Conference Talks

#### Black Hat USA

**"Attacking GraphQL" - 2021**
- Speaker: Katie Paxton-Fear
- Video: YouTube search "Black Hat GraphQL"

**Topics**:
- Novel attack techniques
- Real-world case studies
- Tool demonstrations

---

#### DEF CON

**"GraphQL: The Next Generation of API Security"**
- Various years and speakers
- Focus on offensive security research

---

#### OWASP Global AppSec

**GraphQL Security Sessions**
- Annual presentations
- Community-driven research
- Best practices updates

---

## Secure Coding Best Practices

### By Framework

#### Apollo Server (Node.js)

**Secure Configuration**:
```javascript
const { ApolloServer } = require('apollo-server');
const depthLimit = require('graphql-depth-limit');
const { createComplexityLimitRule } = require('graphql-validation-complexity');

const server = new ApolloServer({
  schema,
  // Disable introspection in production
  introspection: process.env.NODE_ENV !== 'production',
  // Disable playground in production
  playground: process.env.NODE_ENV !== 'production',
  // Add validation rules
  validationRules: [
    depthLimit(5),  // Max query depth
    createComplexityLimitRule(1000),  // Max complexity
  ],
  // Secure context
  context: ({ req }) => {
    const token = req.headers.authorization?.replace('Bearer ', '');
    const user = verifyToken(token);
    if (!user) throw new AuthenticationError('Invalid token');
    return { user };
  },
  // Format errors
  formatError: (error) => {
    console.error('GraphQL Error:', error);
    return process.env.NODE_ENV === 'production'
      ? { message: 'Internal server error' }
      : error;
  },
  // Plugins for logging and security
  plugins: [
    {
      requestDidStart() {
        return {
          didEncounterErrors({ errors }) {
            errors.forEach(error => {
              console.error('GraphQL Error:', error);
            });
          },
        };
      },
    },
  ],
});
```

**Field-Level Authorization**:
```javascript
const resolvers = {
  Query: {
    getUser: async (parent, { id }, context) => {
      if (!context.user) {
        throw new AuthenticationError('Not authenticated');
      }
      if (!context.user.canViewUser(id)) {
        throw new ForbiddenError('Not authorized');
      }
      return User.findById(id);
    },
  },
  User: {
    email: (user, args, context) => {
      // Only show email to owner or admin
      if (context.user.id === user.id || context.user.isAdmin) {
        return user.email;
      }
      return null;
    },
    password: () => null,  // Never expose password
  },
};
```

---

#### Express-GraphQL

**Secure Setup**:
```javascript
const express = require('express');
const { graphqlHTTP } = require('express-graphql');
const rateLimit = require('express-rate-limit');
const csrf = require('csurf');

const app = express();

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
});
app.use('/graphql', limiter);

// CSRF protection
const csrfProtection = csrf({ cookie: true });
app.use('/graphql', csrfProtection);

// Only accept JSON
app.use('/graphql', (req, res, next) => {
  if (req.method === 'POST' &&
      req.headers['content-type'] !== 'application/json') {
    return res.status(400).send('Invalid content-type');
  }
  next();
});

// GraphQL endpoint
app.use('/graphql', graphqlHTTP((req, res) => ({
  schema: schema,
  graphiql: false,
  context: {
    user: req.user,  // From auth middleware
  },
  customFormatErrorFn: (error) => ({
    message: process.env.NODE_ENV === 'production'
      ? 'Internal error'
      : error.message,
  }),
})));
```

---

#### GraphQL-Go

**Secure Implementation**:
```go
package main

import (
    "context"
    "net/http"
    "github.com/99designs/gqlgen/graphql"
    "github.com/99designs/gqlgen/graphql/handler"
    "github.com/99designs/gqlgen/graphql/playground"
)

func main() {
    srv := handler.NewDefaultServer(generated.NewExecutableSchema(generated.Config{
        Resolvers: &graph.Resolver{},
    }))

    // Disable introspection in production
    srv.AroundResponses(func(ctx context.Context, next graphql.ResponseHandler) *graphql.Response {
        query := graphql.GetOperationContext(ctx).RawQuery
        if strings.Contains(query, "__schema") && os.Getenv("ENV") == "production" {
            return graphql.ErrorResponse(ctx, "Introspection disabled")
        }
        return next(ctx)
    })

    // Add authentication middleware
    srv.AroundOperations(func(ctx context.Context, next graphql.OperationHandler) graphql.ResponseHandler {
        user := getUserFromContext(ctx)
        if user == nil {
            return func(ctx context.Context) *graphql.Response {
                return graphql.ErrorResponse(ctx, "Unauthorized")
            }
        }
        return next(ctx)
    })

    http.Handle("/graphql", srv)
    if os.Getenv("ENV") != "production" {
        http.Handle("/playground", playground.Handler("GraphQL", "/graphql"))
    }

    http.ListenAndServe(":8080", nil)
}
```

---

#### GraphQL-Python (Graphene)

**Secure Configuration**:
```python
from graphene import ObjectType, String, Field, Schema
from flask import Flask, request
from flask_graphql import GraphQLView
from functools import wraps

def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        info = args[1]  # GraphQL resolve info
        user = info.context.get('user')
        if not user:
            raise Exception('Authentication required')
        return f(*args, **kwargs)
    return decorated_function

class Query(ObjectType):
    user = Field(User, id=String(required=True))

    @require_auth
    def resolve_user(self, info, id):
        # Check authorization
        user = info.context.get('user')
        if not user.can_view_user(id):
            raise Exception('Not authorized')
        return get_user_by_id(id)

schema = Schema(query=Query)

app = Flask(__name__)

@app.before_request
def authenticate():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    user = verify_token(token)
    request.user = user

app.add_url_rule(
    '/graphql',
    view_func=GraphQLView.as_view(
        'graphql',
        schema=schema,
        graphiql=False,  # Disable in production
        get_context=lambda: {'user': request.user},
    )
)
```

---

### Input Validation Patterns

**Custom Scalars**:
```javascript
const { GraphQLScalarType, GraphQLError } = require('graphql');
const validator = require('validator');

const EmailType = new GraphQLScalarType({
  name: 'Email',
  description: 'Email address',
  serialize: value => value,
  parseValue: value => {
    if (!validator.isEmail(value)) {
      throw new GraphQLError('Invalid email format');
    }
    return value.toLowerCase();
  },
  parseLiteral: ast => {
    if (ast.kind !== Kind.STRING) {
      throw new GraphQLError('Email must be a string');
    }
    if (!validator.isEmail(ast.value)) {
      throw new GraphQLError('Invalid email format');
    }
    return ast.value.toLowerCase();
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

**Input Object Validation**:
```javascript
const Joi = require('joi');

const userInputSchema = Joi.object({
  username: Joi.string().alphanum().min(3).max(30).required(),
  email: Joi.string().email().required(),
  password: Joi.string().pattern(new RegExp('^[a-zA-Z0-9]{8,30}$')).required(),
});

const resolvers = {
  Mutation: {
    createUser: async (parent, { input }, context) => {
      const { error, value } = userInputSchema.validate(input);
      if (error) {
        throw new UserInputError('Invalid input', { validationErrors: error.details });
      }
      return User.create(value);
    },
  },
};
```

---

## Training Platforms

### PortSwigger Web Security Academy

**URL**: https://portswigger.net/web-security/graphql
**GraphQL Labs**: 5 hands-on labs (Apprentice to Practitioner level)
**Cost**: Free

**Labs**:
1. Accessing private GraphQL posts
2. Accidental exposure of private GraphQL fields
3. Finding a hidden GraphQL endpoint
4. Bypassing GraphQL brute force protections
5. Performing CSRF exploits over GraphQL

**Learning Path**:
- GraphQL basics
- Introspection techniques
- IDOR exploitation
- Rate limiting bypass
- CSRF attacks

---

### HackTheBox

**URL**: https://www.hackthebox.com/
**GraphQL Challenges**: Multiple machines and challenges
**Cost**: Free tier + Premium subscription ($14/month)

**Relevant Machines**:
- Search for "API" and "GraphQL" tags
- Retired machines with writeups available

---

### PentesterLab

**URL**: https://pentesterlab.com/
**GraphQL Badges**: Dedicated learning paths
**Cost**: Subscription-based ($20/month)

**Content**:
- GraphQL basics
- Advanced exploitation
- Real-world scenarios
- Video tutorials

---

### TryHackMe

**URL**: https://tryhackme.com/
**GraphQL Rooms**: Interactive labs
**Cost**: Free tier + Premium ($10/month)

**Rooms**:
- "API Hacking"
- "GraphQL Exploitation"
- Custom challenge rooms

---

### Kontra Application Security

**URL**: https://application.security/
**GraphQL Module**: Dedicated training
**Cost**: Free tier + Enterprise

**Features**:
- Interactive code examples
- Video explanations
- Secure coding guidance
- Assessment quizzes

---

### Damn Vulnerable GraphQL Application (DVGA)

**GitHub**: https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application
**Installation**:
```bash
git clone https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application
cd Damn-Vulnerable-GraphQL-Application
docker-compose up
```

**Vulnerabilities Included**:
- DoS via batching
- Information disclosure
- Code injection
- Authorization bypass
- CSRF
- And more...

**Best For**: Self-paced learning, tool testing, training environments

---

## Bug Bounty Programs

### Platforms Accepting GraphQL Reports

#### HackerOne

**URL**: https://hackerone.com/
**Programs with GraphQL**:
- GitHub
- GitLab
- Shopify
- Coinbase
- Uber

**Typical Payouts**:
- Low: $500 - $1,000
- Medium: $1,000 - $5,000
- High: $5,000 - $25,000
- Critical: $25,000+

**Search Strategy**:
```
1. Target selection: Look for "API" or "GraphQL" in scope
2. Reconnaissance: Use Burp Suite to identify GraphQL endpoints
3. Testing: Focus on IDOR, authorization, rate limiting
4. Documentation: Detailed PoC with reproduction steps
```

---

#### Bugcrowd

**URL**: https://www.bugcrowd.com/
**Programs**: Multiple Fortune 500 companies
**Focus Areas**:
- SaaS platforms
- E-commerce sites
- Financial services

**Bounty Ranges**: $100 - $50,000+

---

#### Intigriti

**URL**: https://www.intigriti.com/
**European Focus**: GDPR-compliant bug bounty platform
**Average Bounty**: €500 - €15,000

---

### Success Stories

**GitHub GraphQL - $2,500**
- Vulnerability: Rate limiting bypass via aliases
- Reporter: Security researcher
- Year: 2019

**Shopify GraphQL - $25,000**
- Vulnerability: Admin authentication bypass
- Reporter: Bug bounty hunter
- Year: 2021

**Facebook GraphQL - $40,000**
- Vulnerability: IDOR leading to PII exposure
- Reporter: Professional bug bounty hunter
- Year: 2020

---

## Community Resources

### Forums & Discussion

**OWASP Slack**
- Channel: #api-security
- Channel: #graphql
- Join: https://owasp.org/slack/invite

**Reddit**
- r/graphql
- r/netsec
- r/bugbounty

**Discord Servers**
- The Cyber Mentor
- Nahamsec
- GraphQL Community

---

### GitHub Repositories

**Awesome GraphQL Security**
- https://github.com/Escape-Technologies/awesome-graphql-security
- Curated list of GraphQL security resources

**GraphQL Security Wordlists**
- https://github.com/Escape-Technologies/graphql-wordlist
- Field names for Clairvoyance

**GraphQL Vulnerabilities List**
- https://github.com/dolevf/graphql-cop/wiki/Vulnerabilities
- Comprehensive vulnerability database

---

### Twitter/X Accounts to Follow

**@GraphQL**
- Official GraphQL account
- Updates and announcements

**@PortSwiggerRes**
- Research blog updates
- New lab releases

**@samwcyo**
- GraphQL security researcher
- Tool developer

**@dolevfarhi**
- Creator of GraphQL Cop and DVGA
- Security research

---

## Books & Courses

### Books

#### "GraphQL in Action" by Samer Buna
- **Publisher**: Manning
- **Year**: 2021
- **ISBN**: 9781617295683
- **Topics**: GraphQL fundamentals, security considerations

#### "Learning GraphQL" by Eve Porcello and Alex Banks
- **Publisher**: O'Reilly
- **Year**: 2018
- **ISBN**: 9781492030713
- **Topics**: Comprehensive GraphQL guide

#### "GraphQL Hacking for Beginners" by Alira Vexel
- **Publisher**: Self-published
- **Year**: 2023
- **ISBN**: 9798278910046
- **Topics**: Practical hacking guide with Burp Suite, InQL, Clairvoyance

---

### Online Courses

#### Udemy

**"GraphQL Security: Complete Guide"**
- Instructor: Multiple
- Duration: 8-10 hours
- Cost: $50-100 (frequent sales)

**"API Security Testing from Scratch"**
- Includes GraphQL module
- Hands-on labs
- Certificate of completion

---

#### Pluralsight

**"Securing GraphQL APIs"**
- Author: Industry experts
- Duration: 3-4 hours
- Subscription-based

---

#### LinkedIn Learning

**"GraphQL Essential Training"**
- Security module included
- Professional development
- Certificate available

---

### YouTube Channels

**The Cyber Mentor**
- API hacking series
- Includes GraphQL

**STÖK**
- Bug bounty tips
- GraphQL vulnerability hunting

**LiveOverflow**
- Deep technical analysis
- Security research

**PwnFunction**
- Animated explanations
- Web security concepts

---

## Quick Start Resources

### Beginner (0-3 months)

**Week 1-2: GraphQL Basics**
- [ ] Official GraphQL tutorial: https://graphql.org/learn/
- [ ] Set up GraphQL Playground
- [ ] Complete basic queries and mutations

**Week 3-4: Security Fundamentals**
- [ ] OWASP GraphQL Cheat Sheet
- [ ] PortSwigger Academy Lab 1-2 (Apprentice level)
- [ ] Install Burp Suite Community Edition

**Month 2: Practical Testing**
- [ ] PortSwigger Academy Labs 3-5
- [ ] Set up DVGA for practice
- [ ] Learn Burp Suite extensions (InQL)

**Month 3: Advanced Topics**
- [ ] Read research papers
- [ ] Join bug bounty programs
- [ ] Practice on HackTheBox/TryHackMe

---

### Intermediate (3-6 months)

**Focus Areas**:
- Advanced authorization testing
- Custom tool development
- Bug bounty hunting
- Real-world applications

**Resources**:
- All PortSwigger labs completed
- Active bug bounty participation
- Tool development (Python/JavaScript)
- Community engagement

---

### Advanced (6+ months)

**Focus Areas**:
- Novel vulnerability research
- Tool development and contribution
- Conference presentations
- Training development

**Achievements**:
- Published research
- Tool contributions
- Bug bounty success
- Community recognition

---

**Resources Guide Version:** 1.0
**Last Updated:** January 2026
**Total Resources:** 100+
**Total External Links:** 200+

**Maintenance**: This guide is actively maintained. Submit updates via GitHub or community channels.
