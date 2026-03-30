---
name: server-side
description: Server-side vulnerability testing - SSRF, HTTP Request Smuggling, Path Traversal, File Upload, Insecure Deserialization, and Host Header injection.
---

# Server-Side

Test for server-side vulnerabilities that allow unauthorized access, RCE, or data exfiltration.

## Techniques

| Type | Key Vectors |
|------|-------------|
| **SSRF** | Internal service access, cloud metadata, protocol smuggling |
| **HTTP Smuggling** | CL.TE, TE.CL, TE.TE, CL.0, H2.CL, h2c, multi-layer proxy chains, connection pooling desync |
| **Path Traversal** | Directory traversal, null bytes, encoding bypass |
| **File Upload** | Extension bypass, content-type manipulation, polyglot files |
| **Deserialization** | Java, PHP, Python, .NET gadget chains |
| **Host Header** | Password reset poisoning, cache poisoning, routing-based SSRF |

## Workflow

1. Identify server-side processing points
2. Test for vulnerability class indicators
3. Bypass protections (WAF, allowlists, encoding filters)
4. Demonstrate impact (file read, RCE, internal access)
5. Capture evidence with PoC

## Reference

- `reference/ssrf*.md` - SSRF techniques and labs
- `reference/http-request-smuggling*.md` - Smuggling techniques
- `reference/path-traversal*.md` - Path traversal bypass methods
- `reference/file-upload*.md` - File upload exploitation
- `reference/insecure-deserialization*.md` - Deserialization attacks
- `reference/http-host-header*.md` - Host header injection
