# Error Messages — Forced Disclosure

## When this applies

- Application returns verbose stack traces, framework error pages, or SQL error messages on invalid input.
- Custom error pages aren't configured; debug mode is enabled.
- Type-confusion / boundary-value inputs trigger uncaught exceptions.

## Technique

Force the server into an exception path. Stack traces, framework names/versions, internal paths, IPs, developer names, and DB info all leak from default error handlers.

## Steps

```
□ Trigger type errors: productId="string"
□ Try boundary values: id=-1, id=999999999
□ Test special characters: id=', id=", id=%00
□ Force exceptions: divide by zero, null references
□ Test different parameters across all endpoints
□ Analyze stack traces for:
  - Framework names and versions
  - File paths and directory structure
  - Internal IP addresses
  - Developer names/emails
  - Database information
```

**Quick Exploit:**
```http
GET /product?productId="invalid" HTTP/1.1
Host: target.com
```

### Error triggering payloads

```
String instead of number: id="abc"
Negative values: id=-1
Null/undefined: id=null
Special characters: id='
Array notation: id[]
Object notation: id{}
Very large numbers: id=999999999999999
```

### Common framework indicators

From error messages:
```
Apache Struts 2 -> Java application
Laravel -> PHP application
Django -> Python application
Spring Boot -> Java application
Express.js -> Node.js application
Ruby on Rails -> Ruby application
ASP.NET -> Microsoft stack
```

From headers:
```
X-Powered-By: Express -> Node.js/Express
X-Powered-By: PHP/7.x -> PHP
Server: Apache Tomcat -> Java
X-AspNet-Version -> ASP.NET
X-Rails-* -> Ruby on Rails
```

### Information to extract

- Framework name and version
- Programming language
- File paths and directory structure
- Database type and version
- Server operating system
- Internal IP addresses
- Developer usernames/emails

### Response analysis

```
200 - Information disclosed
401/403 - Access control implemented (test bypasses)
404 - Not found (but check response body)
405 - Method not allowed (try other methods)
500 - Server error (good for information leakage)
```

## Verifying success

- Stack trace contains framework version, file paths, and internal hostnames.
- 500 responses return more useful body than the rendered error page.
- Different parameter values trigger different code paths (timing or content variance) — useful for user enumeration.

## Common pitfalls

- Production sites often have generic error pages — try less common parameters and method changes (TRACE, OPTIONS).
- Some frameworks (Spring) gate stack traces behind a profile (`actuator/trace`) — discoverable separately.
- Custom error handlers may swallow the original exception but log it — check for log endpoints.

## Tools

- Burp Suite Repeater
- Burp Param Miner (hidden parameters)
- Backslash Powered Scanner
- Burp Error Message Checks extension
