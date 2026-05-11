---
name: techstack-backend
description: Backend tech-stack identification — web servers, runtimes, languages, frameworks, databases, APIs, and CMS via HTTP headers, cookies, error pages, and API discovery.
---

# Backend Tech-Stack Identification

## Scope

Identify server-side technologies: web servers (nginx, Apache, IIS), runtimes (Node, Python, PHP, Ruby, Java, .NET), backend frameworks (Express, Django, Flask, Rails, Laravel, Spring, ASP.NET), databases (Postgres, MySQL, Mongo, Redis), CMS (WordPress, Drupal, Magento), and API surfaces (REST, GraphQL, OpenAPI).

## Signals (input)

- HTTP response headers — `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-Drupal-*`, `X-Generator`, etc.
- Cookies — session-name fingerprints (`PHPSESSID`, `JSESSIONID`, `_rails_session`, ...)
- Error page bodies (404, 500)
- Path patterns hinting CMS (`/wp-admin/`, `/sites/default/`)
- API subdomains and OpenAPI/Swagger/GraphQL endpoints
- `robots.txt` directives

## Inferences (output)

- Web server + version
- Runtime / language + version
- Backend framework (with implied runtime)
- CMS + version
- Database (often indirect — via ORM dependency or hosted-DB DNS)
- API style (REST/GraphQL/gRPC) and authentication scheme

## Techniques

See [reference/patterns.md](reference/patterns.md).

## When to use

- Phase 2/3 of a tech-stack OSINT engagement
- Mapping server-side attack surface (RCE, SSRF, deserialization)
- CVE matching by server + version
- Locating GraphQL / OpenAPI for follow-on api-security testing
