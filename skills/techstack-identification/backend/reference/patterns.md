# Backend Detection Patterns

Consolidated from `backend_inferencer`, `http_fingerprinting`, `api_portal_discovery`.

## Core Probe

```bash
curl -sI -L --max-redirs 3 --connect-timeout 10 "$URL"
curl -s "$URL/<random-uuid>"   # 404 body for error-page fingerprinting
curl -s "$URL/robots.txt"
```

Headers to capture: `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-AspNetMvc-Version`, `X-Generator`, `X-Drupal-Cache`, `X-Drupal-Dynamic-Cache`, `X-Varnish`, `X-Cache`, `CF-RAY`, `X-Amz-Cf-Id`, `X-Vercel-Id`, `X-Netlify-*`, `Via`.

## Server Header

| Pattern | Tech | Version | Implies |
|---------|------|---------|---------|
| `nginx/<v>` | nginx | yes | — |
| `Apache/<v>` | Apache HTTP | yes | — |
| `Microsoft-IIS/<v>` | IIS | yes | .NET likely |
| `cloudflare` | Cloudflare proxy | no | (origin obscured) |
| `AmazonS3` | AWS S3 | no | AWS |
| `gunicorn/<v>` | Gunicorn | yes | Python |
| `Werkzeug/<v>` | Flask dev server | yes | Python |
| `Caddy`, `LiteSpeed` | Caddy / LiteSpeed | maybe | — |

## X-Powered-By / X-Generator

| Value | Tech | Implies |
|-------|------|---------|
| `Express` | Express.js | Node.js |
| `PHP/<v>` | PHP | — |
| `ASP.NET` | ASP.NET | .NET |
| `Servlet` | Java Servlet | Java |
| `Next.js` | Next.js | React, Node.js |
| `Phusion Passenger` | Passenger | Ruby |
| `WP Engine` | WP Engine | WordPress |
| `Plesk*` | Plesk panel | — |
| `X-Generator: Drupal` | Drupal | PHP |
| `X-Generator: WordPress` | WordPress | PHP |

## Cookie Name Fingerprints

| Cookie | Tech | Implies |
|--------|------|---------|
| `PHPSESSID` | PHP | — |
| `JSESSIONID` | Java Servlet | Java |
| `ASP.NET_SessionId` | ASP.NET | .NET |
| `connect.sid` | Express | Node.js |
| `_rails_session`, `rack.session` | Rails / Rack | Ruby |
| `laravel_session`, `XSRF-TOKEN` | Laravel | PHP |
| `django_session`, `csrftoken` | Django | Python |
| `cf_clearance`, `__cf_bm`, `__cfduid` | Cloudflare | — |
| `AWSALB`, `AWSALBCORS` | AWS ALB | AWS |
| `BIGipServer*` | F5 BIG-IP | — |
| `wp-settings-`, `wordpress_logged_in` | WordPress | PHP |
| `_gh_sess` | GitHub | — |

## Error Page Signatures (request `/<uuid>` and inspect body)

| Pattern | Tech |
|---------|------|
| `<center>nginx</center>` | nginx |
| `Apache/[\d.]+ \(.*\) Server at` | Apache |
| `Server Error in '/' Application` | IIS |
| `Apache Tomcat/[\d.]+` | Tomcat |
| `Cannot GET /` | Express |
| `Page not found (404)` + Django chrome | Django |
| `Action Controller: Exception` | Rails |
| `Whoops, looks like something went wrong` | Laravel |

## CMS Path Heuristics

| Path | CMS |
|------|-----|
| `/wp-content/`, `/wp-admin/`, `/wp-includes/` | WordPress |
| `/sites/default/`, `/misc/drupal.js`, `X-Drupal-Cache` | Drupal |
| `/components/`, `/modules/` + Joomla generator | Joomla |
| `/skin/frontend/`, `Mage.Cookies` | Magento |
| `myshopify.com` CNAME | Shopify |
| `Ghost <v>` generator | Ghost |
| `Contentful API` URL | Contentful |
| `/admin/strapi` | Strapi |

## Database Inference (indirect)

| Signal | DB |
|--------|----|
| `pg`, `psycopg2`, `pgbouncer` host | PostgreSQL |
| `mysql2`, `mysqlclient` | MySQL |
| `mongoose` dep, `*.mongodb.net` | MongoDB |
| `redis` dep, `*.redis.cache.windows.net` | Redis |
| `elasticsearch` dep, `:9200` | Elasticsearch |
| AWS SDK + `dynamodb.<region>.amazonaws.com` | DynamoDB |

## API Discovery

### Subdomains to probe

`api`, `developer`, `developers`, `dev`, `docs`, `documentation`, `api-docs`, `apidocs`, `api-portal`, `portal`, `integrate`, `sandbox`, `public-api`, `open`, `openapi`, `swagger`, `rest`, `graphql`, `gql`, `v1`, `v2`, `v3`.

### OpenAPI / Swagger paths

```
/openapi.json            /swagger.json           /api-docs
/openapi.yaml            /swagger.yaml           /api-docs.json
/v{1..3}/openapi.json    /docs/openapi.json      /api/openapi.json
/.well-known/openapi.json
```

Validation: response is JSON with `openapi:` or `swagger:` key + `info`, `paths`.

### GraphQL detection

POST introspection to `/graphql`, `/gql`, `/api/graphql`, `/v1/graphql`, `/query`:

```graphql
{ __schema { types { name } } }
```

GraphQL responses contain `data.__schema.types`. Note whether introspection is enabled (security finding if production).

### robots.txt parsing

Extract `Disallow:`, `Allow:`, `Sitemap:`. Flag entries matching `^/(api|v\d+|internal|admin)/`.

## API → Tech Inferences

| Signal | Indication |
|--------|-----------|
| `/swagger-ui/` path | Swagger UI (often Java/Spring) |
| `/redoc` | ReDoc |
| Introspection enabled | GraphQL server (Apollo, graphql-yoga, hot-chocolate, etc.) |
| OAuth 2.0 in spec | Identity-provider integration |
| `/v1/`, `/v2/` versioning | Mature REST API |

## Confidence Notes

- High: explicit version-bearing header (`Server: nginx/1.24.0`, `X-Powered-By: PHP/8.2.0`)
- Medium: framework-only header, cookie-name fingerprint, CMS path
- Low: error-page heuristic alone, single ambiguous cookie

## Rate Limits

- HTTP: 30 req/min/domain, 2s delay same-host
- GraphQL introspection: 5 req/min (expensive)
- OpenAPI fetch: no limit (local parse)
- Honor `Retry-After`. Only safe methods (GET, HEAD, OPTIONS).
