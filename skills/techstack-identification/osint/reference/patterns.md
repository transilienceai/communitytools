# OSINT Detection Patterns

Consolidated from `code_repository_intel`, `job_posting_analysis`, `web_archive_analysis`.

## 1. Code Repository Intelligence

### Find the org

- Direct: `github.com/<company>` / `gitlab.com/<company>`
- Search: `org:<company>` in GitHub UI, Google `site:github.com "<company>"`
- Check company website footer for repo links

GitHub API (60 req/h unauth, 5000/h auth): `GET https://api.github.com/orgs/<org>` and `/repos/<owner>/<repo>/languages`. Validate org by description / website-URL match / recent activity.

### Language statistics → tech implications

| Language | Implies |
|----------|---------|
| TypeScript | Modern Node ecosystem |
| Python | Backend / ML — Django, Flask, FastAPI candidates |
| Ruby | Rails ecosystem |
| Go | Cloud-native / microservices |
| Rust | Performance-critical / systems |
| Java / Kotlin | Enterprise / JVM, Android |
| Swift | iOS / macOS |
| PHP | Laravel / Symfony |
| C# | .NET ecosystem |

### Dependency files

**`package.json` (Node.js):** `react`/`next`/`vue`/`nuxt`/`svelte` (frontend), `express`/`fastify`/`@nestjs/*` (backend), `prisma`/`mongoose`/`pg`/`mysql2`/`redis` (data), `graphql`/`apollo-server` (API).

**`requirements.txt` / `pyproject.toml` (Python):** `django`, `flask`, `fastapi`, `sqlalchemy`, `celery`, `redis`, `boto3`, `pandas`, `tensorflow`, `pytorch`.

**`Gemfile` (Ruby):** `rails`, `sinatra`, `sidekiq`, `pg`.

**`go.mod` (Go):** `gin-gonic/gin`, `gorilla/mux`, `gorm.io/gorm`, `labstack/echo`.

**`composer.json` (PHP):** `laravel/framework`, `symfony/*`, `phpunit/phpunit`.

Capture version ranges (e.g. `"react": "^18.2.0"`).

### CI/CD configs

`.github/workflows/*.yml` GitHub Actions · `.gitlab-ci.yml` · `Jenkinsfile` · `.circleci/config.yml` · `.travis.yml` · `azure-pipelines.yml` · `bitbucket-pipelines.yml` · `.drone.yml` · `cloudbuild.yaml` GCP · `buildspec.yml` AWS CodeBuild.

### Dockerfile FROM line

Extract base image + tag → language/runtime + version. `FROM node:18-alpine` → Node 18; `FROM python:3.11-slim` → Python 3.11; `FROM postgres:15` → Postgres 15.

`docker-compose.yml`: enumerate services, image refs, port mappings, env names (`DATABASE_URL=postgres://...` reveals DB).

## 2. Job Posting & ATS Analysis

### Locate careers page

Common paths: `/careers`, `/jobs`, `/work-with-us`, `/join-us`, `/about/careers`, `/company/careers`. Subdomains: `careers.<domain>`, `jobs.<domain>`. Fallback: footer scan, `site:<domain> careers`.

### ATS fingerprints

| ATS | URL pattern | Signal |
|-----|-------------|--------|
| Greenhouse | `boards.greenhouse.io` | startup / tech-forward |
| Lever | `jobs.lever.co` | startup / growth |
| Workday | `*.wd[3-5].myworkdayjobs.com` | enterprise |
| Ashby | `jobs.ashbyhq.com` | modern startup |
| iCIMS | `careers-*.icims.com` | enterprise |
| Taleo | `taleo.net` | enterprise (Oracle) |
| SmartRecruiters | `jobs.smartrecruiters.com` | mid-market |
| BambooHR | `*.bamboohr.com/jobs` | SMB |
| Jobvite / Breezy HR | `jobs.jobvite.com` / `*.breezy.hr` | mid / SMB |

### Tech extraction from descriptions

Regex over body text:

```
Experience with ([\w\s,/+#.]+)
Proficiency in ([\w\s,/+#.]+)
Knowledge of ([\w\s,/+#.]+)
Tech stack:?\s*([\w\s,/+#.]+)
Required:?\s*([\w\s,/+#.]+)
Nice to have:?\s*([\w\s,/+#.]+)
```

Match against keyword lists: languages, frontend frameworks, backend frameworks, databases, cloud/infra, CI/CD/observability tools.

### Frequency scoring

Per technology: `frequency = mentions_in_postings / total_postings`.

- ≥0.50 → Core Stack
- 0.25-0.50 → Common
- <0.25 → Occasional

### Role-type implications

Frontend Eng → React/Vue/Angular + TS + CSS framework · Backend Eng → server-side language + DB · Full Stack → both · DevOps → cloud + CI/CD + K8s/Docker + IaC · Data Eng → Python/Scala + Spark/Airflow · ML Eng → Python + TF/PyTorch · iOS Dev → Swift/Xcode · Android Dev → Kotlin/Java + Android SDK.

### Confidence

Job-posting evidence is **indirect**: 60-80% base. Distinguish "Required" vs "Nice to have"; combine with technical evidence to validate. "Nice to have" alone → Low.

## 3. Web Archive (Wayback Machine)

### CDX query

```
GET http://web.archive.org/cdx/search/cdx
  ?url=<domain>
  &output=json
  &filter=statuscode:200
  &collapse=timestamp:6   # group by month YYYYMM
  &limit=100
  &from=<YYYY>&to=<YYYY>
```

Snapshot URL: `https://web.archive.org/web/<timestamp>/<original_url>`.

### Snapshot selection

Take ≈5 snapshots: 6mo / 1y / 2y / 3y / 5y ago. Most recent baselines current; older detect migrations.

### Comparison points

Headers: `Server`, `X-Powered-By`, `Set-Cookie`. HTML: `meta[name=generator]`, `script[src]`, `link[href]`. Bundle markers: `/wp-content/`, `/_next/`, `/_nuxt/`, `/static/js/`.

### Migration patterns

| From → To | Indicators | Timeline |
|-----------|-----------|----------|
| WordPress → React/Next.js | `/wp-content/` disappears; React globals + `/_next/` appear | 6-18 mo |
| AngularJS → Angular | `ng-app` removed; `ng-version` appears | 12-24 mo |
| jQuery → React/Vue | jQuery CDN removed; SPA globals + bundle URLs | 6-12 mo |
| On-prem → Cloud | CloudFront/Cloudflare headers appear; cloud cert issuer | 3-12 mo |

### Confidence

Historical signals: 60-75% base. Strengthens current detections by showing trajectory; never overrides current direct evidence.

## Rate / Error

- GitHub API: 60/h unauth, 5000/h auth; on 403 wait & retry; fall back to web scraping (10/min)
- GitLab API: 300/min
- Career pages: 10/min; job postings 20/min; ATS APIs vary
- Wayback CDX: 15/min; snapshot fetches 10/min; cache CDX results
- Never clone repos, never apply to jobs, do not store full archived content
