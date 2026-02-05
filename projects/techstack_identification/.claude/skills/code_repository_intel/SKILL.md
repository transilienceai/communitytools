---
name: code-repository-intel
description: Scans GitHub/GitLab for public repos, dependencies, and CI configurations
tools: Bash, WebFetch
model: inherit
hooks:
  PreToolUse:
    - matcher: "WebFetch"
      hooks:
        - type: command
          command: "../../../hooks/skills/pre_rate_limit_hook.sh"
  PostToolUse:
    - matcher: "WebFetch"
      hooks:
        - type: command
          command: "../../../hooks/skills/post_skill_logging_hook.sh"
---

# Code Repository Intelligence Skill

## Purpose

Scan public code repositories (GitHub, GitLab) to discover technologies through dependency files, CI configurations, and language statistics.

## Operations

### 1. find_github_org

Search for company's GitHub organization.

**Search Strategies:**
```
1. Direct org URL: github.com/{company_name}
2. GitHub search: org:{company_name}
3. Google dork: site:github.com "{company_name}"
4. Check company website for GitHub links
```

**GitHub API (if available):**
```
GET https://api.github.com/orgs/{org_name}
GET https://api.github.com/users/{username}
```

**Validation:**
- Organization description matches company
- Website URL in profile matches domain
- Recent activity (not abandoned)

### 2. analyze_repo_languages

Extract primary languages from repositories.

**GitHub API:**
```
GET https://api.github.com/repos/{owner}/{repo}/languages
```

**Response:**
```json
{
  "TypeScript": 245000,
  "JavaScript": 45000,
  "CSS": 12000,
  "HTML": 8000
}
```

**Language Implications:**
```json
{
  "TypeScript": {"implies": ["Node.js ecosystem"], "modern": true},
  "Python": {"implies": ["Backend/ML"], "frameworks": ["Django", "Flask", "FastAPI"]},
  "Ruby": {"implies": ["Rails ecosystem"]},
  "Go": {"implies": ["Cloud native", "Microservices"]},
  "Rust": {"implies": ["Performance critical", "Systems"]},
  "Java": {"implies": ["Enterprise"]},
  "Kotlin": {"implies": ["Android", "JVM modern"]},
  "Swift": {"implies": ["iOS/macOS"]},
  "PHP": {"implies": ["Web backend"], "frameworks": ["Laravel", "Symfony"]},
  "C#": {"implies": [".NET ecosystem"]}
}
```

### 3. scan_dependency_files

Parse dependency files for technology stack.

**Dependency File Mapping:**

**package.json (Node.js):**
```json
{
  "react": {"tech": "React", "confidence": 95},
  "next": {"tech": "Next.js", "implies": ["React"], "confidence": 95},
  "vue": {"tech": "Vue.js", "confidence": 95},
  "nuxt": {"tech": "Nuxt.js", "implies": ["Vue.js"], "confidence": 95},
  "express": {"tech": "Express.js", "confidence": 95},
  "fastify": {"tech": "Fastify", "confidence": 95},
  "nest": {"tech": "NestJS", "confidence": 95},
  "prisma": {"tech": "Prisma ORM", "confidence": 95},
  "mongoose": {"tech": "MongoDB", "confidence": 90},
  "pg": {"tech": "PostgreSQL", "confidence": 90},
  "mysql2": {"tech": "MySQL", "confidence": 90},
  "redis": {"tech": "Redis", "confidence": 90},
  "graphql": {"tech": "GraphQL", "confidence": 95},
  "apollo-server": {"tech": "Apollo GraphQL", "confidence": 95}
}
```

**requirements.txt / pyproject.toml (Python):**
```json
{
  "django": {"tech": "Django", "confidence": 95},
  "flask": {"tech": "Flask", "confidence": 95},
  "fastapi": {"tech": "FastAPI", "confidence": 95},
  "sqlalchemy": {"tech": "SQLAlchemy", "confidence": 90},
  "celery": {"tech": "Celery", "confidence": 90},
  "redis": {"tech": "Redis", "confidence": 85},
  "boto3": {"tech": "AWS SDK", "confidence": 90},
  "pandas": {"tech": "Data Science stack", "confidence": 70},
  "tensorflow": {"tech": "TensorFlow", "confidence": 95},
  "pytorch": {"tech": "PyTorch", "confidence": 95}
}
```

**Gemfile (Ruby):**
```json
{
  "rails": {"tech": "Ruby on Rails", "confidence": 95},
  "sinatra": {"tech": "Sinatra", "confidence": 95},
  "sidekiq": {"tech": "Sidekiq", "confidence": 90},
  "pg": {"tech": "PostgreSQL", "confidence": 85}
}
```

**go.mod (Go):**
```json
{
  "gin-gonic/gin": {"tech": "Gin", "confidence": 95},
  "gorilla/mux": {"tech": "Gorilla Mux", "confidence": 90},
  "gorm.io/gorm": {"tech": "GORM", "confidence": 90}
}
```

### 4. detect_ci_configs

Find and analyze CI/CD configuration files.

**CI Config Locations:**
```
.github/workflows/*.yml → GitHub Actions
.gitlab-ci.yml → GitLab CI
Jenkinsfile → Jenkins
.circleci/config.yml → CircleCI
.travis.yml → Travis CI
azure-pipelines.yml → Azure Pipelines
bitbucket-pipelines.yml → Bitbucket Pipelines
.drone.yml → Drone CI
cloudbuild.yaml → Google Cloud Build
buildspec.yml → AWS CodeBuild
```

**CI Config Analysis:**
```json
{
  "github_actions": {
    "indicates": "GitHub Actions CI/CD",
    "signals": ["Likely GitHub-centric workflow"]
  },
  "gitlab_ci": {
    "indicates": "GitLab CI/CD",
    "signals": ["Self-hosted or GitLab.com"]
  },
  "jenkins": {
    "indicates": "Jenkins",
    "signals": ["Enterprise CI", "Self-hosted"]
  }
}
```

### 5. search_dockerfile

Identify container base images and configuration.

**Dockerfile Analysis:**
```
FROM node:18-alpine → Node.js 18
FROM python:3.11-slim → Python 3.11
FROM golang:1.21 → Go 1.21
FROM ruby:3.2 → Ruby 3.2
FROM openjdk:17 → Java 17
FROM nginx:latest → nginx
FROM postgres:15 → PostgreSQL 15
FROM redis:7 → Redis 7
```

**Docker Compose Analysis:**
- Service names
- Image references
- Environment variables
- Port mappings

## Output

```json
{
  "skill": "code_repository_intel",
  "domain": "string",
  "results": {
    "organization": {
      "platform": "GitHub|GitLab",
      "name": "string",
      "url": "string",
      "verified": "boolean",
      "public_repos": "number"
    },
    "repositories": [
      {
        "name": "string",
        "url": "string",
        "description": "string",
        "languages": {
          "TypeScript": 65,
          "JavaScript": 25,
          "CSS": 10
        },
        "primary_language": "TypeScript",
        "last_updated": "date",
        "stars": "number"
      }
    ],
    "dependencies_found": {
      "node": [
        {"name": "react", "version": "^18.2.0", "tech": "React"},
        {"name": "next", "version": "13.4.0", "tech": "Next.js"}
      ],
      "python": [],
      "ruby": [],
      "go": []
    },
    "ci_cd": {
      "platform": "GitHub Actions",
      "config_file": ".github/workflows/ci.yml",
      "jobs_detected": ["build", "test", "deploy"]
    },
    "containerization": {
      "uses_docker": true,
      "base_images": ["node:18-alpine", "nginx:alpine"],
      "orchestration": "Kubernetes (k8s manifests found)"
    },
    "technologies_summary": [
      {
        "name": "string",
        "category": "Language|Framework|Database|Tool",
        "confidence": "number",
        "source": "dependency_file|ci_config|dockerfile"
      }
    ]
  },
  "evidence": [
    {
      "type": "repository",
      "url": "string",
      "file": "string",
      "content_sample": "string",
      "timestamp": "ISO-8601"
    }
  ]
}
```

## Rate Limiting

- GitHub API (unauthenticated): 60 requests/hour
- GitHub API (authenticated): 5000 requests/hour
- GitLab API: 300 requests/minute
- Web scraping fallback: 10 requests/minute

## Error Handling

- 404: Organization/repo doesn't exist or is private
- 403: Rate limited - wait and retry
- Continue with partial results
- Fall back to web scraping if API fails

## Security Considerations

- Only access public repositories
- Do not clone repositories
- Respect rate limits
- Do not store code content
- Log all API calls for audit
