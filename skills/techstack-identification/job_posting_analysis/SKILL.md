---
name: job-posting-analysis
description: Extracts technology requirements from job postings and career pages
tools: Bash, WebFetch, WebSearch
model: inherit
hooks:
  PreToolUse:
    - matcher: "WebFetch"
      hooks:
        - type: command
          command: "../../../hooks/skills/pre_network_skill_hook.sh"
        - type: command
          command: "../../../hooks/skills/pre_rate_limit_hook.sh"
  PostToolUse:
    - matcher: "WebFetch"
      hooks:
        - type: command
          command: "../../../hooks/skills/post_skill_logging_hook.sh"
---

# Job Posting Analysis Skill

## Purpose

Extract technology stack information from job postings and career pages, which often reveal internal tech stack details.

## Operations

### 1. find_careers_page

Locate company's career/jobs page.

**Search Strategies:**
```
1. Common paths: /careers, /jobs, /work-with-us, /join-us
2. Subdomains: careers.{domain}, jobs.{domain}
3. Web search: site:{domain} careers OR jobs
4. Footer links on main site
```

**Common Career Page URLs:**
```
https://{domain}/careers
https://{domain}/jobs
https://careers.{domain}
https://jobs.{domain}
https://{domain}/about/careers
https://{domain}/company/careers
```

### 2. detect_ats_platform

Identify Applicant Tracking System in use.

**ATS Detection Patterns:**
```json
{
  "Greenhouse": {
    "url_pattern": "boards.greenhouse.io",
    "indicates": ["Tech-forward startup", "Modern hiring"],
    "confidence": 95
  },
  "Lever": {
    "url_pattern": "jobs.lever.co",
    "indicates": ["Tech-forward startup", "Growth stage"],
    "confidence": 95
  },
  "Workday": {
    "url_pattern": ".wd5.myworkdayjobs.com|.wd3.myworkdayjobs.com",
    "indicates": ["Enterprise company", "Large org"],
    "confidence": 95
  },
  "Ashby": {
    "url_pattern": "jobs.ashbyhq.com",
    "indicates": ["Modern startup", "Tech-forward"],
    "confidence": 95
  },
  "iCIMS": {
    "url_pattern": "careers-.*\\.icims\\.com|icims.com",
    "indicates": ["Enterprise hiring"],
    "confidence": 95
  },
  "Taleo": {
    "url_pattern": "taleo.net",
    "indicates": ["Enterprise (Oracle)", "Large org"],
    "confidence": 95
  },
  "SmartRecruiters": {
    "url_pattern": "jobs.smartrecruiters.com",
    "indicates": ["Mid-market to Enterprise"],
    "confidence": 95
  },
  "BambooHR": {
    "url_pattern": ".bamboohr.com/jobs",
    "indicates": ["SMB company"],
    "confidence": 95
  },
  "Jobvite": {
    "url_pattern": "jobs.jobvite.com",
    "indicates": ["Mid-market hiring"],
    "confidence": 95
  },
  "Breezy HR": {
    "url_pattern": ".breezy.hr",
    "indicates": ["SMB startup"],
    "confidence": 95
  }
}
```

### 3. extract_tech_requirements

Parse job descriptions for technology mentions.

**Extraction Patterns:**
```regex
Experience with ([\w\s,/]+)
Proficiency in ([\w\s,/]+)
Knowledge of ([\w\s,/]+)
Tech stack:? ([\w\s,/]+)
Working knowledge of ([\w\s,/]+)
Familiar with ([\w\s,/]+)
Strong background in ([\w\s,/]+)
Required:?\s*([\w\s,/]+)
Nice to have:?\s*([\w\s,/]+)
Technologies:?\s*([\w\s,/]+)
Tools:?\s*([\w\s,/]+)
```

**Technology Keyword Categories:**

**Languages:**
```
JavaScript, TypeScript, Python, Java, Go, Rust, Ruby, PHP,
C#, C++, Kotlin, Swift, Scala, Elixir, Clojure
```

**Frontend Frameworks:**
```
React, Vue, Angular, Svelte, Next.js, Nuxt, Gatsby,
Redux, MobX, Zustand, React Query, Tailwind, Bootstrap
```

**Backend Frameworks:**
```
Node.js, Express, NestJS, Django, Flask, FastAPI,
Rails, Spring, .NET, Laravel, Phoenix
```

**Databases:**
```
PostgreSQL, MySQL, MongoDB, Redis, Elasticsearch,
DynamoDB, Cassandra, Neo4j, Snowflake, BigQuery
```

**Cloud/Infrastructure:**
```
AWS, GCP, Azure, Kubernetes, Docker, Terraform,
Ansible, CloudFormation, Pulumi
```

**Tools:**
```
Git, GitHub, GitLab, Jenkins, CircleCI, GitHub Actions,
Datadog, New Relic, Grafana, Prometheus, Sentry
```

### 4. calculate_tech_frequency

Weight technologies by mention frequency across postings.

**Scoring:**
```python
def calculate_frequency_score(tech, postings):
    mentions = sum(1 for p in postings if tech in p.requirements)
    total_postings = len(postings)

    frequency = mentions / total_postings

    # Classify importance
    if frequency >= 0.5:
        importance = "Core Stack"  # 50%+ of postings
    elif frequency >= 0.25:
        importance = "Common"      # 25-50%
    else:
        importance = "Occasional"  # < 25%

    return {
        "mentions": mentions,
        "frequency": frequency,
        "importance": importance
    }
```

### 5. analyze_role_patterns

Identify tech stack from role types.

**Role Type Signals:**
```json
{
  "Frontend Engineer": {
    "implies": ["React/Vue/Angular", "JavaScript/TypeScript", "CSS frameworks"],
    "confidence": 70
  },
  "Backend Engineer": {
    "implies": ["Server-side language", "Database", "API development"],
    "confidence": 70
  },
  "Full Stack Engineer": {
    "implies": ["Frontend framework", "Backend framework", "Database"],
    "confidence": 65
  },
  "DevOps Engineer": {
    "implies": ["Cloud platform", "CI/CD", "Kubernetes/Docker", "IaC"],
    "confidence": 75
  },
  "Data Engineer": {
    "implies": ["Python/Scala", "Spark/Airflow", "Data warehouse"],
    "confidence": 75
  },
  "ML Engineer": {
    "implies": ["Python", "TensorFlow/PyTorch", "Cloud ML services"],
    "confidence": 75
  },
  "iOS Developer": {
    "implies": ["Swift", "Xcode", "iOS SDK"],
    "confidence": 85
  },
  "Android Developer": {
    "implies": ["Kotlin/Java", "Android SDK"],
    "confidence": 85
  }
}
```

## Output

```json
{
  "skill": "job_posting_analysis",
  "domain": "string",
  "results": {
    "careers_page": {
      "url": "string",
      "ats_platform": "Greenhouse",
      "ats_confidence": 95
    },
    "postings_analyzed": "number",
    "technologies_extracted": [
      {
        "name": "React",
        "category": "Frontend Framework",
        "mentions": 15,
        "total_postings": 20,
        "frequency": 0.75,
        "importance": "Core Stack",
        "contexts": [
          "Experience with React and TypeScript",
          "Build UIs using React"
        ],
        "confidence": 80
      }
    ],
    "role_distribution": {
      "Frontend": 5,
      "Backend": 8,
      "Full Stack": 4,
      "DevOps": 2,
      "Data": 1
    },
    "tech_stack_inference": {
      "frontend": ["React", "TypeScript", "Tailwind"],
      "backend": ["Node.js", "PostgreSQL", "Redis"],
      "infrastructure": ["AWS", "Kubernetes"],
      "confidence": "Medium"
    },
    "company_signals": {
      "engineering_size": "Large (20+ open roles)",
      "growth_stage": "Scaling",
      "tech_culture": "Modern (tech-forward ATS, current stack)"
    }
  },
  "evidence": [
    {
      "type": "job_posting",
      "title": "Senior Frontend Engineer",
      "url": "string",
      "technologies_mentioned": ["React", "TypeScript", "GraphQL"],
      "timestamp": "ISO-8601"
    }
  ]
}
```

## Rate Limiting

- Careers page fetch: 10/minute
- Job posting pages: 20/minute
- ATS APIs: Varies by platform

## Error Handling

- 404: No careers page found
- Access denied: ATS may require authentication
- Continue with partial data
- Fall back to search engine results

## Security Considerations

- Only access public job postings
- Do not apply to jobs or create accounts
- Respect robots.txt
- Do not scrape PII (recruiter names, emails)
- Log all fetches for audit

## Confidence Notes

Job posting data provides **indirect signals**:
- Technologies mentioned in job posts may not be currently deployed
- "Nice to have" vs "Required" distinction matters
- Combine with direct technical evidence for validation
- Base confidence: 60-80% (lower than direct signals)
