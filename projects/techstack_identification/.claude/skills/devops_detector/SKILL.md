---
name: devops-detector
description: Detects CI/CD tools, containerization, and orchestration from public signals
tools: Read, Grep
model: inherit
hooks:
  PostToolUse:
    - matcher: "Read"
      hooks:
        - type: command
          command: "../../../hooks/skills/post_output_validation_hook.sh"
---

# DevOps Detector Skill

## Purpose

Detect DevOps tools, CI/CD platforms, containerization, and orchestration from repository signals, job postings, and infrastructure indicators.

## Input

Raw signals from Phase 2:
- `repository_signals` - CI/CD configs, Dockerfiles, IaC
- `job_signals` - DevOps job requirements
- `dns_signals` - Service-specific subdomains
- `http_signals` - Deployment patterns

## Technology Categories

### CI/CD Platforms

| Platform | Detection Signals | Weight |
|----------|-------------------|--------|
| GitHub Actions | .github/workflows/*.yml | 40 |
| GitLab CI | .gitlab-ci.yml | 40 |
| Jenkins | Jenkinsfile, jenkins.* subdomain | 35 |
| CircleCI | .circleci/config.yml | 40 |
| Travis CI | .travis.yml | 35 |
| Azure Pipelines | azure-pipelines.yml | 40 |
| Bitbucket Pipelines | bitbucket-pipelines.yml | 35 |
| Drone CI | .drone.yml | 35 |
| TeamCity | .teamcity/ directory | 35 |
| Buildkite | .buildkite/ directory | 35 |

### Build Tools

| Tool | Detection Signals | Weight |
|------|-------------------|--------|
| Webpack | webpack.config.js, webpack patterns | 30 |
| Vite | vite.config.js | 30 |
| Rollup | rollup.config.js | 30 |
| esbuild | esbuild patterns | 25 |
| Turbo | turbo.json | 30 |
| Nx | nx.json | 30 |
| Lerna | lerna.json | 25 |
| pnpm | pnpm-workspace.yaml | 25 |

### Containerization

| Technology | Detection Signals | Weight |
|------------|-------------------|--------|
| Docker | Dockerfile, docker-compose.yml | 40 |
| Podman | Containerfile, podman-compose.yml | 35 |
| containerd | containerd config | 30 |

### Container Orchestration

| Platform | Detection Signals | Weight |
|----------|-------------------|--------|
| Kubernetes | k8s/, kubernetes/, kustomization.yaml | 40 |
| Docker Swarm | docker-stack.yml | 30 |
| Amazon ECS | ecs-*.json, task definitions | 35 |
| Nomad | *.nomad files | 30 |

### Infrastructure as Code

| Tool | Detection Signals | Weight |
|------|-------------------|--------|
| Terraform | *.tf files, .terraform/ | 40 |
| Pulumi | Pulumi.yaml | 35 |
| AWS CloudFormation | *.cfn.yml, template.yaml | 35 |
| AWS CDK | cdk.json | 35 |
| Ansible | ansible.cfg, playbook.yml | 35 |
| Chef | cookbooks/, recipes/ | 30 |
| Puppet | manifests/, modules/ | 30 |
| Helm | Chart.yaml, charts/ | 35 |

### Monitoring & Observability

| Tool | Detection Signals | Weight |
|------|-------------------|--------|
| Prometheus | prometheus.yml | 35 |
| Grafana | grafana.* subdomain | 30 |
| Datadog | datadog-agent configs | 35 |
| New Relic | newrelic.yml | 35 |
| Sentry | sentry.properties, dsn in config | 35 |
| PagerDuty | pagerduty integration | 30 |
| OpsGenie | opsgenie integration | 30 |

### Secret Management

| Tool | Detection Signals | Weight |
|------|-------------------|--------|
| HashiCorp Vault | vault references | 30 |
| AWS Secrets Manager | secretsmanager patterns | 30 |
| Doppler | doppler.yaml | 30 |
| 1Password | op:// references | 25 |

## Detection Logic

```python
def detect_devops_technologies(signals):
    results = []

    # CI/CD Detection from Repository
    if signals.repository_signals:
        for file in signals.repository_signals.files:
            # GitHub Actions
            if '.github/workflows/' in file and file.endswith('.yml'):
                results.append({
                    "name": "GitHub Actions",
                    "category": "CI/CD",
                    "signals": [{"type": "config_file", "value": file}],
                    "total_weight": 40
                })

            # GitLab CI
            if file == '.gitlab-ci.yml':
                results.append({
                    "name": "GitLab CI",
                    "category": "CI/CD",
                    "signals": [{"type": "config_file", "value": file}],
                    "total_weight": 40
                })

            # Docker
            if file.lower() in ['dockerfile', 'docker-compose.yml', 'docker-compose.yaml']:
                results.append({
                    "name": "Docker",
                    "category": "Containerization",
                    "signals": [{"type": "config_file", "value": file}],
                    "total_weight": 40
                })

            # Kubernetes
            if any(k8s_indicator in file.lower() for k8s_indicator in ['kubernetes', 'k8s', 'kustomization', 'helm']):
                results.append({
                    "name": "Kubernetes",
                    "category": "Container Orchestration",
                    "signals": [{"type": "config_file", "value": file}],
                    "total_weight": 40
                })

            # Terraform
            if file.endswith('.tf'):
                results.append({
                    "name": "Terraform",
                    "category": "Infrastructure as Code",
                    "signals": [{"type": "config_file", "value": file}],
                    "total_weight": 40
                })

    # Job Posting Analysis
    if signals.job_signals:
        devops_keywords = {
            "kubernetes": ("Kubernetes", "Container Orchestration"),
            "docker": ("Docker", "Containerization"),
            "terraform": ("Terraform", "Infrastructure as Code"),
            "ansible": ("Ansible", "Configuration Management"),
            "jenkins": ("Jenkins", "CI/CD"),
            "github actions": ("GitHub Actions", "CI/CD"),
            "gitlab ci": ("GitLab CI", "CI/CD"),
            "prometheus": ("Prometheus", "Monitoring"),
            "grafana": ("Grafana", "Monitoring"),
            "datadog": ("Datadog", "Monitoring"),
            "aws": ("AWS", "Cloud Platform"),
            "gcp": ("Google Cloud", "Cloud Platform"),
            "azure": ("Azure", "Cloud Platform")
        }

        for keyword, (tech_name, category) in devops_keywords.items():
            if keyword in signals.job_signals.tech_mentions:
                add_if_not_exists(results, tech_name, category, {
                    "type": "job_posting",
                    "value": f"'{keyword}' mentioned in job postings",
                    "frequency": signals.job_signals.tech_mentions[keyword].frequency
                }, 25)

    # DNS-based Detection
    devops_subdomains = {
        "jenkins": ("Jenkins", "CI/CD"),
        "ci": ("CI/CD System", "CI/CD"),
        "build": ("Build System", "CI/CD"),
        "deploy": ("Deployment System", "CI/CD"),
        "grafana": ("Grafana", "Monitoring"),
        "prometheus": ("Prometheus", "Monitoring"),
        "kibana": ("Elastic Stack", "Logging"),
        "argocd": ("Argo CD", "GitOps"),
        "vault": ("HashiCorp Vault", "Secret Management")
    }

    for subdomain in signals.discovered_subdomains:
        for pattern, (tech_name, category) in devops_subdomains.items():
            if pattern in subdomain.lower():
                results.append({
                    "name": tech_name,
                    "category": category,
                    "signals": [{"type": "subdomain", "value": subdomain}],
                    "total_weight": 30
                })

    return results
```

## Output

```json
{
  "skill": "devops_detector",
  "results": {
    "technologies": [
      {
        "name": "GitHub Actions",
        "category": "CI/CD",
        "signals": [
          {
            "type": "config_file",
            "value": ".github/workflows/ci.yml",
            "weight": 40
          },
          {
            "type": "config_file",
            "value": ".github/workflows/deploy.yml",
            "weight": 40
          }
        ],
        "total_weight": 80,
        "workflows_detected": ["ci.yml", "deploy.yml"]
      },
      {
        "name": "Docker",
        "category": "Containerization",
        "signals": [
          {
            "type": "config_file",
            "value": "Dockerfile",
            "weight": 40
          },
          {
            "type": "config_file",
            "value": "docker-compose.yml",
            "weight": 35
          }
        ],
        "total_weight": 75,
        "base_images": ["node:18-alpine", "nginx:alpine"]
      },
      {
        "name": "Kubernetes",
        "category": "Container Orchestration",
        "signals": [
          {
            "type": "config_file",
            "value": "kubernetes/deployment.yaml",
            "weight": 40
          },
          {
            "type": "job_posting",
            "value": "Kubernetes mentioned in 5 job postings",
            "weight": 25
          }
        ],
        "total_weight": 65
      },
      {
        "name": "Terraform",
        "category": "Infrastructure as Code",
        "signals": [
          {
            "type": "config_file",
            "value": "terraform/main.tf",
            "weight": 40
          }
        ],
        "total_weight": 40,
        "providers_detected": ["aws", "cloudflare"]
      },
      {
        "name": "Datadog",
        "category": "Monitoring",
        "signals": [
          {
            "type": "job_posting",
            "value": "Datadog mentioned in DevOps job postings",
            "weight": 25
          }
        ],
        "total_weight": 25
      }
    ],
    "devops_summary": {
      "ci_cd": ["GitHub Actions"],
      "containerization": ["Docker"],
      "orchestration": ["Kubernetes"],
      "iac": ["Terraform"],
      "monitoring": ["Datadog"],
      "maturity_assessment": "Advanced - Full CI/CD pipeline with IaC and container orchestration"
    }
  }
}
```

## Maturity Assessment

```
DevOps Maturity Levels:

Basic:
- Manual deployments
- No CI/CD detected
- Minimal automation

Intermediate:
- CI/CD pipeline detected
- Containerization (Docker)
- Basic monitoring

Advanced:
- Full CI/CD with multiple stages
- Container orchestration (K8s)
- Infrastructure as Code
- Comprehensive monitoring

Cloud-Native:
- GitOps practices (ArgoCD)
- Service mesh
- Observability stack
- Multi-cloud or hybrid
```

## Error Handling

- Private repositories: Note as limitation
- Incomplete config analysis: Provide partial results
- Job posting only signals: Lower confidence
