# Formats Index

Standardized output format specifications for all engagements. Every deliverable an agent produces must conform to the relevant format below.

## Engagement Output Types

Core folder-level formats defining what goes where in `{OUTPUT_DIR}/` (see CLAUDE.md for canonical directory structure):

| Format | File | Description |
|--------|------|-------------|
| Data | [data.md](data.md) | JSON data files — report exports, recon inventories, structured findings |
| Logs | [logs.md](logs.md) | NDJSON execution and activity logs (coordinator + per-executor) |

## Report Generation

All reports use the Transilience design system:

| Format | File | Description |
|--------|------|-------------|
| Design System | [transilience-report-style/SKILL.md](transilience-report-style/SKILL.md) | Page config, typography, color palette, advisory card layout, ReportLab PDF generation |
| Pentest Report | [transilience-report-style/pentest-report.md](transilience-report-style/pentest-report.md) | Pentest report structure, finding quality standard, severity calibration, compliance mapping |

## Reconnaissance

| Format | File | Description |
|--------|------|-------------|
| Reconnaissance | [reconnaissance.md](reconnaissance.md) | JSON schemas, directory structure, and report template for Phase 2 recon |

## Platform-Specific

| Format | File | Description |
|--------|------|-------------|
| HTB Completion | [htb-completion-report.md](htb-completion-report.md) | HackTheBox challenge completion report and Slack notification input |
| Sensitive Data | [sensitive-data-metadata.md](sensitive-data-metadata.md) | HackerOne credential/token tracking for legal compliance |

## TechStack Reports

| Format | File | Description |
|--------|------|-------------|
| JSON Report | [techstack-json-report.md](techstack-json-report.md) | TechStackReport JSON schema |
| Evidence | [techstack-evidence-formatter.md](techstack-evidence-formatter.md) | Evidence formatting with sources, reasoning, and citations |
| Export | [techstack-report-exporter.md](techstack-report-exporter.md) | Markdown, HTML, and PDF export from TechStackReport JSON |

