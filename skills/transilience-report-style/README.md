# Transilience Report Style — Skill

## What It Does

Generates branded PDF reports following the Transilience AI design system — dark pages, purple-to-magenta gradients, Poppins + Carlito typography, severity-coded colors. Works for any report type (threat intel, compliance, audit, vulnerability assessment, etc.).

## Setup

```
your-project/.claude/skills/transilience-report-style/
├── SKILL.md
└── assets/
    └── logos/
        ├── transilience_logo.png   ← transparent PNG, 55 × 22mm
        └── client_logo.png         ← transparent PNG, 38 × 27mm
```

Both logos **must be transparent PNGs** — they sit on the dark `#07040B` background.

## Usage

Give Claude your report data in any format — JSON, Markdown, CSV, plain text, uploaded files, whatever you have — along with the logos, and ask it to generate the report:

```
Generate a Transilience branded PDF report using the attached data.
Transilience logo: assets/logos/transilience_logo.png
Client logo: assets/logos/acme_logo.png
Client: Acme Corp, Financial Services, North America
```

The skill triggers on "Transilience report", "Transilience PDF", "Transilience design system", "branded report", or "generate report" when Transilience context is present.
