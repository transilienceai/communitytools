# Transilience AI — Threat Intelligence Report Design System

**Version:** 4.0  
**Format:** PDF (A4), ReportLab  
**Last Updated:** February 24, 2026

---

## 1. Page & Document Configuration

| Property | Value |
|---|---|
| Page Size | A4 (595.28 × 841.89 pt) |
| Margins | 20mm all sides |
| Content Width (CW) | 555.28 pt (A4 width − 2 × 20mm) |
| Top Margin Offset | +8 pt (28mm effective top) |
| Bottom Margin Offset | +10 pt (30mm effective bottom) |
| Background Color | `#07040B` (BG) — near-black with purple undertone |
| Output | Embedded fonts, single PDF file |

---

## 2. Typography

### 2.1 Font Stack

| Alias | Font | Weight | Role |
|---|---|---|---|
| `FH` | Poppins-Bold | 700 | Headlines, metric values, section numbers, score values |
| `FM` | Poppins-Medium | 500 | Subheads, section labels, card section headers, sidebar labels |
| `FR` | Poppins (Regular) | 400 | Footer text, metadata labels, TOC sub-items |
| `FL` | Poppins-Light | 300 | Reserved (registered, not actively used) |
| `FI` | Poppins-Italic | 400i | Reserved (registered, not actively used) |
| `FB` | Carlito (Regular) | 400 | Body text, card summaries, table cells, bullet content |
| `FBB` | Carlito-Bold | 700 | Bold inline emphasis within body paragraphs |
| `FBI` | Carlito-Italic | 400i | Confidentiality notices, closing statement |
| `FBBI` | Carlito-BoldItalic | 700i | Registered for `<b><i>` combinations within Carlito |
| `FMONO` | Courier | — | MITRE technique IDs, CVE identifiers, subdomain names |

**Family Registration:** Carlito is registered as a full family (`normal`, `bold`, `italic`, `boldItalic`) enabling automatic style switching via ReportLab's `<b>` and `<i>` XML tags.

### 2.2 Type Scale

| Style Key | Font | Size | Leading | Color | Alignment | Usage |
|---|---|---|---|---|---|---|
| `ct` | Poppins-Bold | 36 pt | 44 pt | `#FFFFFF` | Left | Cover title ("THREAT INTELLIGENCE", "REPORT") |
| `cc` | Poppins-Medium | 18 pt | 24 pt | `#8B5CF6` | Left | Cover client name |
| `h1` | Poppins-Bold | 20 pt | 26 pt | `#FFFFFF` | Left | Section titles |
| `h2` | Poppins-Medium | 16 pt | 21 pt | `#FFFFFF` | Left | Subsection titles |
| `h3` | Poppins-Medium | 13 pt | 17 pt | `#8B5CF6` | Left | Sub-headers within sections |
| `tt` | Poppins-Medium | 13 pt | 18 pt | `#FFFFFF` | Left | Card titles, posture item titles |
| `body` | Carlito | 12 pt | 17 pt | `#F0F2F5` | Justify | Body paragraphs |
| `bs` | Carlito | 11 pt | 15 pt | `#F0F2F5` | Left | Small body (table cells, metadata values) |
| `ts` | Carlito | 11 pt | 16 pt | `#F0F2F5` | Justify | Card description text |
| `label` | Poppins | 10 pt | 13 pt | `#E0E3E8` | Left | Cover metadata labels |
| `sl` | Poppins-Medium | 10 pt | 13 pt | `#8B5CF6` | Left | Table column headers |
| `bullet` | Carlito | 12 pt | 17 pt | `#F0F2F5` | Left | Bullet items (14pt leftIndent, 0 bulletIndent) |
| `notice` | Carlito-Italic | 10 pt | 14 pt | `#E0E3E8` | Left | Confidentiality footer |

### 2.3 Advisory Card Typography

| Element | Font | Size | Color | Notes |
|---|---|---|---|---|
| Serial + Severity Tag | Poppins-Bold | 14 pt | Severity color | Format: `#1  [CRITICAL]` |
| Card Title | Poppins-Bold | 14 pt | `#FFFFFF` | Same line as serial, leading 20pt |
| Metadata Row | Carlito | 10 pt | `#F0F2F5` | Labels in `#8B5CF6`, pipe-separated |
| Score Labels | Poppins-Medium | 10 pt | `#F0F2F5` | "SEVERITY", "RELEVANCE", "PRIORITY" |
| Score Values | Poppins-Bold | 12 pt | Dynamic color | `0.85` format |
| Score Band Label | Poppins-Bold | 10 pt | Dynamic color | "HIGH", "MEDIUM", "LOW" (priority row only) |
| Section Headers | Poppins-Medium | 10 pt | `#8B5CF6` | "TECHNICAL DETAILS", "IMPACT CONTEXT", etc. |
| Detection Evidence Header | Poppins-Medium | 10 pt | `#10B981` | Green to distinguish from purple headers |
| Section Body | Carlito | 11 pt | `#F0F2F5` | leading 15pt |
| MITRE Label | Carlito | 11 pt | `#F59E0B` | Amber for "MITRE Tactics:", "Techniques:" |
| CVE Label | Carlito | 11 pt | `#3B82F6` | Blue for "CVEs:" |
| CVE/Technique Values | Courier | 10–11 pt | `#F0F2F5` | Monospace for IDs |
| Relevance Bullets | Carlito | 11 pt | `#F0F2F5` | • symbol, 16pt leftIndent, leading 16pt |
| Source Link | Carlito | 10 pt | `#3B82F6` | Underlined |

---

## 3. Color Palette

### 3.1 Backgrounds

| Token | Hex | RGB | Usage |
|---|---|---|---|
| `BG` | `#07040B` | (7, 4, 11) | Page background — deepest layer |
| `BG2` | `#0D0A14` | (13, 10, 20) | Reserved secondary background |
| `BGC` | `#13101C` | (19, 16, 28) | Card backgrounds, table header rows, metric boxes |
| `BGCA` | `#1A1625` | (26, 22, 37) | Alternating table rows, progress bar track |
| `BGEL` | `#18181B` | (24, 24, 27) | Reserved elevated surface |
| `GL` | `#1E1A2E` | (30, 26, 46) | Table gridlines, footer bar background |
| `BS` | `#2A2535` | (42, 37, 53) | Card/box border stroke (0.4pt width) |

### 3.2 Brand Colors

| Token | Hex | RGB | Usage |
|---|---|---|---|
| `BP` | `#6941C6` | (105, 65, 198) | Primary brand — TOC numbers, metric accents, section number ghost |
| `BPL` | `#8B5CF6` | (139, 92, 246) | Primary light — h3 headers, card section headers, metadata labels, page numbers |
| `BM` | `#C9317C` | (201, 49, 124) | Magenta accent — third-party tech stack category |

### 3.3 Text Colors

| Token | Hex | Usage |
|---|---|---|
| `T1` | `#FFFFFF` | Brightest — headlines, card titles, tech names in evidence |
| `T2` | `#F0F2F5` | Primary body — paragraphs, table cells, card content |
| `T3` | `#E0E3E8` | Muted — labels, impact context field names, no-match text |
| `TM` | `#CDD1D8` | Most muted — fallback severity color |

### 3.4 Severity Colors

| Token | Hex | Severity | Usage |
|---|---|---|---|
| `SC` | `#EF4444` | Critical | Accent bars, score coloring, badges, immediate recommendations |
| `SH` | `#FB923C` | High | Accent bars, score coloring, badges, short-term recommendations |
| `SM` | `#EAB308` | Medium | Accent bars, score coloring, badges, medium-term recommendations |
| `SL` | `#22C55E` | Low | Accent bars, score coloring, badges, security posture "STRONG" |

### 3.5 Accent Colors

| Token | Hex | Usage |
|---|---|---|
| `AB` | `#3B82F6` | Info blue — CVE labels, source links, "ASSETS" metric box |
| `AE` | `#10B981` | Emerald green — "Implemented" status, detection evidence header |
| `AA` | `#F59E0B` | Amber — MITRE labels, analytics tech category |

### 3.6 Gradient Specification

The brand gradient is a linear interpolation between two endpoints used across multiple components:

| Property | Start (left) | End (right) |
|---|---|---|
| Red | 0.412 (105/255) | 0.788 (201/255) |
| Green | 0.255 (65/255) | 0.192 (49/255) |
| Blue | 0.776 (198/255) | 0.486 (124/255) |
| Hex equivalent | `#6941C6` (BP) | `#C9317C` (BM) |

**Rendered as:** 80 discrete steps, left-to-right. Used in: page top rule (3.5pt), section dividers (2pt), cover separators (3pt), progress bars, card bottom dividers.

---

## 4. Component Library

### 4.1 GradientLine

A full-width or partial-width horizontal rule using the brand gradient.

| Property | Value |
|---|---|
| Default height | 2 pt |
| Steps | 80 |
| Corner radius | None (rectangular) |
| Usage | Section dividers (full CW, 2pt), cover (full CW, 3pt), cover sub-separator (CW×0.35, 2pt), card bottom (CW×0.5, 1pt) |

### 4.2 GradientBar

A proportional progress bar with gradient fill and rounded track.

| Property | Value |
|---|---|
| Track height | 12 pt |
| Track background | `BGCA` (`#1A1625`) |
| Track corner radius | 3 pt |
| Fill | Brand gradient, clipped to fraction width |
| Min fraction | 0.06 (floor) |
| Max width | 160 pt (default) |

### 4.3 CardBox

A bordered container with optional accent sidebar. Used for posture items, recommendations, methodology phases.

| Property | Value |
|---|---|
| Background | `BGC` (`#13101C`) |
| Corner radius | 6 pt |
| Border | `BS` (`#2A2535`), 0.4 pt stroke |
| Accent bar | 4 pt wide, full height, left side, 2pt corner radius |
| Default padding | 11 pt |
| Content offset | padding + 6pt (when accent present) |

### 4.4 MetricBox

A compact KPI display used in the executive summary row.

| Property | Value |
|---|---|
| Height | 58 pt |
| Width | (CW − 30) / 5 per box |
| Background | `BGC` (`#13101C`) |
| Border | `BS` 0.4pt stroke, 6pt corner radius |
| Top accent | 3pt colored bar across full width, 1pt corner radius |
| Value | Poppins-Bold 22pt, centered, severity-colored |
| Label | Poppins 9pt, centered, `T2`, 7pt from bottom |

### 4.5 SeverityBadge

A colored pill showing severity level.

| Property | Value |
|---|---|
| Width | 60 pt |
| Height | 16 pt |
| Corner radius | 3 pt |
| Background | Severity color fill |
| Text | Poppins-Medium 9pt, centered |
| Text color | White (critical/high/low), Black (medium) |

### 4.6 SectionNumber

A large decorative section number with ghost double-strike effect.

| Property | Value |
|---|---|
| Width | Full CW |
| Height | 38 pt |
| Front layer | Poppins-Bold 42pt, `rgba(105, 65, 198, 0.7)` at (0, 0) |
| Ghost layer | Poppins-Bold 42pt, `rgba(140, 92, 230, 0.5)` at (1, 1) — offset 1pt right and up |

### 4.7 ScoreRow

Three horizontal inline score bars stacked vertically.

| Property | Value |
|---|---|
| Total height | 60 pt |
| Row height | 16 pt |
| Row padding | 4 pt |
| Bar max width | CW × 0.48 |
| Bar height | 8 pt |
| Bar track | `BGCA`, 3pt radius |
| Bar fill | Severity color at 0.85 alpha, min 4pt width |
| Glow dot | Circle at fill endpoint, severity color at 0.3 alpha, 5pt radius |
| Layout x-positions | Label: 0, Value: CW×0.12 + 10, Bar: CW×0.22, Band: CW×0.72 + 10 |

**Dynamic color rules:**

| Score Type | Thresholds |
|---|---|
| Severity | ≥0.75 → `SC` (red), ≥0.5 → `SH` (orange), else → `SM` (yellow) |
| Relevance | ≥0.6 → `AE` (green), ≥0.3 → `AA` (amber), else → `T3` (muted) |
| Priority | ≥0.7 → `SC` (red), ≥0.5 → `SH` (orange), ≥0.3 → `SM` (yellow), else → `T3` |

### 4.8 AccentBar (Card Top)

A thin colored bar at the top of each advisory card.

| Property | Value |
|---|---|
| Width | Full CW |
| Height | 4 pt |
| Corner radius | 2 pt |
| Color | Severity color of the advisory |

### 4.9 TechStackBlock

A category block displaying technology items as a bulleted list.

| Property | Value |
|---|---|
| Width | CW × 0.48 |
| Background | `BGC`, 5pt radius |
| Border | `BS` 0.3pt stroke |
| Header bar | 22pt height, category color fill, 5pt radius |
| Header text | Poppins-Medium 10pt, white, 10pt left offset |
| Item bullet | 2pt radius circle, category color, at (14, y+3) |
| Item text | Carlito 10pt, `T2`, at (22, y) |
| Item spacing | 16pt vertical |

---

## 5. Page Template (dark_bg)

Applied to every page via `onFirstPage` and `onLaterPages`.

### 5.1 Background Fill
- Full page `BG` (`#07040B`) rectangle

### 5.2 Top Gradient Rule
- Brand gradient (80 steps, BP → BM), 3.5pt height, full page width, positioned at page top

### 5.3 Footer Bar
| Property | Value |
|---|---|
| Height | 26 pt |
| Background | `GL` (`#1E1A2E`) |
| Left text | Poppins 7pt, `T3`: `TRANSILIENCE AI   ·   Threat Intelligence Report   ·   CONFIDENTIAL` |
| Left offset | 20mm margin |
| Page number | Poppins-Bold 9pt, `BP` — right-aligned |
| Page label | Poppins 8pt, `T2`: `Page ` — immediately left of number |

### 5.4 Left Accent Strip
- 2.5pt wide vertical bar, full page height minus footer, `rgba(105, 65, 198, 0.12)`, positioned at x=0

---

## 6. Radar Visualization

A custom Flowable rendering a polar threat radar.

### 6.1 Dimensions

| Property | Value |
|---|---|
| Canvas size | 300pt + 100pt width, 300pt + 60pt height |
| Center | (200, 180) |
| Max radius | 300 × 0.38 = 114 pt |

### 6.2 Background Glow

Concentric filled circles from `max_r + 20` down to 0 (step −2), each with increasing alpha (0.03 → 0.05), color `rgba(10, 5, 20, alpha)`.

### 6.3 Ring Grid

4 dashed concentric rings at 25%, 50%, 75%, 100% of max radius.

| Ring | Fraction | Label | Label Color |
|---|---|---|---|
| Inner | 0.25 | CRITICAL | `SC` (#EF4444) |
| Mid-inner | 0.50 | HIGH | `SH` (#FB923C) |
| Mid-outer | 0.75 | MEDIUM | `SM` (#EAB308) |
| Outer | 1.00 | LOW | `SL` (#22C55E) |

- Ring stroke: `rgba(105, 65, 198, 0.3)`, 0.5pt, dash pattern (3, 3)
- Labels positioned along 15° angle from center at each ring's radius, Poppins-Medium 7pt

### 6.4 Sector Spokes

12 spokes at 30° intervals, representing attack surfaces:

`Web Apps/API, Cloud/Infra, Network, Endpoints, Email, Mobile, IoT/OT, Data Storage, Identity, Third-Party, Physical, Social Eng.`

- Spoke stroke: `rgba(105, 65, 198, 0.25)`, 0.3pt
- Labels: Poppins-Medium 9pt, white, at `max_r + 32` from center
- Alignment: centered if near vertical, left-aligned if right half, right-aligned if left half

### 6.5 Center Crosshair

- 16pt arms, color `rgba(140, 92, 230, 0.4)`, 0.4pt
- Center glow: 16 concentric circles, `rgba(105, 65, 198, 0.04 × (16−r))`

### 6.6 Threat Points

Each threat plotted using `theta_deg` and `radius_norm` from data.

| Severity | RGB | Point radius |
|---|---|---|
| Critical | (0.937, 0.267, 0.267) | 7 pt |
| High | (0.984, 0.573, 0.235) | 5.5 pt |
| Medium | (0.918, 0.702, 0.031) | 4.5 pt |
| Low | (0.133, 0.773, 0.369) | 3.5 pt |

**Three-layer rendering per point:**
1. **Outer glow:** severity color at 0.12 alpha, radius + 7pt
2. **Mid glow:** severity color at 0.25 alpha, radius + 3pt
3. **Core dot:** severity color at 0.9 alpha, exact radius
4. **Specular highlight:** white at 0.3 alpha, offset (−0.15r, +0.15r), radius 0.35r

---

## 7. Advisory Card Structure

Cards are returned as flat lists of Flowables (not wrapped in CardBox), enabling ReportLab page-split. Between cards: `CondPageBreak(220)` — only breaks if <220pt space remains.

### 7.1 Card Layout (top to bottom)

| # | Section | Spacing After |
|---|---|---|
| 1 | **AccentBar** (4pt, severity color) | 8pt |
| 2 | **Title** — `#{serial}  [{SEVERITY}]  {title}` | 2pt (spaceAfter) |
| 3 | **Metadata Row** — pipe-separated: Source │ Surface │ Status │ First Seen | 2pt + 10pt gap |
| 4 | **ScoreRow** — 3 inline progress bars (60pt) | 12pt gap |
| 5 | **Summary** — justified body text | 4pt + 6pt gap |
| 6 | **TECHNICAL DETAILS** (conditional) — Tactics, Techniques, CVEs | 4pt per item + 6pt gap |
| 7 | **IMPACT CONTEXT** (always shown) — Industries, Regions, Assets | 4pt per item + 6pt gap |
| 7b | **DETECTION EVIDENCE** (conditional) — Techstack fingerprint matches | 3pt per item + 6pt gap |
| 8 | **RELEVANCE ANALYSIS** (conditional) — Bullet-point reasoning | 4pt per item + 4pt gap |
| 9 | **Source Link** — blue underlined URL | 0pt |
| 10 | **Bottom Divider** — GradientLine at CW×0.5, 1pt height | 8pt before |

### 7.2 Metadata Row Format

```
Source: THREAT INTEL │ Surface: Endpoint / Email │ Status: NEW │ First Seen: 2026-02-24
```

Labels in `BPL` (`#8B5CF6`), values in `T2`, separator: unicode `│` (U+2502) with 4-space padding.

Source label mapping: `threat` → `THREAT INTEL`, `product` → `PRODUCT VULN`, `breach` → `BREACH INTEL`.

### 7.3 Detection Evidence Format

```
• {TechName}  —  {evidence_string}
```

Tech name in `T1` (white, bold), em-dash separator, evidence string in `T2`. Max 6 items per card.

### 7.4 Section Header Coloring

| Header | Color |
|---|---|
| TECHNICAL DETAILS | `BPL` (#8B5CF6) |
| IMPACT CONTEXT | `BPL` (#8B5CF6) |
| DETECTION EVIDENCE | `AE` (#10B981) — green to visually distinguish |
| RELEVANCE ANALYSIS | `BPL` (#8B5CF6) |

---

## 8. Cover Page Layout

### 8.1 Structure (top to bottom)

| Element | Configuration |
|---|---|
| Logo row | 3-column table: [Transilience logo (55×22mm), spacer, Client logo (38×27mm)], row height 28mm |
| Gap | 26mm |
| Gradient separator | Full CW, 3pt height |
| Gap | 12mm |
| Title line 1 | "THREAT INTELLIGENCE" — `ct` style (Poppins-Bold 36pt, white) |
| Title line 2 | "REPORT" — `ct` style |
| Gap | 6mm |
| Client name | `cc` style (Poppins-Medium 18pt, `BPL`) |
| Gap | 4mm |
| Sub-separator | GradientLine CW×0.35, 2pt |
| Gap | 8mm |
| Metadata table | 6 rows, 2 columns (CW×0.3 label, CW×0.7 value) |
| Gap | 15mm |
| Confidentiality notice | Carlito-Italic 10pt, `T3` |

### 8.2 Metadata Fields

| Label | Style |
|---|---|
| REPORT DATE | Poppins 10pt `T3` → value Carlito 11pt `T2` |
| CLASSIFICATION | Same |
| SECTOR | Same |
| REGION | Same |
| GENERATED BY | Same |
| REPORT ID | Same — format: `TI-{CLIENT}-{YYYYMMDD}` |

---

## 9. Table of Contents Layout

| Element | Style |
|---|---|
| Title | "TABLE OF CONTENTS" — `h1` style |
| Divider | GradientLine full CW, 2pt |
| Gap | 8mm |
| Main entry | 3-column table: section number (Poppins-Bold 13pt `BP`, 35pt col), title (Poppins-Medium 10.5pt `T1`), page (Poppins-Bold 11pt `T1`, right-aligned, 40pt col) |
| Entry separator | 0.3pt `GL` line below |
| Sub-entry | Indented 15pt, Poppins 10pt, sub-number in `T3`, title in `T2` |

---

## 10. Report Section Blueprint

### 10.1 Standard Section Header Pattern

Every numbered section follows this sequence:
1. `SectionNumber(num)` — decorative ghost number (38pt height)
2. Section title in `h1` style (Poppins-Bold 20pt)
3. `GradientLine(CW, 2)` — full-width separator
4. `Spacer(1, 4*mm)` — breathing room

### 10.2 Section Inventory (12 sections)

| # | Section | Content Type |
|---|---|---|
| 01 | Executive Summary | MetricBox row + narrative + bulleted key findings |
| 02 | Threat Landscape Overview | Source distribution table + attack surface table |
| 03 | Threat Radar Visualization | RadarVisualization flowable + legend |
| 04 | Critical Severity Advisories | Advisory cards (PageBreak before section) |
| 05 | High Severity Advisories | Advisory cards (PageBreak before section) |
| 06 | Medium Severity Advisories | Advisory cards (PageBreak before section) |
| 07 | Attack Surface Analysis | Digital footprint table + subdomain inventory |
| 08 | Asset Inventory & Crown Jewels | Crown jewel CardBoxes + full inventory table |
| 09 | Technology Stack Intelligence | TechStackBlocks + security headers table |
| 10 | Security Posture Assessment | Status CardBoxes (6 items) |
| 11 | Strategic Recommendations | Tiered CardBoxes (Immediate/Short/Medium-term) |
| 12 | Methodology & Data Sources | Pipeline CardBoxes + scoring methodology + evidence table |

---

## 11. Spacing System

### 11.1 Vertical Rhythm

| Context | Spacing |
|---|---|
| After section title | 8pt (h1 spaceAfter) |
| After gradient divider | 4mm (≈11.3pt) |
| Between card sections (within) | 4pt |
| Between card section groups | 6pt |
| After metadata row → scores | 10pt |
| After scores → summary | 12pt |
| After summary → tech details | 6pt |
| Between advisory cards | CondPageBreak(220) |
| Between severity sections | PageBreak() |
| Before Evidence Collection | PageBreak() |

### 11.2 Table Padding

| Property | Value |
|---|---|
| Top padding | 4–5 pt |
| Bottom padding | 4–5 pt |
| Left padding | 6–8 pt |
| Row separator | 0.5pt `GL` line |

---

## 12. Data-Driven Components

### 12.1 Evidence Map Architecture

Technology evidence is extracted from `techstack_report.json` and indexed by keyword. The extraction traverses:
- `technologies.frontend[]` — name, evidence[].finding, evidence[].details
- `technologies.backend[]` — web servers, frameworks, CMS, languages
- `technologies.infrastructure[]` — DNS, CDN providers
- `technologies.security[]` — WAF, certificates, headers, email security
- `technologies.third_party[]` — analytics, collaboration tools

Each evidence item is indexed under multiple keywords derived from the technology name fragments. Alias mappings expand coverage (e.g., `email` → `proofpoint`, `microsoft`, `dmarc`).

### 12.2 Threat-Evidence Matching

`get_threat_evidence(threat)` scans the threat's title, summary, and threat_name against the keyword index. Returns up to 6 `(tech_name, evidence_string)` tuples. Deduplication by `{tech_name}:{evidence}` key.

### 12.3 Severity Sorting

All threats sorted by: severity rank descending (critical=4, high=3, medium=2, low=1), then prioritization_score descending. Split into four lists for section rendering.

---

## 13. Unicode Characters

| Character | Code | Usage |
|---|---|---|
| `│` | U+2502 | Pipe separator in metadata rows |
| `•` | U+2022 | Bullet point in relevance analysis, detection evidence |
| `—` | U+2014 | Em-dash in section headers, posture items, evidence items |
| `·` | U+00B7 | Middle dot in footer text |
| `✔` | U+2714 | Reserved (previously used in evidence, now removed) |
| `&bull;` | HTML entity | Bullet in executive summary key findings |

---

## 14. Adaptive Behaviors

### 14.1 Page Break Strategy

| Transition | Method |
|---|---|
| Between advisories (same severity) | `CondPageBreak(220)` — break only if <220pt remains |
| Between severity sections | `PageBreak()` — always new page |
| Before Evidence Collection | `PageBreak()` — separate last page |

### 14.2 Card Splittability

Advisory cards return flat `list[Flowable]` instead of monolithic `CardBox`. This allows ReportLab's frame to split cards across page boundaries at any Paragraph/Spacer seam, eliminating blank pages.

### 14.3 Client Adaptation

The design system is client-agnostic. Customized per client:
- Cover: client logo, name, sector, region, report ID
- Executive summary: narrative and key findings
- Attack surface: domain/subdomain inventory
- Evidence map: keyword aliases tuned to client's tech stack
- Security posture: assessments specific to client's infrastructure
- Recommendations: actionable items specific to client's vulnerabilities

All visual elements (colors, typography, spacing, components) remain identical across clients.
