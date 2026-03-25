# Handala / Void Manticore — Intune MDM Wiper Manga Comic

## Project Context

This project creates a 12-panel manga comic carousel depicting the March 11, 2026 attack where Iranian hacktivist group Handala (Void Manticore / MOIS) weaponized Microsoft Intune MDM to wipe 200,000+ devices across 79 countries.

**No Python scripts.** Content is markdown storyboard + Claude Code skills/agents with generate→inspect→refine loops.

## Key Files

| File | Purpose |
|------|---------|
| `storyboard/panels.md` | Cinematographic panel descriptions (12 panels) |
| `storyboard/characters.md` | Character bible — 6 visual entities with behavioral detail |
| `storyboard/style-guide.md` | Art direction: ink, shading, color system, composition |
| `storyboard/attack-intel.md` | Compressed attack intelligence for visual accuracy |
| `project.json` | Project metadata |

## Agents

| Agent | File | Purpose |
|-------|------|---------|
| comic-artist | `.claude/agents/comic-artist.md` | Generate→inspect→refine loop for all 12 manga panels |

## Generation Workflow

1. The `comic-artist` agent reads all storyboard files
2. For each panel, it assembles a prompt from style + scene + character descriptions
3. It invokes the `generating-panels` skill (Gemini API via curl)
4. It inspects the generated image using multimodal vision
5. It evaluates against 6 quality criteria (INK, SHADE, COMP, CHAR, MOOD, ANTI-AI)
6. If <4/6 pass → adjusts prompt and regenerates (max 3 attempts)
7. Saves attempts and final to `outputs/panels/panel-NN/`

## Color System

| Code | Hex | Meaning |
|------|-----|---------|
| Attacker | #00FF41 | Green — Kian, corruption, phishing, Handala logo |
| Defender | #0078D4 | Azure blue — Intune (uncorrupted), Entra ID |
| Crisis | #FF0033 | Red — SOC alerts, emergency beacons, war room |

## Act Structure

- **Act I (00-03)**: Green dominant — the spark, preparation, patience
- **Act II (04-07)**: Green→red transition — breach, escalation, cascade
- **Act III (08-11)**: Red→desaturated — aftermath, helplessness, silence
- **Panel 12**: Neutral light — clarity, understanding, resolve

## Critical Rules

- Generated images must contain NO text/letters/numbers — all typography added in post
- Style: manga (Nihei/Inoue/Miura reference), NOT anime/cartoon/Western comic
- 70%+ dark tones per panel — this is noir
- Characters must remain visually consistent across all panels
- `GOOGLE_API_KEY` env var required for image generation
