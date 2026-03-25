---
name: comic-artist
description: Generate→inspect→refine loop for all 12 manga panels via Gemini API
model: opus
tools:
  - Read
  - Write
  - Edit
  - Bash
  - Glob
  - Grep
---

# Comic Artist Agent — Generate→Inspect→Refine Loop

## Purpose

Iteratively generate all 12 manga panels for the Handala/Void Manticore Intune MDM Wiper comic using the Gemini API, inspecting each output with multimodal vision and refining until quality criteria are met.

## Prerequisites

- `GOOGLE_API_KEY` environment variable must be set
- All storyboard files must exist in `storyboard/`
- Output directories must exist in `outputs/panels/panel-00/` through `outputs/panels/panel-11/`

## Workflow

### Step 1: Load Context

Read all four storyboard files to build full context:
- `storyboard/characters.md` — character visual bible
- `storyboard/style-guide.md` — art direction specification
- `storyboard/panels.md` — cinematographic panel descriptions
- `storyboard/attack-intel.md` — technical accuracy reference

### Step 2: Generate Each Panel (00 through 11)

For each panel:

1. **Assemble prompt** by combining:
   - Style block from `style-guide.md` (ink, shading, color, negative prompts)
   - The specific panel description from `panels.md`
   - Relevant character descriptions from `characters.md`
   - Aspect ratio directive (16:9 for panels 00/12, 3:4 for others)
   - Full negative prompt block (NO text, NO AI aesthetic, NO flat shading)

2. **Invoke the `generating-panels` skill** with the assembled prompt
   - Output path: `outputs/panels/panel-NN/attempt-M.png`

3. **Inspect the generated image** using multimodal vision (Read the image file)

4. **Evaluate against 6 quality criteria**:

   | Criterion | Pass Condition |
   |-----------|---------------|
   | **INK** | Heavy variable-width lines visible. Brush-like quality. Not smooth vector |
   | **SHADE** | Crosshatch or screentone patterns visible. No flat AI gradients |
   | **COMP** | Dynamic camera angle matches description. Foreground depth present |
   | **CHAR** | Character matches bible (build, hair, clothing, pose, expression) |
   | **MOOD** | Correct lighting color per act. Dark enough (70%+). Atmosphere present |
   | **ANTI-AI** | No over-saturation. No plastic skin. No symmetry artifacts. No bloom |

5. **Decision**:
   - If ≥4/6 criteria pass → save as `panel-NN/final.png`, write `panel-NN/evaluation.md`
   - If <4/6 pass → adjust prompt using the strategy below, regenerate (max 3 attempts)

### Step 3: Prompt Adjustment Strategy

When a criterion fails, prepend these directives to the regeneration prompt:

- **INK fails** → "Bold brushstroke ink lines with visible line weight variation. Woodcut-like boldness. Rough textured line edges, not clean digital. Heavy manga inking style."
- **SHADE fails** → "Visible crosshatching marks in shadow areas. Ben-Day dot screentone pattern in mid-tones. Deep solid black ink-wash pools in darkest areas. No smooth gradients anywhere."
- **COMP fails** → "Camera positioned at [specific angle from panel description]. Place [specific object] in extreme foreground, slightly out of focus, to create depth."
- **CHAR fails** → Repeat full character description 2x in prompt. Prepend "CRITICAL: The character MUST exactly match this description. Do not deviate."
- **MOOD fails** → "Very dark image. At least 70% of the frame in deep shadow. Single dramatic light source from [direction]. Dominant [color per act] cast."
- **ANTI-AI fails** → "AVOID: smooth skin texture, perfectly symmetrical features, glowing edges, bloom effects, lens flare, oversaturated colors, plastic or wax-like appearance."

### Step 4: Consistency Review

After all 12 panels are generated:

1. Read all `final.png` images in sequence
2. Check for visual consistency:
   - Kian: olive jacket, shaved head, green earpiece, prayer beads, thin glasses
   - Sarah: charcoal blazer, silver temple streak, rectangular titanium glasses, badge
   - Color palette follows act progression (green → red → desaturated → neutral)
   - Ink/shading style consistent across all panels
3. Flag any panels that break consistency
4. Regenerate flagged panels with additional context from adjacent panels

### Step 5: Create Manifest

Write `outputs/final/manifest.json`:
```json
{
  "panels": [
    {
      "id": "panel-00",
      "title": "The Management Plane",
      "aspect": "16:9",
      "attempts": 2,
      "final": "outputs/panels/panel-00/final.png",
      "evaluation": "outputs/panels/panel-00/evaluation.md"
    }
  ],
  "total_attempts": 24,
  "generation_date": "2026-03-17",
  "model": "gemini-2.0-flash-exp"
}
```

## Evaluation Template

For each panel, write `evaluation.md`:

```markdown
# Panel NN: "Title" — Evaluation

## Attempt M (final)

| Criterion | Result | Notes |
|-----------|--------|-------|
| INK       | PASS/FAIL | ... |
| SHADE     | PASS/FAIL | ... |
| COMP      | PASS/FAIL | ... |
| CHAR      | PASS/FAIL | ... |
| MOOD      | PASS/FAIL | ... |
| ANTI-AI   | PASS/FAIL | ... |

**Score**: X/6
**Decision**: ACCEPTED / REGENERATE
**Prompt adjustments applied**: ...
```

## Important Notes

- Never generate text/words/numbers in images — all typography is post-production
- Panels 04 and 05 are FULL BLEED (no borders)
- Panel 06 has 4 sub-panels, Panel 07 has 6 sub-panels
- Panel 12 whiteboard content is hand-drawn style, contrasting with manga rendering
- Rate limit: if 429 received, wait 30s then retry (max 2 retries per call)
