# Quality Criteria — Panel Evaluation

## The Six Criteria

Each generated panel is evaluated against these six criteria. A panel passes if it scores ≥4/6.

---

### 1. INK — Line Work Quality

**Pass**: Heavy variable-width ink lines are visible. Lines have brush-like quality with tapered endpoints and pressure variation. Character outlines are bolder than background lines. Lines feel hand-drawn, not digitally uniform.

**Fail**: Lines are uniform width (vector-like). Edges are smooth and clean without character. No visible brush texture. Lines feel computer-generated rather than hand-inked.

**What to look for**:
- Thick outlines on character silhouettes
- Thin detail lines on facial features and textures
- Visible line taper at endpoints
- Slight wobble or imperfection suggesting hand-drawn quality
- Dry-brush effects on rough surfaces

---

### 2. SHADE — Shadow & Tone Technique

**Pass**: Crosshatching marks visible in shadow areas (parallel lines at angles). Screentone/dot patterns visible in mid-tone areas. Large areas of solid black for deep shadows. Tonal transitions achieved through marks, not smooth blending.

**Fail**: Shadows are smooth gradients or airbrush-style. No visible mark-making technique. Mid-tones are flat or blended. No screentone patterns. Shadows look digitally rendered.

**What to look for**:
- Parallel crosshatch lines in shadow zones
- Ben-Day dot patterns in mid-tone areas
- Solid black ink-wash pools (at least 30% of panel)
- Hard edges between tone zones
- No smooth airbrushed transitions

---

### 3. COMP — Composition & Camera

**Pass**: Camera angle matches the panel description (low angle, over-shoulder, close-up, etc.). Foreground depth element present. Three-layer depth (foreground, midground, background). Character placement matches described position. Dynamic framing uses architectural elements.

**Fail**: Default centered composition regardless of described angle. No foreground depth element. Flat composition without spatial layers. Character positioned differently than described.

**What to look for**:
- Specific camera angle from panel description achieved
- Foreground object creating depth (blurred or partially visible)
- Character positioned as described (center, left third, behind, etc.)
- Architectural framing elements (doorways, monitor bezels, corridors)
- Correct aspect ratio (16:9 or 3:4)

---

### 4. CHAR — Character Accuracy

**Pass**: Character is recognizable from their bible description. Key identifying features present (Kian's shaved head/olive jacket/prayer beads, Sarah's silver streak/rectangular glasses/blazer). Posture and gesture match described action. Expression matches described emotional state.

**Fail**: Character doesn't match physical description. Missing key identifying features. Wrong clothing or accessories. Posture or expression contradicts the panel description.

**What to look for**:
- **Kian**: Shaved head, olive jacket, thin rectangular glasses, green earpiece, prayer beads on left wrist, lean angular build
- **Sarah**: Silver streak at left temple, rectangular titanium glasses, charcoal blazer, Stryker badge on lanyard
- **Hassan**: Stocky build, silver-streaked mustache, dark suit, government pin
- Correct hand positions and gestures as described
- Appropriate emotional expression

---

### 5. MOOD — Atmosphere & Lighting

**Pass**: Lighting color matches act designation (green/blue/red per act structure). Image is dark — 70%+ in shadow or dark tones. Atmosphere matches described mood (menace, helplessness, devastation, etc.). Light sources match description (screens, desk lamp, emergency beacons).

**Fail**: Image is too bright or evenly lit. Wrong dominant color for the act. Atmosphere doesn't match (cheerful when should be grim, energetic when should be still). Light sources don't match described direction or color.

**What to look for**:
- Act I (00-03): Green dominant, cold, controlled
- Act II (04-07): Green-to-red transition, building tension
- Act III (08-11): Red dominant, then desaturated and gray
- Panel 12: Neutral white light (deliberately jarring after darkness)
- 70%+ dark tones in the image
- Light direction matches description

---

### 6. ANTI-AI — Avoiding AI Aesthetic

**Pass**: Image has organic, hand-crafted quality. Faces show natural asymmetry. Skin has texture (not smooth plastic). No bloom or glow effects. Colors are restrained and dark. No "perfect" or "polished" AI look.

**Fail**: Over-smoothed skin with plastic/wax appearance. Perfectly symmetrical faces. Bloom, glow, or lens flare effects. Over-saturated colors. Generic "AI art" aesthetic. Soft dreamy rendering.

**What to look for**:
- Skin texture: rough, hatched, textured — not porcelain smooth
- Facial asymmetry: natural human variation
- NO bloom or glow halos around light sources
- NO lens flare effects
- Colors restrained, not hyperchromatic
- Overall impression: could this be from a printed manga volume?

---

## Scoring

| Score | Decision |
|-------|----------|
| 6/6 | Excellent — save as final |
| 5/6 | Good — save as final |
| 4/6 | Acceptable — save as final |
| 3/6 | Needs work — regenerate with adjustments |
| 2/6 | Poor — regenerate with major adjustments |
| 1/6 | Failed — regenerate with completely revised prompt |
| 0/6 | Critical failure — check API response and prompt structure |

## Maximum Attempts

- 3 attempts per panel before accepting best available
- If all 3 attempts score <4/6, accept the highest-scoring attempt and note issues in evaluation
- Total budget: ~36 API calls maximum (12 panels × 3 attempts)
