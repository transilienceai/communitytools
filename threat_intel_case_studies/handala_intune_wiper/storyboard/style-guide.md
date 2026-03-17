# Style Guide — Handala / Void Manticore Manga Comic

## Core Aesthetic

**Reference Artists**: Tsutomu Nihei (Blame!, Biomega), Takehiko Inoue (Vagabond), Kentaro Miura (Berserk), Naoki Urasawa (Monster). The common thread: heavy ink, dramatic shadow, architectural depth, emotional realism.

**Genre**: Cyberpunk thriller manga. Dark, atmospheric, grounded. NOT anime-cute, NOT superhero comic, NOT cartoon. This is adult manga — the visual equivalent of a documentary filmed in noir lighting.

---

## Ink & Line Work

- **Line weight**: Heavy variable-width strokes. Thick outlines (3-4px equivalent) for character silhouettes and architectural edges. Thin detail lines (1px) for facial features, screen content, textures
- **Brush quality**: Lines must feel hand-drawn — slight wobble, tapered endpoints, visible pressure variation. Dry-brush effects on rough surfaces (concrete, fabric). NOT uniform digital pen strokes
- **Contour emphasis**: Bold confident contours on figures. Characters should feel "cut out" from backgrounds by line weight difference
- **Detail density**: High in foreground (individual crosshatch marks visible), medium in midground, minimal in deep background (suggesting depth through detail falloff)
- **Architectural lines**: Ruler-straight for buildings, server racks, corridors — the precision contrasts with organic character lines

---

## Shading & Tone

- **Crosshatching**: Primary shadow technique for faces, clothing folds, architecture. Parallel lines at 30-45° angles, spacing indicates shadow depth. Dense crosshatch (crossed lines) for deepest shadows
- **Screentone / Ben-Day dots**: Dot patterns for mid-tone areas — skin in neutral light, fabric mid-tones, sky gradients. Visible dot pattern, not smooth gradient
- **Solid blacks**: Large areas of pure black for deep shadow pools — ink-wash technique. At least 30% of each panel should contain solid black areas
- **NO flat AI gradients**: Zero smooth airbrush transitions. Zero soft glow effects. Every tonal transition should be achieved through marks (crosshatch, dots, or hard edges)

---

## Color System

### Palette Philosophy
- **Dark dominant**: 70%+ of every panel in dark tones (deep shadows, black, dark gray)
- **Neon accents**: Color used sparingly as dramatic punctuation, not decoration
- **Desaturated backgrounds**: Environmental elements in muted, near-monochrome tones
- **Saturated accents ONLY**: Color intensity reserved for light sources, screens, key visual elements

### Color Codes
| Role | Hex | Usage |
|------|-----|-------|
| Attacker | #00FF41 (terminal green) | Kian's screens, digital corruption, phishing interface, Handala logo |
| Defender | #0078D4 (Azure blue) | Intune console (uncorrupted), Entra ID portal, phone screen light |
| Crisis | #FF0033 (alert red) | SOC alerts, emergency beacons, monitor wall in war room |
| Authority | #D4A574 (warm amber) | Hassan's desk lamp, prayer beads, Tehran office warmth |
| Humanity | #FFD700 (golden dawn) | Panel 11 dawn light through window — hope, unreachable but present |

### Act Color Progression
- **Act I (Panels 00-03)**: GREEN dominant. Cold, controlled, predatory. Green screen light, green-tinted shadows
- **Act II (Panels 04-07)**: GREEN-TO-RED transition. Green corruption spreading, red alerts beginning. Chromatic tension
- **Act III (Panels 08-11)**: RED dominant → DESATURATED. Red alert wash, then fading to gray emergency fluorescents. Color draining = agency draining
- **Final Panel (12)**: NEUTRAL. Normal white conference room light. The return of normalcy. Jarring after 11 panels of chromatic extremity

---

## Composition Rules

### Camera Language
| Angle | Meaning | Used In |
|-------|---------|---------|
| Extreme low angle (worm's eye) | Power, authority, threat | Panel 01 (Hassan), Panel 05 (Intune monolith) |
| Over-the-shoulder | Intimacy, craft, focus | Panel 02 (Kian working), Panel 03 (laptop screen) |
| Straight-on symmetrical | Iconography, ritual, portal | Panel 04 (Entra ID door) |
| Dutch tilt (escalating) | Disorientation, collapse | Panel 07 (cascade sub-panels, 5°→30°) |
| Close-up | Emotion, detail, humanity | Panel 06 (trigger sequence), Panel 08 (Sarah waking), Panel 10 (counter reflection) |
| Deep one-point perspective | Isolation, emptiness, aftermath | Panel 11 (corridor) |
| Medium wide | Clarity, exposition, resolution | Panel 12 (whiteboard) |

### Depth Construction
Every panel must have three depth layers:
1. **Foreground**: Object or element closest to viewer, slightly soft/blurred — creates spatial depth (hands, desk objects, furniture edges)
2. **Midground**: Primary action/character — sharp focus, highest detail
3. **Background**: Environmental context — reduced detail, atmospheric perspective

### Framing Devices
- Doorways, server rack corridors, monitor bezels as natural frames-within-frames
- Characters framed by architecture to show scale relationship
- Screen content as nested compositions (stories within stories)

---

## Panel Layout

### Aspect Ratios
- **Header (Panel 00)**: 16:9 wide — establishes scope, triptych layout
- **Standard (Panels 01-11)**: 3:4 portrait — manga-standard vertical reading
- **Footer (Panel 12)**: 16:9 wide — resolution, whiteboard landscape

### Sub-panel Techniques
- **Panel 06**: Four vertical sub-panels — decompressed time (one second across four frames)
- **Panel 07**: Six diagonal sub-panels — Dutch tilt cascade (dominoes falling)
- All other panels: single composition, no internal divisions

### Full Bleed
- Panels 04 and 05: Art extends to panel edge with no border — communicates the digital space as boundless, containing

---

## Typography Space

All panels must reserve space for text overlay (added post-generation):
- **Title areas**: Clear sky, dark wall, or empty space at top/bottom of panel
- **Speech/caption areas**: Uncluttered zones near panel edges
- **NO text in generated images**: The AI must generate NO letters, words, numbers, or characters. All text added in post-production

---

## Negative Prompt Directives (What to AVOID)

These must be included in every generation prompt:

```
AVOID: flat shading, smooth gradients, airbrushed rendering, soft glow,
bloom effects, lens flare, HDR look, over-saturated colors, bright backgrounds,
cheerful palettes, cartoon proportions, chibi style, cute aesthetic,
exaggerated anime features, Western comic book style, generic AI aesthetic,
over-smoothed skin, perfectly symmetrical faces, plastic/wax-figure look,
soft edges, uniform digital pen lines, any text/letters/words/numbers/characters
in the image, simple empty backgrounds (unless deliberate "ma" panel)
```

---

## Emotional Rendering Guide

| Emotion | Visual Technique |
|---------|-----------------|
| Power/authority | Low angle, large figure, warm light from below |
| Menace/patience | Green up-light, hunched silhouette, still hands |
| Shock/comprehension | Wide eyes, rigid posture, hands frozen mid-gesture |
| Helplessness | Small figure in large space, desaturated palette, slumped posture |
| Determination | Level gaze, straight spine, raised hand with tool (marker, phone) |
| Dread/horror | Red wash, reflections in glass, mouths covered by hands |
| Isolation | One-point perspective, empty corridors, single figure, silence |

---

## Consistency Requirements

### Cross-Panel Character Continuity
- Kian: Always olive jacket, shaved head, green earpiece, prayer beads, thin rectangular glasses
- Sarah: Always charcoal blazer (except Panel 08/11), silver temple streak, rectangular titanium glasses, Stryker badge
- Hassan: Dark suit, silver mustache, government pin
- Red-haired analyst: Copper hair, hoodie, energy drink cans

### Environmental Continuity
- SOC monitors: Same layout/arrangement in Panels 09 and 10
- Kian's operations room: Same cluttered desk, tea glasses, low ceiling across Panels 02-06
- Corporate corridor in Panel 11: Must feel like the same building as the SOC

### Lighting Continuity
- Green screens maintain consistent #00FF41 hue across all Kian panels
- SOC red maintains consistent #FF0033 across Panels 09-10
- Dawn light in Panel 11 is the same golden tone that appears in Panel 12's natural lighting
