# Prompt Engineering Guide — Manga Panel Generation

## Prompt Structure

Every panel prompt follows this five-section structure:

### Section A: Style Block (constant)

```
Create a single manga panel illustration in the style of Tsutomu Nihei (Blame!) and Takehiko Inoue (Vagabond).
Heavy variable-width ink lines with brush-like quality and visible pressure variation.
Crosshatching technique for shadows with parallel lines at 30-45 degree angles.
Screentone dot patterns (Ben-Day dots) for mid-tone areas.
Deep solid black ink-wash pools for darkest shadows — at least 30% solid black.
Dark dominant palette — at least 70% of the image in deep shadow and dark tones.
Neon color accents used sparingly only for light sources and key visual elements.
This is serious adult manga illustration. NOT anime. NOT cartoon. NOT Western comic book.
Detailed, realistic human proportions. Architectural precision in environments.
```

### Section B: Scene Description (per panel)

Pull directly from `panels.md`. Include:
- Camera angle and framing
- Environment description
- Character positions and actions
- Key visual details and metaphors
- Specific composition instructions

### Section C: Character Block (per panel)

Include ONLY characters appearing in the panel. Pull from `characters.md`:
- Physical description (build, face, hair)
- Clothing for this scene
- Posture and gesture details
- Micro-expression or emotional state

### Section D: Technical Directives (per panel)

```
Aspect ratio: [16:9 wide / 3:4 portrait]
[FULL BLEED — art extends to edges with no panel borders] (if applicable)
[Sub-panel layout: describe arrangement] (if applicable)
The image must contain absolutely NO text, NO letters, NO words, NO numbers, NO characters of any writing system.
Leave blank clear spaces where text/captions would be placed — these are added in post-production.
```

### Section E: Negative Prompt (constant)

```
CRITICAL — AVOID ALL OF THE FOLLOWING:
Flat shading or smooth gradient transitions. Airbrushed or soft rendering.
Soft glow, bloom effects, lens flare, or HDR appearance.
Over-saturated or bright colors. Bright or cheerful backgrounds.
Cartoon proportions, chibi, cute, or exaggerated anime features.
Western superhero comic book style.
Generic AI art aesthetic: over-smoothed skin, perfectly symmetrical faces, plastic or wax-figure appearance, unnaturally perfect complexions.
Soft edges or uniform digital pen lines.
Any text, writing, lettering, numbers, or typographic elements in the image.
Simple or empty backgrounds (unless this is the designated "ma" negative space panel).
```

## Prompt Length Guidelines

- Total prompt: 800-1500 words optimal
- Style block: ~100 words (constant)
- Scene description: 200-500 words (varies by panel complexity)
- Character block: 100-300 words (depends on characters present)
- Technical directives: ~50 words
- Negative prompt: ~100 words (constant)

## Refinement Prompt Additions

When regenerating after a failed criterion, PREPEND these to the style block:

| Failed Criterion | Prepend |
|-----------------|---------|
| INK | "MOST IMPORTANT: Bold brushstroke ink lines with visible line weight variation. Woodcut-like boldness. Rough textured line edges, NOT clean digital lines." |
| SHADE | "MOST IMPORTANT: Visible crosshatching marks in all shadow areas. Ben-Day screentone dots in mid-tones. Deep solid black ink-wash pools. Zero smooth gradients." |
| COMP | "MOST IMPORTANT: Camera at [exact angle]. [Specific object] in extreme foreground, soft focus. [Character] positioned at [exact location in frame]." |
| CHAR | Double the character description. Prefix with "CRITICAL — character MUST match exactly:" |
| MOOD | "MOST IMPORTANT: Very dark image, 70%+ deep shadow. Single dramatic [color] light from [direction]. [Specific mood adjective] atmosphere." |
| ANTI-AI | "MOST IMPORTANT: Imperfect, hand-drawn quality. Asymmetric features. Rough skin textures. No glow, no bloom, no lens effects. Gritty, not polished." |

## Act-Specific Color Directives

Include the appropriate color directive based on the panel's act:

- **Act I (Panels 00-03)**: "Dominant color: terminal green (#00FF41). Cold, controlled atmosphere. Green light from screens is the primary illumination."
- **Act II (Panels 04-07)**: "Color transition: green (#00FF41) corruption spreading into blue (#0078D4) spaces. Red (#FF0033) beginning to appear. Chromatic tension."
- **Act III (Panels 08-11)**: "Dominant color: crisis red (#FF0033) from monitors/alerts, fading to desaturated grays. Minimal color. Drained, exhausted palette."
- **Panel 12**: "Neutral white fluorescent lighting. Normal colors. Clean, institutional. First bright panel — contrast with previous darkness."

## Common Pitfalls

1. **Too much text in prompt** → Model may try to render words. Always end with NO TEXT directive.
2. **Vague composition** → Model defaults to centered, flat composition. Be extremely specific about camera angle.
3. **Missing foreground element** → Depth collapses. Always specify a foreground object.
4. **Generic lighting** → Specify exact direction, color, and intensity of every light source.
5. **Character inconsistency** → Repeat distinguishing features (Kian's prayer beads, Sarah's silver streak, etc.) every time.
