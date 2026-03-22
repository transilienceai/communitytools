---
name: frontend-inferencer
description: Infers frontend technologies including React, Angular, Vue, jQuery, Bootstrap, etc.
tools: Read, Grep
model: inherit
hooks:
  PostToolUse:
    - matcher: "Read"
      hooks:
        - type: command
          command: "../../../hooks/skills/post_output_validation_hook.sh"
---

# Frontend Inferencer Skill

## Purpose

Infer frontend technologies by analyzing collected signals from JavaScript, DOM, HTML, and CSS analysis phases.

## Input

Raw signals from Phase 2:
- `javascript_signals` - Global variables, DOM attributes, bundle patterns
- `html_signals` - Meta tags, script URLs, CSS classes
- `http_signals` - Headers (for SPA indicators)

## Technology Categories

### JavaScript Frameworks

| Technology | Detection Signals | Weight |
|------------|-------------------|--------|
| React | window.React, data-reactroot, /_next/ | 30-40 |
| Vue.js | window.Vue, data-v-*, /_nuxt/ | 30-40 |
| Angular | ng-version, _ngcontent-*, window.ng | 30-40 |
| Svelte | window.__svelte, data-svelte-h | 30-35 |
| jQuery | window.jQuery, window.$ | 25-30 |
| Alpine.js | window.Alpine, x-data, x-init | 25-30 |

### Meta-Frameworks

| Technology | Detection Signals | Implies | Weight |
|------------|-------------------|---------|--------|
| Next.js | __NEXT_DATA__, /_next/static/ | React, Node.js | 35-40 |
| Nuxt.js | window.__NUXT__, /_nuxt/ | Vue.js, Node.js | 35-40 |
| Gatsby | window.___gatsby | React | 35-40 |
| Remix | __remixContext | React | 35-40 |
| SvelteKit | __sveltekit | Svelte | 35-40 |
| Astro | data-astro-* | - | 30-35 |

### CSS Frameworks

| Technology | Detection Signals | Weight |
|------------|-------------------|--------|
| Bootstrap | btn btn-*, container, navbar, col-* | 25-30 |
| Tailwind CSS | bg-*, text-*, flex, p-*, m-* | 25-30 |
| Material UI | MuiButton, MuiGrid, MuiPaper | 30-35 |
| Ant Design | ant-btn, ant-card, ant-table | 30-35 |
| Chakra UI | chakra-* classes | 25-30 |
| Foundation | button, callout, grid-x | 25-30 |
| Bulma | button is-*, columns, hero | 25-30 |

### UI Component Libraries

| Technology | Detection Signals | Weight |
|------------|-------------------|--------|
| Radix UI | data-radix-* | 25-30 |
| Headless UI | data-headlessui-* | 25-30 |
| shadcn/ui | Combination of Tailwind + Radix patterns | 20-25 |

### State Management

| Technology | Detection Signals | Weight |
|------------|-------------------|--------|
| Redux | window.__REDUX_DEVTOOLS_EXTENSION__ | 25-30 |
| MobX | window.__mobxGlobal | 25-30 |
| Zustand | Bundle patterns | 20-25 |
| Recoil | Bundle patterns | 20-25 |

### Build Tools (from bundle patterns)

| Technology | Detection Signals | Weight |
|------------|-------------------|--------|
| Webpack | /bundle.js, .chunk.js, /vendor.js | 20-25 |
| Vite | /@vite/, .js?v= | 25-30 |
| Parcel | /parcel-* | 20-25 |
| esbuild | Bundle patterns | 20-25 |
| Rollup | Bundle patterns | 20-25 |

## Inference Logic

```python
def infer_frontend_technologies(signals):
    results = []

    # JavaScript Framework Detection
    for framework in FRAMEWORK_PATTERNS:
        score = 0
        evidence = []

        # Check global variables
        for global_var in framework.globals:
            if global_var in signals.javascript_signals.globals:
                score += framework.global_weight
                evidence.append(f"{global_var} detected")

        # Check DOM attributes
        for attr in framework.dom_attributes:
            if attr in signals.html_signals.dom_attributes:
                score += framework.dom_weight
                evidence.append(f"{attr} attribute found")

        # Check bundle patterns
        for pattern in framework.bundle_patterns:
            if pattern in signals.javascript_signals.script_urls:
                score += framework.bundle_weight
                evidence.append(f"Bundle pattern: {pattern}")

        if score > 0:
            results.append({
                "name": framework.name,
                "category": framework.category,
                "signals": evidence,
                "total_weight": score,
                "implies": framework.implies
            })

    # CSS Framework Detection
    for css_framework in CSS_FRAMEWORK_PATTERNS:
        matches = count_class_matches(
            signals.html_signals.css_classes,
            css_framework.patterns
        )

        if matches >= css_framework.min_matches:
            score = css_framework.base_weight + (matches * 2)
            results.append({
                "name": css_framework.name,
                "category": "CSS Framework",
                "signals": [f"{matches} class patterns matched"],
                "total_weight": score
            })

    return results
```

## Output

```json
{
  "skill": "frontend_inferencer",
  "results": {
    "technologies": [
      {
        "name": "React",
        "category": "JavaScript Framework",
        "version": "18.x (if detectable)",
        "signals": [
          {
            "type": "javascript_global",
            "value": "window.React detected",
            "source": "https://example.com",
            "weight": 30
          },
          {
            "type": "dom_attribute",
            "value": "data-reactroot found",
            "source": "https://example.com",
            "weight": 25
          }
        ],
        "total_weight": 55,
        "implies": []
      },
      {
        "name": "Next.js",
        "category": "Meta-Framework",
        "version": "13.x",
        "signals": [
          {
            "type": "javascript_global",
            "value": "__NEXT_DATA__ found",
            "source": "https://example.com",
            "weight": 35
          },
          {
            "type": "bundle_pattern",
            "value": "/_next/static/ paths",
            "source": "https://example.com",
            "weight": 30
          }
        ],
        "total_weight": 65,
        "implies": ["React", "Node.js"]
      },
      {
        "name": "Tailwind CSS",
        "category": "CSS Framework",
        "signals": [
          {
            "type": "css_classes",
            "value": "15 Tailwind class patterns matched (bg-*, text-*, flex, p-*, etc.)",
            "source": "https://example.com",
            "weight": 30
          }
        ],
        "total_weight": 30
      }
    ],
    "implied_technologies": [
      {
        "name": "Node.js",
        "implied_by": ["Next.js"],
        "confidence": "High"
      }
    ],
    "summary": {
      "primary_framework": "Next.js",
      "ui_library": "Tailwind CSS",
      "state_management": null,
      "build_tool": "Webpack (via Next.js)"
    }
  }
}
```

## Version Detection

### React
```javascript
// From __REACT_DEVTOOLS_GLOBAL_HOOK__
window.__REACT_DEVTOOLS_GLOBAL_HOOK__.renderers.get(1).version

// From React DevTools
window.React.version
```

### Angular
```html
<!-- From ng-version attribute -->
<app-root ng-version="16.2.0">
```

### Next.js
```javascript
// From __NEXT_DATA__
JSON.parse(document.getElementById('__NEXT_DATA__').textContent).nextVersion
```

### Vue.js
```javascript
// From Vue instance
window.Vue.version
```

## Confidence Calculation

```
Frontend Technology Confidence:

High (80-100%):
  - Direct framework global detected
  - Multiple supporting signals
  - Version information available

Medium (50-79%):
  - Bundle patterns match
  - DOM attributes present
  - No direct confirmation

Low (20-49%):
  - Only CSS class patterns
  - Single indirect signal
  - Job posting mention only
```

## Error Handling

- Missing signals: Return empty results for category
- Conflicting signals: Include both with notes
- Version detection failure: Omit version, continue
