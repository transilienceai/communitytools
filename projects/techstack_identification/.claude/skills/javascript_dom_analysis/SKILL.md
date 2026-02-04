---
name: javascript-dom-analysis
description: Detects frontend frameworks via global variables, DOM attributes, and bundle patterns
tools: Bash, WebFetch
model: inherit
hooks:
  PreToolUse:
    - matcher: "WebFetch"
      hooks:
        - type: command
          command: "../../../hooks/skills/pre_network_skill_hook.sh"
        - type: command
          command: "../../../hooks/skills/pre_rate_limit_hook.sh"
  PostToolUse:
    - matcher: "WebFetch"
      hooks:
        - type: command
          command: "../../../hooks/skills/post_evidence_capture_hook.sh"
---

# JavaScript/DOM Analysis Skill

## Purpose

Detect frontend frameworks and libraries by analyzing JavaScript global variables, DOM attributes, bundle patterns, and source maps.

## Operations

### 1. detect_framework_globals

Check for framework-specific global variables in page context.

**Global Variable Patterns:**
```json
{
  "React": {
    "globals": ["window.React", "window.ReactDOM", "__REACT_DEVTOOLS_GLOBAL_HOOK__"],
    "confidence": 90,
    "category": "JavaScript Framework"
  },
  "Vue.js": {
    "globals": ["window.Vue", "window.__VUE__", "__VUE_DEVTOOLS_GLOBAL_HOOK__"],
    "confidence": 90,
    "category": "JavaScript Framework"
  },
  "Angular": {
    "globals": ["window.getAllAngularRootElements", "window.ng?.coreTokens", "window.ng?.probe"],
    "confidence": 90,
    "category": "JavaScript Framework"
  },
  "Next.js": {
    "globals": ["__NEXT_DATA__", "__NEXT_LOADED_PAGES__", "next/router"],
    "confidence": 95,
    "implies": ["React", "Node.js"],
    "category": "Meta-Framework"
  },
  "Nuxt": {
    "globals": ["window.__NUXT__", "window.$nuxt"],
    "confidence": 95,
    "implies": ["Vue.js", "Node.js"],
    "category": "Meta-Framework"
  },
  "Gatsby": {
    "globals": ["window.___gatsby", "window.___emitter"],
    "confidence": 95,
    "implies": ["React"],
    "category": "Static Site Generator"
  },
  "Svelte": {
    "globals": ["window.__svelte"],
    "confidence": 90,
    "category": "JavaScript Framework"
  },
  "jQuery": {
    "globals": ["window.jQuery", "window.$"],
    "confidence": 85,
    "category": "JavaScript Library"
  },
  "Backbone.js": {
    "globals": ["window.Backbone"],
    "confidence": 90,
    "category": "JavaScript Framework"
  },
  "Ember.js": {
    "globals": ["window.Ember", "window.Em"],
    "confidence": 90,
    "category": "JavaScript Framework"
  },
  "Alpine.js": {
    "globals": ["window.Alpine"],
    "confidence": 90,
    "category": "JavaScript Framework"
  }
}
```

### 2. analyze_dom_attributes

Find framework-specific DOM attributes.

**DOM Attribute Patterns:**
```json
{
  "data-reactroot": {"tech": "React", "confidence": 90},
  "data-reactid": {"tech": "React (legacy)", "confidence": 85},
  "data-react-checksum": {"tech": "React (server-rendered)", "confidence": 90},
  "data-v-": {"tech": "Vue.js (scoped CSS)", "confidence": 90, "note": "Vue SFC"},
  "ng-version": {"tech": "Angular", "confidence": 95, "extract_version": true},
  "ng-app": {"tech": "AngularJS", "confidence": 90},
  "ng-controller": {"tech": "AngularJS", "confidence": 90},
  "_ngcontent-": {"tech": "Angular", "confidence": 90},
  "_nghost-": {"tech": "Angular", "confidence": 90},
  "data-svelte-h": {"tech": "Svelte", "confidence": 90},
  "x-data": {"tech": "Alpine.js", "confidence": 90},
  "x-init": {"tech": "Alpine.js", "confidence": 85},
  "data-ember-action": {"tech": "Ember.js", "confidence": 90},
  "data-turbo": {"tech": "Hotwire/Turbo", "confidence": 90},
  "data-stimulus-controller": {"tech": "Stimulus", "confidence": 90}
}
```

### 3. fingerprint_bundles

Analyze JavaScript file naming patterns and paths.

**Bundle Pattern Detection:**
```json
{
  "/_next/static/": {"tech": "Next.js", "confidence": 95},
  "/_nuxt/": {"tech": "Nuxt.js", "confidence": 95},
  "/static/js/main.": {"tech": "Create React App", "confidence": 85},
  "/static/js/[0-9]+.": {"tech": "Webpack (chunked)", "confidence": 70},
  "/build/": {"tech": "Generic build tool", "confidence": 50},
  "/dist/": {"tech": "Generic bundler", "confidence": 50},
  "/assets/": {"tech": "Rails/Generic", "confidence": 40},
  "/bundle.js": {"tech": "Webpack", "confidence": 60},
  "/vendor.js": {"tech": "Webpack (vendor chunk)", "confidence": 60},
  ".chunk.js": {"tech": "Code splitting", "confidence": 70},
  "/wp-content/": {"tech": "WordPress", "confidence": 95},
  "/wp-includes/": {"tech": "WordPress", "confidence": 95}
}
```

**Version Extraction:**
```
Next.js: /_next/static/chunks/main-[hash].js → Version in __NEXT_DATA__
React: Detect version from React DevTools hook or package
Angular: Extract from ng-version attribute
```

### 4. check_source_maps

Test for exposed source map files.

**Process:**
1. For each JavaScript file found
2. Check for `.map` suffix or `sourceMappingURL` comment
3. If accessible, note as security finding
4. Extract original file names if available

**Source Map URLs:**
```
{script}.js.map
{script}.min.js.map
sourceMappingURL={url}
```

### 5. detect_analytics

Find analytics and tracking libraries.

**Analytics Global Patterns:**
```json
{
  "Google Analytics": {
    "globals": ["gtag", "ga", "dataLayer", "_gaq"],
    "scripts": ["google-analytics.com", "googletagmanager.com"],
    "confidence": 95
  },
  "Facebook Pixel": {
    "globals": ["fbq", "_fbq"],
    "scripts": ["connect.facebook.net/en_US/fbevents.js"],
    "confidence": 95
  },
  "Mixpanel": {
    "globals": ["mixpanel"],
    "scripts": ["cdn.mxpnl.com", "mixpanel.com"],
    "confidence": 95
  },
  "Segment": {
    "globals": ["analytics"],
    "scripts": ["cdn.segment.com", "segment.io"],
    "confidence": 90
  },
  "Amplitude": {
    "globals": ["amplitude"],
    "scripts": ["cdn.amplitude.com"],
    "confidence": 95
  },
  "Heap": {
    "globals": ["heap"],
    "scripts": ["heap-analytics.com", "heapanalytics.com"],
    "confidence": 95
  },
  "Hotjar": {
    "globals": ["hj", "hjSiteSettings"],
    "scripts": ["static.hotjar.com"],
    "confidence": 95
  },
  "FullStory": {
    "globals": ["FS", "_fs_namespace"],
    "scripts": ["fullstory.com"],
    "confidence": 95
  }
}
```

## Output

```json
{
  "skill": "javascript_dom_analysis",
  "domain": "string",
  "results": {
    "pages_analyzed": "number",
    "frameworks_detected": [
      {
        "name": "React",
        "version": "18.2.0 (if detectable)",
        "category": "JavaScript Framework",
        "detection_method": "global_variable",
        "signal": "window.React detected",
        "confidence": 90
      }
    ],
    "dom_signals": [
      {
        "attribute": "data-reactroot",
        "element": "div#root",
        "tech": "React",
        "page": "https://example.com"
      }
    ],
    "bundle_analysis": {
      "bundler": "Webpack",
      "code_splitting": true,
      "meta_framework": "Next.js",
      "paths_found": ["/_next/static/chunks/"]
    },
    "source_maps": {
      "exposed": "boolean",
      "urls": ["array if exposed"],
      "security_note": "Source maps expose original source code"
    },
    "analytics_detected": [
      {
        "name": "Google Analytics",
        "detection_method": "script_url",
        "confidence": 95
      }
    ],
    "third_party_scripts": [
      {
        "domain": "string",
        "purpose": "analytics|ads|widgets|cdn"
      }
    ]
  },
  "evidence": [
    {
      "type": "js_global",
      "url": "string",
      "global": "string",
      "timestamp": "ISO-8601"
    },
    {
      "type": "dom_attribute",
      "url": "string",
      "attribute": "string",
      "element": "string"
    }
  ]
}
```

## Rate Limiting

- Page fetches: 10/minute
- JavaScript analysis: No limit (client-side)

## Error Handling

- JavaScript errors don't block analysis
- Continue with DOM analysis if JS detection fails
- Log parsing errors for debugging

## Security Considerations

- Only fetch and analyze public pages
- Do not execute fetched JavaScript
- Note source map exposure as security finding
- Log all fetches for audit
