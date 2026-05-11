---
name: techstack-frontend
description: Frontend tech-stack identification — JavaScript frameworks, meta-frameworks, CSS frameworks, UI libraries, build tools, and CMS via DOM, JS globals, HTML, and bundle patterns.
---

# Frontend Tech-Stack Identification

## Scope

Identify client-side technologies: JavaScript frameworks (React, Vue, Angular, Svelte), meta-frameworks (Next.js, Nuxt, Gatsby, Remix), CSS frameworks (Tailwind, Bootstrap, Material UI), state management, build tools, CMS generators, and analytics SDKs from rendered HTML/JS.

## Signals (input)

- HTTP response bodies (HTML)
- JavaScript global variables (`window.*`)
- DOM attributes (`data-*`, `ng-*`, `_ngcontent-*`)
- Script src URL patterns (`/_next/`, `/wp-content/`, etc.)
- `<meta name="generator">` tags
- HTML comments
- CSS class patterns
- JSON-LD / structured data
- Source map exposure

## Inferences (output)

- JS framework + version (e.g. React 18.2)
- Meta-framework (implies host framework — Next.js → React)
- CMS / static site generator (WordPress, Drupal, Hugo, Ghost)
- CSS framework + UI library
- Build tool (Webpack, Vite, Parcel)
- Analytics / tracking SDKs (GA, Mixpanel, Hotjar, FullStory)
- Source map exposure (security finding)

## Techniques

See [reference/patterns.md](reference/patterns.md).

## When to use

- Phase 2/3 of a tech-stack OSINT engagement
- Mapping client-side attack surface for XSS / DOM-based testing
- Validating CMS/version for CVE matching
- Identifying SaaS dependencies via third-party scripts
