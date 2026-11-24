# Stage 3 Mentor Dashboard Design

## Intent
Give a hackathon mentor one clear place to understand what the repository scan learned: its structure, how requests move through it, which packages matter, what changed, what needs investigation, and how complete the scan is.

## Goals
- Make the graph one view among several, with a repo summary and dedicated pages for architecture, flows, dependencies, changes, findings, and coverage.
- Keep claims tied to evidence, confidence, and source metadata where available.
- Make the demo useful before the Stage 1–2 pipeline exists, while keeping data replaceable by Stage 3 JSON output.
- Allow users to inspect a module, path, package, or finding without losing context.

## Non-goals
- Implement Stage 3 graph analysis, the FastAPI API, risk scoring, or the Stage 1–2 scanner.
- Claim demo fixture values came from a real scan.

## Constraints
- The checkout contains only planning documents; no app, pipeline source, or output JSON is available.
- Use a dependency-free static UI so it can be opened immediately and later served from the existing project.
- Start with a clearly labeled mini-shop demo fixture and a data module that can be replaced by API loading.

## Approaches
- **Chosen: static dashboard with modular demo data.** Fast to run in the current empty checkout, no build setup, and separates presentation from scan data.
- React/Vite app. Better for a larger connected application, but adds setup and dependencies before any app exists.
- Graph-only page. Quickest, but fails the stated mentor presentation need to segregate findings and evidence.

## Design
Use a persistent left navigation and a compact repo header. Overview presents scan status, key counts, a plain-language repo summary, top findings, recent changes, and coverage. Separate views cover architecture, request flows, dependency blast radius, time travel, findings, and coverage. The architecture view combines a clickable lightweight graph with a searchable module list and an evidence detail panel. All displayed content comes from `ui/data/demo-data.js`; UI rendering and navigation live in `ui/app.js` and `ui/styles.css`.

## Builder calls
- Use vanilla HTML/CSS/JavaScript and inline SVG for a portable no-install demo.
- Fixture content follows the mini-shop example in `docs/stage3.md`; values are illustrative until pipeline output is connected.
- Include JSON import as a basic handoff path for actual scan output, with graceful handling of unsupported shapes.
