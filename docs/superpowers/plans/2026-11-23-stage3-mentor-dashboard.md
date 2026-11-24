# Stage 3 Mentor Dashboard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a mentor-facing Stage 3 dashboard that organizes the scan story into useful, evidence-backed views beyond the graph.

**Architecture:** A dependency-free static web app with modular fixture data and client-side view rendering. A small adapter accepts imported JSON while the planned pipeline is not in this checkout.

**Tech Stack:** HTML, CSS, vanilla JavaScript, inline SVG.

**Spec:** `docs/superpowers/specs/2026-11-23-stage3-mentor-dashboard-design.md`

## Global Constraints
- Stage 3 reports understanding and coverage; it does not make risk verdicts.
- AI explanations and findings need evidence and confidence.
- No pipeline/API code exists in this checkout.
- Do not add dependencies or tests for this UI task.

## Review Focus
- Empty or malformed imported JSON should show a useful message instead of breaking navigation.
- Long module names and evidence paths must remain readable in narrow panels.
- Demo fixture must be clearly identified as demo data.
- Evidence and confidence should remain visible in detail views.
- Every major information class from the Stage 3 plan must have a navigable section.

## File Structure
- `ui/index.html`: application shell and navigation.
- `ui/styles.css`: responsive visual system and page layouts.
- `ui/app.js`: rendering, navigation, selection, and JSON import.
- `ui/data/demo-data.js`: replaceable demo dataset.
- `docs/superpowers/specs/...`: accepted design and scope.

### Task 1: Dashboard shell and demo data

**Files:** Create the four `ui/` files above.

**Interfaces:** `demoData` exports repository metadata, modules, graph edges, paths, packages, changes, findings, and coverage. `app.js` consumes that object and writes into `#app`.

- [x] Create a labeled demo fixture based on mini-shop, with evidence, confidence, and Stage 3 sections.
- [x] Create semantic application shell with sidebar navigation, repo selector/import control, and main content root.
- [x] Create responsive styling for desktop presentation and small screens.

### Task 2: Mentor-facing content views

**Files:** Modify `ui/app.js`, `ui/styles.css`.

**Interfaces:** Navigation keys: `overview`, `architecture`, `flows`, `dependencies`, `changes`, `findings`, `coverage`.

- [x] Render summary cards, repo explanation, recent changes, findings, and coverage on overview.
- [x] Render clickable module graph, module inventory, and selected node evidence panel.
- [x] Render route execution traces, package blast radius, time-travel changes, findings, and coverage as dedicated pages.
- [x] Keep node/package/finding detail inspectable with evidence and confidence.

### Task 3: Scan JSON import and handoff

**Files:** Modify `ui/app.js`, `ui/index.html`.

- [x] Accept a local JSON file and validate its top-level shape before replacing demo data.
- [x] Show a visible error for unsupported JSON and a success state for loaded input.
- [x] Add concise run instructions and explain where Stage 3 outputs map into the UI data adapter.
