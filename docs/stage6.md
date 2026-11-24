# Software Supply Chain Guardian: Stage 6 Build Plan
## Evidence & UI (Day 1, slide step 5 + the whole product experience)

**Version:** final v2 · **Depends on:** Stages 1–5 plans

> **Build rule: MVP first.** This doc describes the full product, but pages are tagged **P0 / P1 / Later** (section 4). Build **depth in the P0 pages first, not breadth across all pages.** Until an entity's full page exists, clicking it opens the **peek drawer**, so everything stays clickable from day one.

> **What Stage 6 does:** turns everything the guardian knows into a **clear, multi-page web app**. Every entity (module, file, package, route, vulnerability, anomaly, commit) has **its own page with its own URL**. Everything is clickable, and any page can be opened in a new tab.
>
> It answers the Day 1 checkpoint directly, with one page each: **"What is in the application?"** · **"What changed?"** · **"What appears risky?"**

---

## 1. UX principles (every page must follow these)

1. **Every name is a link.** Anywhere a package, file, function, module, route, finding or commit appears, it's an `EntityLink`. Click = go to its page. **Ctrl/Cmd-click or middle-click = new tab** (real `<a href>` links, not `onClick` only).
2. **Peek, then open.** Clicking a node in a graph opens a **side drawer (peek)** with the summary + an **"Open full page ↗"** button. This keeps users in context, and the full page is one click away.
3. **Every page has a URL.** Filters, selected tabs and graph focus live in the URL query (`?risk=high&tab=evidence`), so anything can be shared or bookmarked and back/forward works.
4. **Always know where you are.** Left sidebar (sections) + breadcrumbs (`Overview › Modules › payments › service.py`) + page title with entity type icon.
5. **Fact vs AI is always visible.** Facts show a neutral `Fact` badge. AI text shows an `AI · confidence 0.8` badge and a **"View evidence"** link. Users must never confuse a guess with a fact.
6. **Never rely on colour alone.** Risk chips always include text + icon (`▲ High`), not just orange.
7. **Graphs stay minimal.** At most ~30 nodes visible at once; the rest is collapsed into groups. Focus mode = show only the selected node + its neighbours. Every graph has a legend, zoom-to-fit, search and filter toggles.
8. **Three states everywhere:** loading skeleton, empty state with a helpful next action, and error state with retry.
9. **Global search (Ctrl/Cmd + K)** jumps to any package, file, function, route, CVE or commit.
10. **Keyboard friendly:** `j/k` to move through lists, `Enter` to open, `Esc` to close drawers.

---

## 2. Stack

| Purpose | Tool |
|---|---|
| App | **React + TypeScript + Vite** |
| Routing | **React Router** (one route per page; nested layouts) |
| Data | **TanStack Query** (caching, loading/error states) |
| Styling / components | **Tailwind CSS + shadcn/ui** (accessible: tabs, drawers, dialogs, command palette, tables) |
| Graphs (**one library for everything**) | **Cytoscape.js**: `cytoscape-fcose` for the architecture map (compound nodes = module boxes containing files); `breadthfirst` / `cytoscape-dagre` left-to-right layout for flow paths and blast radius; same wrapper for the time-travel diff overlay |
| Flow diagrams (optional, later) | React Flow **only if** Cytoscape layouts prove insufficient. Not required |
| Tables | **TanStack Table** (sorting, filtering, column toggle, virtualization) |
| Code viewer | **Shiki** or `prism-react-renderer` with line highlights + gutter markers |
| Charts | **Recharts** (small summary charts only) |
| Command palette | shadcn `Command` (cmdk) |
| Live scan progress | Server-Sent Events from FastAPI |
| Backend | **FastAPI** (all stage APIs behind one `/api` prefix) |

---

## 3. App layout

```
┌──────────────────────────────────────────────────────────────────────────┐
│ ◆ Guardian   repo: mini-shop ▾   commit: a1b2c3 (HEAD) ▾   [⌘K Search]  ⚙ │  top bar
├────────────┬─────────────────────────────────────────────────────────────┤
│ Overview   │ Overview › Findings › F-007                                 │  breadcrumbs
│ Map        │                                                             │
│ Flows      │                 PAGE CONTENT                                │
│ Packages   │                                                             │
│ Supply     │                                     ┌───────────────────┐   │
│   chain    │                                     │ Peek drawer       │   │
│ Changes    │                                     │ (on graph click)  │   │
│ Findings 12│                                     │ [Open full page ↗]│   │
│ Review   3 │                                     └───────────────────┘   │
│ Report     │                                                             │
└────────────┴─────────────────────────────────────────────────────────────┘
```
- Sidebar badges show counts (open findings, pending reviews).
- The commit selector in the top bar switches the whole app to a past snapshot (time travel); a banner says *"Viewing commit x (5 days ago). Return to HEAD."*
- **Immutable scan snapshots:** every scan is stored under its own `scan_id` and commit (`output/scans/<scan_id>/` with all Stage 1–5 results) and is **never overwritten**. The commit selector **switches between stored snapshots**; it never checks out Git or triggers a rescan. The Changes page compares two stored snapshots (A vs B). If a commit has no stored snapshot, the selector shows *"Not scanned. Scan this commit?"*

---

## 4. Pages and routes

All routes are under `/scans/:scanId`. Each one is a separate page.

| # | Page | Route | Answers | Priority |
|---|---|---|---|---|
| 0 | **Start / scans list** | `/` | Start a scan, open the demo scan, see past scans | **P0** |
| 1 | **Scan progress** | `/scans/:id/progress` | What stage is running | **P0** |
| 2 | **Overview** | `/scans/:id` | The 3 checkpoint questions at a glance | **P0** |
| 3 | **Architecture map** | `/scans/:id/map` | What's in the app (modules) | **P0** |
| 11 | **Changes (time travel)** | `/scans/:id/changes?from=&to=` | What changed | **P0** |
| 13 | **Findings inbox** | `/scans/:id/findings` | What appears risky | **P0** |
| 14 | **Finding (evidence)** | `/scans/:id/findings/:findingId` | Slide step 5, fully | **P0** |
| 4 | **Module** | `/scans/:id/modules/:moduleId` | What one module does and uses | P1 |
| 5 | **File** | `/scans/:id/files/*path` | Code with annotations | P1 |
| 9 | **Package** | `/scans/:id/packages/:purl` | One component, fully explained | P1 |
| 7 | **Flows** | `/scans/:id/flows` and `/flows/:entryId` | How requests travel | P1 |
| 15 | **Review queue** | `/scans/:id/review` | Human decisions needed | P1 |
| 8 | **Packages (SBOM)** | `/scans/:id/packages` | Every component | P1 |
| 10 | **Supply chain** | `/scans/:id/supply-chain` | CI workflows, actions, images, indexes (origins) | Later |
| 6 | **Function** | `/scans/:id/functions/:fnId` | Callers, callees, sinks | Later (peek drawer until then) |
| 12 | **Commit** | `/scans/:id/commits/:sha` | One commit's impact | Later (peek drawer until then) |
| 16 | **Report** | `/scans/:id/report` | Printable / exportable summary | Later (JSON + SBOM download in P0) |
| 17 | **Coverage** | `/scans/:id/coverage` | What we did and didn't understand | Later (coverage strip on Overview in P0) |

Review actions (Confirm / Dismiss / Override) are available **on the Finding page in P0**; the dedicated Review queue page is P1.

---

## 5. Page specs

### 0. Start / scans list `/`
- Input: Git URL or local path + optional baseline commit → **Scan** button.
- Table of past scans: repo, commit, date, findings by risk, status. Row → Overview.
- Empty state: "Try the demo repo" button (runs mini-shop).

### 1. Scan progress `/scans/:id/progress`
- Vertical stepper: Stage 1 Facts → 2 Code → 3 Knowledge (3A/3B/3C/3D) → 4 Vulnerabilities → 5 Anomalies, each with status, duration and counts (*"Parsed 9/9 files"*, *"Investigating 3 of 7 vulns"*).
- **Live investigation activity feed (SSE)**: the **actions** the agents take and what they found, e.g. *"Advisory parsed → vulnerable function `yaml.load`"*, *"Graph queried → 4 references, 2 caller paths"*, *"Evidence verified → 2 references confirmed, reachability unresolved"*. **Never show the model's private reasoning text**, only tool calls, results and decisions.
- Each stage's results unlock as they finish (links appear). Auto-redirect to Overview when done.

### 2. Overview `/scans/:id`
Three big cards matching the checkpoint, each linking to its page:
- **What's in it:** repo AI card (purpose), modules count, packages (direct/transitive), routes, external services, tables. → *Map*, *Packages*
- **What changed:** since baseline: +/− packages, version bumps, new modules, new outbound domains. → *Changes*
- **What looks risky:** findings by project risk (Critical/High/Medium/Low), pending reviews, top 5 findings list. → *Findings*

Below that: a small "Top risky components" table (package, risk, radius, vulns, anomalies), and a coverage strip (*"Understood 94% of calls · 1 dynamic import"* → Coverage).

### 3. Architecture map `/scans/:id/map`
- Cytoscape graph: **modules as boxes** (size = files, border colour = highest risk inside), arrows = `DEPENDS_ON` (thickness = weight). External services, tables and public routes as small side nodes.
- Toolbar: layout reset, search node, toggles (show packages / services / tables / tests), **"colour by"**: risk · sensitivity · changed recently.
- Click module → **peek drawer**: AI purpose card, counts, top risks, *Open full page ↗*. Double-click → expand into its files inside the box.
- Legend fixed bottom-left.

### 4. Module `/scans/:id/modules/:moduleId`
- Header: name, tags (`sensitive`, `public-facing`, `core`), risk chip.
- **AI card** (purpose, responsibilities, inputs, outputs, data touched) with evidence links.
- Tabs: **Files** (table) · **Packages used** (with API calls, e.g. `yaml.load`) · **Depends on / Used by** (mini graph) · **Routes** · **Data & secrets** (tables, env vars, external services) · **Findings** · **History** (commits touching it).

### 5. File `/scans/:id/files/*path`
- Code viewer with gutter markers: 🟦 import, 🟨 env read, 🟥 vuln usage site, 🟧 anomaly, 🟩 route, ⬛ DB write, 🌐 network.
- Hover marker → tooltip; click → the related entity page.
- Right panel: file AI card (if any), imports list, functions list (links), findings touching this file.
- URL supports `#L12-L18` to highlight lines (used by every evidence link).

### 6. Function `/scans/:id/functions/:fnId`
- Signature, docstring, lines (link to file view).
- **Callers ← · → Callees** two-column mini graph.
- Sinks reached (tables, services, env vars, package APIs), input sources, paths it appears in, findings.

### 7. Flows `/scans/:id/flows` → `/flows/:entryId`
- List: every route / CLI / startup entry with method, path, number of sinks reached, highest risk.
- Flow page: **left-to-right diagram (Cytoscape dagre/breadthfirst layout)**: `POST /checkout (request.json)` → `checkout()` → `charge()` → [Stripe] [orders] [STRIPE_KEY]. Nodes coloured by risk; vulnerable usage sites marked.
- Click a node → peek; edges show file:line on hover.

### 8. Packages (SBOM) `/scans/:id/packages`
- TanStack Table: name, version, direct/transitive, dev/runtime, origin (PyPI/VCS/other index), introduced via (direct dep), used by (# files), blast radius, vulns (count + max), anomalies, **project risk**.
- Filters: risk, direct/transitive, has vulns, has anomalies, unused, changed recently. Quick toggles at the top.
- Buttons: **Download SBOM (CycloneDX)** · Export CSV.

### 9. Package `/scans/:id/packages/:purl`
Header: name@version, risk chip, badges (`direct`, `runtime`, `typosquat?`, `unused`).
Tabs:
- **Overview:** origin (PyPI URL, source repo, maintainers, release date, first release), why it's here (manifest line / required-by chain)
- **Dependency tree:** what pulls it in ↑ and what it pulls in ↓ (collapsible tree)
- **Where it's used:** files → functions → API calls (`yaml.load` at `config/load.py:12`)
- **Blast radius:** graph from package → functions → modules → routes/secrets/tables, plus a plain-English summary
- **Vulnerabilities:** list → finding pages
- **Anomalies:** list → finding pages
- **History:** version over time (timeline), commits that changed it

### 10. Supply chain `/scans/:id/supply-chain`
Covers "where components originate" + "inspect a container image or CI/CD workflow":
- **Sources:** package indexes in use, VCS/URL dependencies
- **CI/CD:** each workflow → triggers, permissions, actions (pinned by SHA ✓/✗), risky steps
- **Containers:** base images (digest pinned ✓/✗), OS-level vulns from Grype, shadow installs
- Every row links to its finding if one exists.

### 11. Changes (time travel) `/scans/:id/changes?from=&to=`
- **Commit timeline slider** at the top (dependency-relevant commits as dots; drag from/to).
- Left: **diff list** grouped as Packages (+ added / − removed / ↑ version) · Modules · Code behaviour (new domains, new secrets) · Lockfile · CI · Images.
- Right: **graph diff**. The architecture map overlaid with green = added, red = removed, amber = changed.
- Each item links to the commit page and any related finding.

### 12. Commit `/scans/:id/commits/:sha`
- Author, date, message; dependency/code changes in this commit; findings introduced by it; "View repo at this commit" (switches the global commit selector).

### 13. Findings inbox `/scans/:id/findings`
- **One list for vulnerabilities + anomalies.**
- Columns: ID, type (Vuln/Anomaly icon), title, component, **project risk**, severity/suspicion, confidence, usage, reachability, review status, detected at.
- Left filter panel: risk, type, confidence, review status, scope (runtime/dev/container/CI), "new in last diff".
- Default sort: project risk ↓, then confidence ↓.
- `j/k` + `Enter` keyboard navigation; row click → finding page; Cmd-click → new tab.

### 14. Finding (evidence) `/scans/:id/findings/:findingId` ⭐ **the most important page**
Sections named **exactly like slide step 5**, so judges can tick them off:

```
┌──────────────────────────────────────────────────────────────────────────┐
│ F-007  PyYAML unsafe loading     ▲ High (project)  CVSS 9.8  Conf: Medium │
│ [Confirm] [Dismiss…] [Override…]               review: pending ●          │
├──────────────────────────────────────────────────────────────────────────┤
│ 1. What was detected     plain-English explanation (AI badge + evidence)  │
│ 2. Which component       pyyaml@5.3.1 → package page · fix: upgrade 5.4   │
│ 3. Dependency path       requirements.txt:3 → pyyaml  (mini diagram)      │
│ 4. Supporting evidence   tabs: Code · Flow · Advisory · Metadata · Commit │
│ 5. Initial risk level    High: rule #4 fired; reasons listed; CVSS shown  │
│                          separately; confidence + why                     │
├──────────────────────────────────────────────────────────────────────────┤
│ ▸ How the agent investigated (timeline of tool calls + results)           │
│ ▸ Recommendation  (Day 2 will act on this)                                │
└──────────────────────────────────────────────────────────────────────────┘
```
- **Code tab:** embedded snippet with highlighted lines, plus "Open file ↗" (`/files/...#L12`).
- **Flow tab:** the path diagram from the entry point to the usage site (or "No path found", with the honest caveat text).
- **Advisory tab:** IDs, aliases, affected ranges, fixed versions, links (vulns); or detector rule + signal data (anomalies).
- **Investigation activity timeline:** each step = action (e.g. *Advisory parsed*, *Graph queried*, *Code read*, *Evidence verified*), tool input, short result, time, plus the final decision and which rule fired. Collapsible. **Actions and evidence only, never the model's private reasoning.** This is the "agentic" proof for judges.
- For **anomalies**: the signals list (each with detector, rule, evidence), **capability** vs **exposure**, and the normal-explanation check result.
- **Review actions** open a dialog (reason required for dismiss/override). After a decision the badge updates and the item leaves the review queue.

### 15. Review queue `/scans/:id/review`
- Only findings paused by the workflow (downgrade guard, low confidence, critical confirm).
- Split view: list on the left, finding evidence on the right; **Confirm / Dismiss / Override** without leaving the page; next item loads automatically.

### 16. Report `/scans/:id/report`
- Print-friendly page: repo summary, checkpoint answers, findings table, top 5 findings with evidence, coverage, review decisions.
- Exports: **PDF** (browser print), **JSON**, **CycloneDX SBOM**, and optionally **SARIF** (so findings can appear in GitHub code scanning).

### 17. Coverage `/scans/:id/coverage`
- Files parsed, calls resolved, modules/files carded, questions resolved/unresolved, known unknowns (dynamic imports, unparsed files), each linking to the place.

---

## 6. Shared components (build these first)

| Component | Used everywhere for |
|---|---|
| `EntityLink` | any entity → its page; icon by type; real `<a href>` (new-tab works) |
| `RiskChip`, `SeverityChip`, `ConfidenceChip` | consistent colours + text + icon |
| `FactBadge` / `AIBadge` | trust indicator; `AIBadge` shows confidence + "View evidence" |
| `EvidenceList` | code / path / advisory / commit / metadata evidence items, each a link |
| `CodeSnippet` | highlighted lines + "Open file ↗" |
| `PeekDrawer` | side drawer with entity summary + "Open full page ↗" |
| `GraphView` | Cytoscape wrapper: legend, search, focus mode, colour-by, toggles |
| `FlowView` | same Cytoscape wrapper with a left-to-right layout preset |
| `ActivityTimeline` | investigation actions + results (progress page and finding page) |
| `DataTable` | TanStack Table wrapper with URL-synced filters |
| `Breadcrumbs`, `PageHeader`, `EmptyState`, `ErrorState`, `Skeleton` | consistency |
| `CommandPalette` | ⌘K global search via `/api/search?q=` |

### Visual language
- Risk: **Critical** red · **High** orange · **Medium** amber · **Low** slate. Always with label + icon.
- Entity icons: module ▣ · file 📄 · function ƒ · package 📦 · route ⇢ · table ⛁ · service ☁ · secret 🔑 · commit ⎇ · finding ⚠ (use an icon library such as `lucide-react`, not emoji).
- Light + dark mode; one accent colour; generous spacing; max ~1200 px content width for text pages; graphs full width.

---

## 7. Backend API (FastAPI, one place for the UI)

### 7.1 Contracts first
Agree on these **shared object schemas** (Pydantic → OpenAPI → TypeScript) **before** splitting work: `Entity` (any node: id, type, name, attrs, card, badges) · `GraphView` (nodes, edges, groups) · `Finding` (unified vuln/anomaly) · `Evidence` · `Change` · `ActivityStep` · `ScanSnapshot`.

### 7.2 MVP endpoints (P0, build only these first)
| Endpoint | Used by |
|---|---|
| `GET /api/scans` · `POST /api/scans` | Start |
| `GET /api/scans/:id/progress/events` (SSE) | Progress |
| `GET /api/scans/:id/overview` | Overview |
| `GET /api/scans/:id/graph?level=repo\|module&id=` | Map |
| `GET /api/scans/:id/entity/:entityId` | **peek drawer for every entity type** (generic) |
| `GET /api/scans/:id/findings` · `GET /api/scans/:id/findings/:id` | Findings, Finding |
| `POST /api/scans/:id/review/:findingId` | Finding (review actions) |
| `GET /api/compare?from=:scanA&to=:scanB` | Changes |

### 7.3 Full endpoint list (add **only when the page that needs it is built**)
Specialized endpoints split out of the generic `entity` endpoint as P1/Later pages arrive:

| Endpoint | Used by page |
|---|---|
| `POST /api/scans` · `GET /api/scans` | 0 |
| `GET /api/scans/:id/events` (SSE) | 1 |
| `GET /api/scans/:id/overview` | 2 |
| `GET /api/scans/:id/graph?level=repo\|module&id=` | 3, 4 |
| `GET /api/scans/:id/node/:nodeId` | peek drawer, 4, 5, 6 |
| `GET /api/scans/:id/files/:path` (source + markers) | 5 |
| `GET /api/scans/:id/functions/:fnId` | 6 |
| `GET /api/scans/:id/flows` · `/flows/:entryId` | 7 |
| `GET /api/scans/:id/packages` · `/packages/:purl` · `/blast-radius/:purl` | 8, 9 |
| `GET /api/scans/:id/supply-chain` | 10 |
| `GET /api/scans/:id/changes?from=&to=` · `/commits/:sha` | 11, 12 |
| `GET /api/scans/:id/findings` · `/findings/:id` (incl. investigation trace) | 13, 14 |
| `GET /api/scans/:id/review` · `POST /api/scans/:id/review/:findingId` | 15 |
| `GET /api/scans/:id/report?format=json\|sarif\|cyclonedx` | 16 |
| `GET /api/scans/:id/coverage` | 17 |
| `GET /api/scans/:id/search?q=` | ⌘K |

Each page calls **one main endpoint** that returns exactly what it needs (aggregate on the server, not the browser).

---

## 8. Frontend folder structure

```
ui/src/
  app/            router.tsx  layout/(Sidebar, TopBar, Breadcrumbs)
  pages/          Start, Progress, Overview, Map, Module, File, Function, Flows, Flow,
                  Packages, Package, SupplyChain, Changes, Commit, Findings, Finding,
                  Review, Report, Coverage
  components/     EntityLink, chips, badges, EvidenceList, CodeSnippet, PeekDrawer,
                  GraphView, FlowView, DataTable, CommandPalette, states
  api/            client.ts, hooks (TanStack Query per endpoint), types.ts (from Pydantic via OpenAPI)
  lib/            risk.ts, icons.ts, url-state.ts
```
Generate TypeScript types from FastAPI's OpenAPI schema (`openapi-typescript`) so the frontend and backend never drift.

---

## 9. Build order (first end-to-end product as early as possible)

1. **App shell + mock data + entity types**: routing, layout, chips, evidence components, peek drawer, mock JSON from the mini-shop expected outputs.
2. **Overview + Findings + Finding page**: the complete Day 1 checkpoint experience on mocks.
3. **Backend connected**: replace mocks with real scan results; unified finding schema.
4. **Architecture graph + entity peek drawer**.
5. **File + Module detail**: code evidence, responsibilities, relationships, sensitivity.
6. **Changes / time travel**: compare stored snapshots, graph diff overlay.
7. **Activity timeline + review flow**: actions, evidence, verification, human decisions; Progress page with SSE.
8. **Package / Packages / Flows / Review queue / Supply chain**.
9. **Exports, coverage, ⌘K search, keyboard, polish.**

## 9.1 Demo reliability: precomputed scan + live scan

Prepare a **completed, stored mini-shop scan** (`output/scans/demo-minishop-head/` + `demo-minishop-baseline/`) containing:
- a confirmed vulnerable dependency (with verified evidence + review decision)
- a suspicious package (typosquat with install-hook capability, exposure `install_path`)
- an unexpected package (`colorama`)
- a suspicious network call (`send_event()` → new domain)
- a public route reaching a sensitive function (`/checkout` → payments → Stripe / orders / STRIPE_KEY)
- a before/after commit comparison
- an investigation activity timeline with verified evidence

Start page shows **"Open demo scan"** (loads instantly, with no LLM/OSV/network needed) and **"Run live scan"** (real pipeline with live progress). If anything is slow or down during judging, the demo still works.

---

## 10. Who does what

| Person | Owns |
|---|---|
| **UI Dev 1** | layout, routing, shared components, Overview, Findings, Finding, Review |
| **UI Dev 2** | GraphView/FlowView, Map, Module, File, Function, Flows, Changes |
| **Backend dev** | FastAPI aggregation endpoints, SSE, search, exports, OpenAPI types |
| **Lead** | Packages, Package, Supply chain, Report, demo script, final polish |

---

## 11. 3-minute demo script (mini-shop)

1. **Start** → **Run live scan** on mini-shop → **Progress**: stages + live investigation activity. (If slow: **Open demo scan** instead and continue.)
2. **Overview**: the three checkpoint cards.
3. **Map**: modules; click `payments` → peek → open full page (sensitive, Stripe, STRIPE_KEY, orders).
4. **Flows** → `/checkout`: path to Stripe, orders, the secret, and the new external domain.
5. **Changes**: slide baseline → HEAD: `+colorama`, `+utils`, new domain, `reqeusts` typosquat.
6. **Findings** → open the typosquat finding: evidence + agent timeline → **Confirm**.
7. **Finding** PyYAML: *CVSS 9.8, but project risk High, confidence Medium, no public path*; show why + the human review.
8. **Report** → export PDF + SBOM.

---

## 12. Definition of done

**Day 1 (P0):**
- [ ] All P0 pages exist at their own routes and load real scan data (no mocks left)
- [ ] Every entity is clickable: full page if built, otherwise peek drawer
- [ ] Precomputed demo scan opens instantly with no network; live scan works end-to-end
- [ ] Changes page compares two stored snapshots; nothing is overwritten
- [ ] Finding page: all 5 slide-step-5 sections + activity timeline + review actions
- [ ] Progress and timelines show actions/results only, no private model reasoning

**Full product (P1 + Later):**
- [ ] Every page in section 4 exists at its own route and loads from the API
- [ ] Every entity mention is an `EntityLink`; Cmd/Ctrl-click opens a new tab everywhere
- [ ] Graph clicks open the peek drawer with "Open full page ↗"
- [ ] Filters/tabs/selection survive refresh and back/forward (URL state)
- [ ] Finding page shows all 5 slide-step-5 sections + agent timeline + review actions
- [ ] AI vs fact badges on every AI text; risk chips have text + icon
- [ ] Loading / empty / error states on every page
- [ ] ⌘K search finds packages, files, functions, routes, CVEs, commits
- [ ] Demo script runs end-to-end in under 3 minutes