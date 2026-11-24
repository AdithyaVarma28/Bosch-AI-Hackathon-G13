(() => {
  // ------------------------------------------------------------------ state
  let data = normalize(window.demoData);
  let mode = "static";            // static (file / imported) | serve (guardian serve) | web (guardian web: scans + links)
  let scanId = new URLSearchParams(location.search).get("scan");
  let scans = [];
  let N = new Map(), OUT = new Map(), IN = new Map(), FIND = new Map(), FLOW = new Map();
  let pollTimer = null;
  const srcCache = new Map();
  const app = document.querySelector("#app");

  // ------------------------------------------------------------------ helpers
  const esc = (s = "") => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const pct = (a, b) => b ? Math.round(a / b * 100) : 0;
  const RISK = { critical: 3, high: 2, medium: 1, low: 0 };
  const tag = (x, kind = "") => `<span class="tag ${kind}">${esc(x)}</span>`;
  const riskTag = r => r ? `<span class="risk-tag ${r}">${esc(r)}</span>` : "";
  const title = (eyebrow, heading, desc, action = "") => `<div class="page-heading"><div><div class="eyebrow">${eyebrow}</div><h1>${heading}</h1>${desc ? `<p>${desc}</p>` : ""}</div>${action}</div>`;
  const panel = (heading, sub, body, action = "", cls = "") => `<section class="panel ${cls}"><div class="panel-header"><div><h2>${heading}</h2>${sub ? `<p>${sub}</p>` : ""}</div>${action}</div>${body}</section>`;
  const link = (label, attrs, cls = "text-link") => `<button class="${cls}" ${attrs}>${label}</button>`;
  const nodeBtn = (id, label, extra = "") => `<button class="node-link" data-node="${esc(id)}">${esc(label || N.get(id)?.l || id)}${extra}</button>`;
  const short = (s, n) => (s = String(s ?? "")).length > n ? s.slice(0, n - 1) + "…" : s;
  const push = (m, k, v) => { if (!m.has(k)) m.set(k, []); m.get(k).push(v); };
  const byRisk = (a, b) => (RISK[b.risk] ?? -1) - (RISK[a.risk] ?? -1);
  const kindName = { module: "Module", file: "File", function: "Function", class: "Class", route: "HTTP route", cli: "CLI command", package: "Package", service: "External service", env: "Environment variable", table: "Database table", group: "Entry points" };

  function normalize(b) {
    if (!b) return b;
    b._stale = !b.explorer && !b.stack && location.protocol.startsWith("http");
    b.explorer ||= { nodes: [], edges: [] };
    b.security ||= { vulnerabilities: [], anomalies: [], hotspots: [], byRisk: {} };
    b.flows ||= { routes: [], narrative: [] };
    b.sbom ||= (b.packages || []).map(p => ({ id: p.name, name: p.name, version: p.version, purl: `pkg:pypi/${p.name}@${p.version}`, direct: p.direct, scope: p.dev ? "dev" : "prod", usedByFiles: p.files, functions: [], vulns: [], anomalies: [], radius: p.radius, reasons: p.reasons, routes: p.routes, nearby: p.nearby }));
    b.changes ||= []; b.findings ||= []; b.modules ||= []; b.repo ||= {};
    return b;
  }

  function buildIndex() {
    N = new Map(data.explorer.nodes.map(n => [n.id, n]));
    OUT = new Map(); IN = new Map();
    for (const [s, t, type, extra] of data.explorer.edges) { push(OUT, s, { id: t, type, extra }); push(IN, t, { id: s, type, extra }); }
    FIND = new Map();
    for (const v of data.security.vulnerabilities || []) FIND.set(v.id, v);
    for (const a of data.security.anomalies || []) FIND.set(a.id, a);
    for (const h of data.security.hotspots || []) FIND.set(h.id, { ...h, kind: "hotspot", risk: h.level, title: `${h.label} ${h.what.toLowerCase()}` });
    for (const n of data.security.notes || []) FIND.set(n.id, { ...n, kind: "note" });
    for (const c of data.security.code || []) FIND.set(c.id, c);
    FLOW = new Map((data.flows.routes || []).map(r => [r.id, r]));
  }
  const out = (id, ...types) => (OUT.get(id) || []).filter(e => !types.length || types.includes(e.type));
  const inc = (id, ...types) => (IN.get(id) || []).filter(e => !types.length || types.includes(e.type));
  const modName = id => N.get(id)?.l || (id || "").replace(/^module:/, "");
  const fnsOfModule = m => data.explorer.nodes.filter(n => (n.t === "function" || n.t === "class") && n.m === m);

  // ------------------------------------------------------------------ routing (#/view/tab?params)
  function route() {
    const [path, q] = location.hash.replace(/^#\/?/, "").split("?");
    const [view, tab] = (path || "overview").split("/");
    return { view: view || "overview", tab, p: new URLSearchParams(q || "") };
  }
  function go(view, tab, params = {}) {
    const q = new URLSearchParams(Object.entries(params).filter(([, v]) => v !== undefined && v !== null && v !== "")).toString();
    const h = `#/${view}${tab ? "/" + tab : ""}${q ? "?" + q : ""}`;
    if (location.hash === h) render(); else location.hash = h;
  }
  window.addEventListener("hashchange", render);

  // ------------------------------------------------------------------ render shell
  function render() {
    clearInterval(pollTimer); pollTimer = null;
    const r = route();
    document.querySelectorAll(".nav-item").forEach(el => el.classList.toggle("active", el.dataset.view === r.view));
    if (data) {
      document.querySelector("#side-repo").textContent = data.repo.name || "—";
      document.querySelector("#top-repo").textContent = data.repo.name || "—";
      document.querySelector("#repo-icon").textContent = (data.repo.name || "?").slice(0, 2).toUpperCase();
      document.querySelector("#repo-kind").textContent = `${data.repo.language || "Python"} repository`;
      document.querySelector("#scan-time").textContent = `${data.repo.commit || ""} · ${data.repo.scannedAt || ""}`;
      document.querySelector("#module-count").textContent = data.modules.length || "";
      const s = data.security, sec = (s.vulnerabilities?.length || 0) + (s.anomalies?.length || 0) + (s.code?.length || 0);
      document.querySelector("#risk-count").textContent = sec || "";
    }
    const pages = { overview: renderOverview, architecture: renderArchitecture, risk: renderRisk, security: renderRisk, remediate: renderRemediate, fixed: renderFixed, report: renderReport, scan: renderNewScan, progress: renderProgress };
    if (!data && !["scan", "progress"].includes(r.view)) { app.innerHTML = emptyState(); bind(); return; }
    app.innerHTML = (data?._stale ? `<div class="banner-warn stale"><b>The Guardian server is running an older version.</b> It was started before the dashboard was updated, so the graph, SBOM details and risk reports are missing. Stop it (Ctrl+C) and start it again: <code>python -m guardian.cli web --root output/scans</code>, then reload this page.</div>` : "") + (pages[r.view] || renderOverview)(r);
    bind(r);
    if (r.view === "architecture" && (r.tab || "graph") === "graph") afterGraph(r);
    if (r.view === "progress") startPolling(r.p.get("id"));
  }
  const emptyState = () => `${title("GUARDIAN", "No scan loaded", "")}<div class="panel empty-big"><p>Start a scan from a GitHub link or a local folder, or import a scan bundle.</p>${link("Start a scan →", 'data-goto="scan"', "primary-button")}</div>`;

  // ------------------------------------------------------------------ overview
  function renderOverview() {
    const r = data.repo, s = data.security, st = data.stack;
    const vulnPk = data.sbom.filter(p => p.vulns?.length).length;
    const br = s.byRisk || {};
    const totalSec = (s.vulnerabilities?.length || 0) + (s.anomalies?.length || 0);
    const metric = (label, value, foot, icon, tone, attrs) => `<button class="metric-card clickable" ${attrs}><div class="metric-top"><span>${label}</span><span class="metric-icon ${tone}">${icon}</span></div><div class="metric-value">${value}</div><div class="metric-foot">${foot}</div><span class="metric-go">→</span></button>`;
    const caps = [];
    if (r.routes) caps.push([`${r.routes} HTTP routes`, 'data-goto="architecture"', "blue"]);
    if (r.cli) caps.push([`${r.cli} CLI command${r.cli > 1 ? "s" : ""}`, 'data-goto="architecture"', "blue"]);
    (r.services || []).forEach(x => caps.push([`Talks to ${x}`, `data-node="svc:${esc(x)}"`, "amber"]));
    if (r.secrets) caps.push([`Reads ${r.secrets} secret${r.secrets > 1 ? "s" : ""}`, 'data-goto="architecture"', "violet"]);
    const narrative = (data.flows.narrative || []).map((n, i) => `<div class="story-step"><span class="story-num">${i + 1}</span><div><b>${esc(n.title)}</b><p>${esc(n.text)}</p>${refChips(n)}</div></div>`).join("");
    const top = [...(s.vulnerabilities || []).filter(v => (v.presence?.score || 0) >= 55), ...(s.anomalies || [])].sort((a, b) => sevNum(b) - sevNum(a)).slice(0, 5);
    const timeline = data.changes.slice(0, 3).map(ch => `<div class="timeline-row"><span class="timeline-dot ${ch.type}"></span><div><div class="timeline-title"><b>${esc(ch.title)}</b><span>${esc(ch.date)} · ${esc(ch.commit)}</span></div><p>${esc(ch.detail)}</p><div class="change-chips">${(ch.items || []).slice(0, 3).map(x => tag(x, "muted")).join("")}</div></div></div>`).join("");
    return `${title("REPOSITORY INTELLIGENCE", `${esc(r.name)} <span class='title-suffix'>at a glance</span>`, esc(short(r.about || r.summary, 420)), `<button class="primary-button" data-goto="architecture">Explore architecture <span>→</span></button>`)}
      ${data.warning ? `<div class="banner-warn"><b>Not a Python repository.</b> ${esc(data.warning)}</div>` : ""}
      <div class="repo-strip"><span class="repo-language"><span class="python-mark">${esc((r.language || "Py").slice(0, 2))}</span> ${esc(r.language || "Python")}</span><span class="strip-sep"></span><span>Branch <b>${esc(r.branch)}</b></span><span class="strip-sep"></span><span>Commit <code>${esc(r.commit)}</code></span><span class="strip-sep"></span><span>Scanned <b>${esc(r.scannedAt)}</b></span>${r.url ? `<span class="strip-sep"></span><a class="strip-link" href="${esc(r.url.replace(/\.git$/, ""))}" target="_blank" rel="noopener">${esc(r.url.replace(/^https:\/\//, "").replace(/\.git$/, ""))} ↗</a>` : ""}<span class="strip-status"><i></i> Analysis complete</span></div>
      <div class="metric-grid">
        ${metric("ENTRY POINTS", r.entryPoints ?? r.routes ?? 0, `${r.routes || 0} routes · ${r.cli || 0} CLI — see how requests flow`, "↗", "blue", 'data-goto="architecture"')}
        ${metric("YOUR CODE", r.files, `${r.functions} functions in ${r.modules} modules`, "ƒ", "violet", 'data-goto="architecture" data-tab="modules"')}
        ${metric("DEPENDENCIES", data.sbom.length, `${data.sbom.filter(p => p.direct).length} direct · ${vulnPk} with known vulnerabilities`, "⬡", "teal", 'data-goto="architecture" data-tab="sbom"')}
        ${metric("RISKS FOUND", totalSec, `<span class="sev-inline critical">${br.critical || 0} critical</span> <span class="sev-inline high">${br.high || 0} high</span> · ${(s.vulnerabilities || []).filter(v => (v.presence?.score || 0) >= 80).length} confirmed in code`, "⚑", "red", 'data-goto="risk"')}
      </div>
      <div class="overview-grid"><div class="overview-main">
        ${panel("What this repository does", "Purpose, capabilities and how it is put together", `<div class="summary-card"><div class="summary-icon">✳</div><div>${r.readme ? `<p>${esc(short(r.readme, 520))}</p>` : ""}${r.purpose ? `<p class="${r.readme ? "muted-p" : ""}">${esc(short(r.purpose.split(". Public entry points")[0], 260))}${r.purpose.includes("Public entry points") ? "." : ""}</p>` : ""}<div class="summary-meta">${caps.map(([t, a, k]) => `<button class="tag ${k} tag-btn" ${a}>${esc(t)}</button>`).join("")}</div></div></div>`)}
        ${st ? panel("Tech stack", "Detected from source files, dependency manifests, Dockerfiles and CI", stackHtml(st), link("Full SBOM →", 'data-goto="architecture" data-tab="sbom"')) : ""}
        ${narrative ? panel("How it works", "The application in a few steps — click a chip to open it in the graph", `<div class="story">${narrative}</div>`, link("Open graph →", 'data-goto="architecture"')) : ""}
      </div><div class="overview-side">
        ${panel("Security snapshot", `${s.packagesChecked || data.sbom.length} packages checked against the OSV database`, `${riskBar(br)}<div class="finding-list">${top.map(f => `<button class="finding-row" data-finding="${esc(f.id)}"><span class="risk-dot ${f.risk}"></span><span class="finding-copy"><b>${esc(short(f.kind === "vulnerability" ? `${f.package} ${f.version}: ${f.vulnId}` : f.title, 70))}</b><small>${esc(f.kind === "vulnerability" ? `${f.presence ? f.presence.label + " · " + f.presence.score + "%" : usageLabel(f)}` : "Suspicious: " + (f.suspicion || "") + " suspicion")}</small></span>${riskTag(f.risk)}</button>`).join("") || `<div class="empty-state small">No dependency findings in this scan.</div>`}</div>${(s.hotspots || []).length ? `<button class="hotspot-note" data-goto="risk" data-tab="suspicious"><b>${s.hotspots.length} code hotspot${s.hotspots.length > 1 ? "s" : ""}</b> in your own code (shell commands, network calls, …) — not in any vulnerability database →</button>` : ""}<div class="how-note">${link("Evidence report →", 'data-goto="risk" data-tab="evidence"')}</div>`, link("All findings →", 'data-goto="risk"'))}
        ${panel("Latest changes", "What moved in the most recent commits", `<div class="timeline">${timeline || `<div class="empty-state small">No history in this scan.</div>`}</div>`, link("History →", 'data-goto="risk" data-tab="suspicious"'))}
      </div></div>`;
  }
  function stackHtml(st) {
    const langs = (st.languages || []).slice(0, 5);
    const bar = langs.length ? `<div class="lang-bar">${langs.map((l, i) => `<i class="l${i}" style="width:${Math.max(l.pct, 1.5)}%" title="${esc(l.name)} ${l.pct}%"></i>`).join("")}</div><div class="lang-legend">${langs.map((l, i) => `<span><i class="l${i}"></i>${esc(l.name)} <small>${l.pct}% · ${l.files} files</small></span>`).join("")}</div>` : "";
    const groups = (st.groups || []).filter(g => g.name !== "Other libraries").map(g => `<div class="stack-group"><span class="stack-label">${esc(g.name)}</span><div class="stack-items">${g.items.slice(0, 6).map(x => `<button class="stack-item" data-pkg="${esc(x.id)}">${esc(x.name)} <small>${esc(x.version || "")}</small>${x.risk ? `<span class="risk-dot ${x.risk}"></span>` : ""}</button>`).join("")}${g.items.length > 6 ? `<span class="stack-more">+${g.items.length - 6}</span>` : ""}</div></div>`).join("");
    const infra = [...(st.services || []).map(s => `<button class="stack-item svc" data-node="${esc(s.id)}">${esc(s.name)}</button>`), ...(st.images || []).map(i => `<span class="stack-item img">🐳 ${esc(i.name)}</span>`), ...(st.ci || []).map(c => `<span class="stack-item ci">CI · ${esc(c.name)}</span>`)].join("");
    return `<div class="stack-body">${bar}${groups}${infra ? `<div class="stack-group"><span class="stack-label">Services & infrastructure</span><div class="stack-items">${infra}</div></div>` : ""}</div>`;
  }
  function riskBar(br) {
    const total = ["critical", "high", "medium", "low"].reduce((a, k) => a + (br[k] || 0), 0);
    if (!total) return `<div class="risk-bar empty"></div>`;
    return `<div class="risk-bar">${["critical", "high", "medium", "low"].map(k => br[k] ? `<i class="${k}" style="width:${br[k] / total * 100}%"></i>` : "").join("")}</div><div class="risk-legend">${["critical", "high", "medium", "low"].map(k => `<button data-goto="risk" data-risk="${k}"><i class="${k}"></i>${br[k] || 0} ${k}</button>`).join("")}</div>`;
  }
  const usageLabel = f => ({ symbol_called: "Vulnerable function is called in your code", package_used_symbol_not_found: "Package used; vulnerable function not found", imported: "Package imported", not_imported: "Installed but not imported", installed_unused: "Installed, never imported" })[f.usage] || (f.usage || "").replace(/_/g, " ");
  function refChips(n) {
    const chips = (n.refs || []).slice(0, 6).map(id => `<button class="ref-chip" data-node="${esc(id)}">${esc(N.get(id)?.l || id.replace(/^\w+:/, ""))}</button>`);
    if (n.finding) chips.push(`<button class="ref-chip danger" data-finding="${esc(n.finding)}">${esc(n.finding)}</button>`);
    return chips.length ? `<div class="ref-chips">${chips.join("")}</div>` : "";
  }

  // ------------------------------------------------------------------ architecture
  function renderArchitecture(r) {
    const tab = r.tab || "graph";
    const tabs = [["graph", "Security graph", data.explorer.nodes.length ? "" : ""], ["sbom", "SBOM", data.sbom.length], ["modules", "Modules", data.modules.length]];
    const head = title("STRUCTURAL MAP", "Architecture <span class='title-suffix'>& security</span>", "Follow how the code is put together and where the risky parts are. Every box can be clicked.", `<div class="tabs">${tabs.map(([k, l, c]) => `<button class="tab ${tab === k ? "active" : ""}" data-goto="architecture" data-tab="${k}">${l}${c !== "" ? ` <small>${c}</small>` : ""}</button>`).join("")}</div>`);
    if (tab === "sbom") return head + renderSbom(r);
    if (tab === "modules") return head + renderModules();
    return head + renderGraph(r);
  }

  // ---------- graph model
  const W = 200, H = 48, VG = 12, CG = 72, PAD = 18, HEAD = 34;
  function graphModel(focus, showAll) {
    const cols = [], edges = [];
    const col = (title, hint) => { const c = { title, hint, nodes: [] }; cols.push(c); return c; };
    const has = new Set();
    const put = (c, n) => { if (!has.has(n.id)) { has.add(n.id); c.nodes.push(n); } };
    const asNode = (id, extra = {}) => { const n = N.get(id) || {}; return { id, label: n.l || id, kind: n.t, risk: n.risk, sub: subOf(n), ...extra }; };
    const fNode = N.get(focus);

    if (!focus || !fNode) {                                   // ---- system view
      const entryCol = col("Entry points", "routes & commands"), handCol = col("Request handlers", "modules"), coreCol = col("Core & data", "modules"), outCol = col("Services & secrets", ""), pkgCol = col("Packages at risk", "known vulnerabilities");
      const groups = new Map();
      for (const n of data.explorer.nodes) if ((n.t === "route" || n.t === "cli") && n.m) { const g = groups.get(n.m) || { r: 0, c: 0, risk: null }; n.t === "route" ? g.r++ : g.c++; if (n.risk && (!g.risk || RISK[n.risk] > RISK[g.risk])) g.risk = n.risk; groups.set(n.m, g); }
      const mods = data.explorer.nodes.filter(n => n.t === "module" && !n.tests);
      for (const [m, g] of [...groups].sort((a, b) => (b[1].r + b[1].c) - (a[1].r + a[1].c))) {
        put(entryCol, { id: `grp:${m}`, label: `${modName(m)} entry points`, kind: "group", risk: g.risk, sub: [g.r ? `${g.r} route${g.r > 1 ? "s" : ""}` : "", g.c ? `${g.c} command${g.c > 1 ? "s" : ""}` : ""].filter(Boolean).join(" · "), module: m });
        edges.push({ s: `grp:${m}`, t: m, kind: "HANDLES" });
      }
      for (const m of mods) put(groups.has(m.id) ? handCol : coreCol, asNode(m.id, { sub: `${m.files || 0} files · ${fnsOfModule(m.id).length} functions` }));
      const inMods = new Set(mods.map(m => m.id));
      for (const m of mods) for (const e of out(m.id, "DEPENDS_ON")) if (inMods.has(e.id)) edges.push({ s: m.id, t: e.id, kind: "DEPENDS_ON" });
      const svc = data.explorer.nodes.filter(n => n.t === "service"), secrets = data.explorer.nodes.filter(n => n.t === "env" && n.secret);
      svc.forEach(n => put(outCol, asNode(n.id)));
      secrets.slice(0, 8).forEach(n => put(outCol, asNode(n.id)));
      const risky = data.explorer.nodes.filter(n => n.t === "package" && n.risk && RISK[n.risk] >= 1).sort(byRisk);
      risky.slice(0, 14).forEach(n => put(pkgCol, asNode(n.id)));
      const restVuln = data.sbom.filter(p => p.vulns?.length && !has.has(p.id)).length;
      if (restVuln) put(pkgCol, { id: "more:sbom", label: `+${restVuln} more vulnerable`, kind: "more", sub: "low risk · open SBOM" });
      // module -> service / secret / package (aggregated from functions)
      const agg = new Map();
      for (const n of data.explorer.nodes) {
        if (!n.m || !inMods.has(n.m)) continue;
        if (n.t === "function" || n.t === "class" || n.t === "file") for (const e of out(n.id, "CONTACTS", "READS_ENV", "USES", "IMPORTS_PKG")) if (has.has(e.id)) {
          const k = `${n.m}|${e.id}`; const hot = !!(n.risk && N.get(e.id)?.risk && (n.findings || []).some(f => (N.get(e.id).findings || []).includes(f)));
          agg.set(k, (agg.get(k) || false) || hot);
        }
      }
      for (const [k, hot] of agg) { const [s, t] = k.split("|"); edges.push({ s, t, kind: "USES", hot }); }
      return { cols, edges, crumbs: [] };
    }

    if (fNode.t === "module") {                               // ---- module view
      const m = focus, entryCol = col("Entry points & callers", ""), fnCol = col(`Inside ${fNode.l}`, "functions & classes"), calleeCol = col("Calls into", "other modules"), extCol = col("Packages · services · secrets", "");
      let fns = fnsOfModule(m).filter(n => !n.top || n.risk).sort((a, b) => (b.score || 0) - (a.score || 0));
      const total = fns.length; if (!showAll) fns = fns.slice(0, 16);
      const inFns = new Set(fns.map(n => n.id));
      for (const n of data.explorer.nodes) if ((n.t === "route" || n.t === "cli") && n.h && inFns.has(n.h)) { put(entryCol, asNode(n.id, { sub: n.t === "cli" ? "CLI command" : `→ ${N.get(n.h)?.l || ""}` })); edges.push({ s: n.id, t: n.h, kind: "HANDLES" }); }
      let callers = 0;
      for (const f of fns) for (const e of inc(f.id, "CALLS")) { const c = N.get(e.id); if (c && c.m !== m && callers < 10) { if (!has.has(c.id)) callers++; put(entryCol, asNode(c.id, { sub: `${modName(c.m)} · caller` })); edges.push({ s: c.id, t: f.id, kind: "CALLS" }); } }
      fns.forEach(f => put(fnCol, asNode(f.id)));
      if (total > fns.length) put(fnCol, { id: "more:fns", label: `Show all ${total}`, kind: "more", sub: `${total - fns.length} more functions` });
      let callees = 0;
      for (const f of fns) for (const e of out(f.id, "CALLS")) { const c = N.get(e.id); if (!c) continue; if (c.m === m) { if (inFns.has(c.id)) edges.push({ s: f.id, t: c.id, kind: "CALLS" }); continue; } if (callees < 14 || has.has(c.id)) { if (!has.has(c.id)) callees++; put(calleeCol, asNode(c.id, { sub: modName(c.m) })); edges.push({ s: f.id, t: c.id, kind: "CALLS" }); } }
      const ext = new Map();
      for (const f of fns) for (const e of out(f.id, "USES", "CONTACTS", "READS_ENV")) {
        const t = N.get(e.id); if (!t) continue;
        ext.set(e.id, (ext.get(e.id) || 0) + 1);
        edges.push({ s: f.id, t: e.id, kind: e.type, hot: !!(f.risk && t.risk && (f.findings || []).some(x => (t.findings || []).includes(x))) });
      }
      // files of the module that import packages without a recorded call
      for (const file of data.explorer.nodes.filter(n => n.t === "file" && n.m === m)) for (const e of out(file.id, "IMPORTS_PKG")) ext.set(e.id, (ext.get(e.id) || 0) + 0.1);
      [...ext.keys()].map(id => N.get(id)).filter(Boolean).sort((a, b) => (RISK[b.risk] ?? -1) - (RISK[a.risk] ?? -1) || (ext.get(b.id) - ext.get(a.id))).slice(0, 18).forEach(n => put(extCol, asNode(n.id)));
      return { cols, edges: edges.filter(e => has.has(e.s) && has.has(e.t)), crumbs: [[m, fNode.l]] };
    }

    // ---- function / class / other focus: neighbourhood
    const f = fNode, inCol = col("Reached from", "routes & callers"), meCol = col(kindName[f.t] || "Selected", ""), calleeCol = col("Calls", ""), extCol = col("Uses", "packages · services · secrets");
    for (const e of inc(f.id, "HANDLES")) { put(inCol, asNode(e.id)); edges.push({ s: e.id, t: f.id, kind: "HANDLES" }); }
    for (const fl of data.flows.routes || []) if (fl.steps?.includes(f.id) && fl.handler !== f.id && inCol.nodes.length < 12) { put(inCol, asNode(fl.id, { sub: "route · indirect" })); edges.push({ s: fl.id, t: f.id, kind: "FLOW" }); }
    for (const e of inc(f.id, "CALLS")) { put(inCol, asNode(e.id, { sub: `${modName(N.get(e.id)?.m)} · caller` })); edges.push({ s: e.id, t: f.id, kind: "CALLS" }); }
    for (const e of inc(f.id, "USES", "CONTACTS", "READS_ENV")) if (inCol.nodes.length < 24) { put(inCol, asNode(e.id, { sub: `${modName(N.get(e.id)?.m)} · user` })); edges.push({ s: e.id, t: f.id, kind: "USES" }); }
    put(meCol, asNode(f.id, { sub: f.f ? `${f.f}:${f.ln || ""}` : subOf(f) }));
    for (const e of out(f.id, "CALLS")) { put(calleeCol, asNode(e.id, { sub: modName(N.get(e.id)?.m) })); edges.push({ s: f.id, t: e.id, kind: "CALLS" }); }
    for (const e of out(f.id, "USES", "CONTACTS", "READS_ENV")) { const t = N.get(e.id); put(extCol, asNode(e.id, { sub: e.extra?.length ? short(e.extra.slice(0, 2).join(", "), 30) : subOf(t || {}) })); edges.push({ s: f.id, t: e.id, kind: e.type, hot: !!(f.risk && t?.risk) }); }
    const crumbs = f.m ? [[f.m, modName(f.m)], [f.id, f.l]] : [[f.id, f.l]];
    return { cols: cols.filter(c => c.nodes.length || c === meCol), edges, crumbs };
  }
  function subOf(n) {
    if (!n) return "";
    if (n.t === "package") return `${n.v || ""}${n.direct === false ? " · transitive" : ""}${n.findings?.length ? ` · ${n.findings.filter(x => x.startsWith("F-")).length} vulns` : ""}`;
    if (n.t === "service") return `external service${n.via ? " · " + n.via : ""}`;
    if (n.t === "env") return n.secret ? "secret (environment)" : "environment variable";
    if (n.t === "route") return "HTTP route";
    if (n.t === "cli") return "CLI command";
    if (n.t === "function" || n.t === "class") return `${n.f || ""}${n.ln ? ":" + n.ln : ""}`;
    if (n.t === "module") return `${n.files || 0} files`;
    return n.t || "";
  }

  // ---------- graph layout + svg
  function layout(model) {
    const pos = new Map();
    model.cols.forEach((c, ci) => c.nodes.forEach((n, i) => pos.set(n.id, { ci, i })));
    // barycentre ordering, left to right
    for (let ci = 1; ci < model.cols.length; ci++) {
      const c = model.cols[ci];
      const score = n => { const ys = model.edges.filter(e => e.t === n.id && pos.get(e.s)?.ci < ci).map(e => pos.get(e.s).i); return ys.length ? ys.reduce((a, b) => a + b, 0) / ys.length : 1e6 + c.nodes.indexOf(n); };
      const keepLast = c.nodes.filter(n => n.kind === "more");
      c.nodes = c.nodes.filter(n => n.kind !== "more").map(n => [n, score(n)]).sort((a, b) => a[1] - b[1]).map(x => x[0]).concat(keepLast);
      c.nodes.forEach((n, i) => pos.set(n.id, { ci, i }));
    }
    const maxN = Math.max(1, ...model.cols.map(c => c.nodes.length));
    const height = HEAD + PAD * 2 + maxN * (H + VG);
    const xy = new Map();
    model.cols.forEach((c, ci) => { const off = (maxN - c.nodes.length) * (H + VG) / 2; c.nodes.forEach((n, i) => xy.set(n.id, { x: PAD + ci * (W + CG), y: HEAD + PAD + off + i * (H + VG), ci })); });
    return { xy, width: PAD * 2 + model.cols.length * W + (model.cols.length - 1) * CG + 50, height };
  }
  function graphSvg(model, sel) {
    const { xy, width, height } = layout(model);
    const near = new Set([sel]);
    for (const e of model.edges) { if (e.s === sel) near.add(e.t); if (e.t === sel) near.add(e.s); }
    const flow = sel && FLOW.get(sel); if (flow) [flow.handler, ...(flow.steps || []), ...(flow.sinks || [])].forEach(x => near.add(x));
    const dim = sel && xy.has(sel);
    const seen = new Set();
    const edges = model.edges.filter(e => { const k = `${e.s}|${e.t}`; if (seen.has(k) || !xy.has(e.s) || !xy.has(e.t)) return false; seen.add(k); return true; }).map(e => {
      const a = xy.get(e.s), b = xy.get(e.t), touch = sel && (e.s === sel || e.t === sel || (flow && near.has(e.s) && near.has(e.t)));
      let d;
      if (a.ci === b.ci) { if (!touch) return ""; const x = a.x + W, k = 34 + Math.abs(a.y - b.y) * .15; d = `M${x},${a.y + H / 2} C${x + k},${a.y + H / 2} ${x + k},${b.y + H / 2} ${x},${b.y + H / 2}`; }
      else if (a.ci < b.ci) { const x1 = a.x + W, x2 = b.x, mx = (x1 + x2) / 2; d = `M${x1},${a.y + H / 2} C${mx},${a.y + H / 2} ${mx},${b.y + H / 2} ${x2 - 3},${b.y + H / 2}`; }
      else { const x1 = a.x, x2 = b.x + W, mx = (x1 + x2) / 2; d = `M${x1},${a.y + H / 2} C${mx},${a.y + H / 2} ${mx},${b.y + H / 2} ${x2 + 3},${b.y + H / 2}`; }
      return `<path class="gedge ${e.kind} ${e.hot ? "hot" : ""} ${touch ? "hl" : dim ? "dimmed" : ""}" d="${d}" marker-end="url(#${e.hot ? "ah" : touch ? "aa" : "ar"})"/>`;
    }).join("");
    const heads = model.cols.map((c, ci) => `<text class="gcol" x="${PAD + ci * (W + CG)}" y="${PAD + 6}">${esc(c.title.toUpperCase())}</text>${c.hint ? `<text class="gcol-hint" x="${PAD + ci * (W + CG)}" y="${PAD + 20}">${esc(c.hint)}</text>` : ""}`).join("");
    const nodes = model.cols.flatMap(c => c.nodes).map(n => {
      const p = xy.get(n.id);
      const cls = ["gnode", `k-${n.kind}`, n.risk ? `r-${n.risk}` : "", n.id === sel ? "sel" : "", dim && !near.has(n.id) ? "dimmed" : ""].join(" ");
      return `<g class="${cls}" data-gnode="${esc(n.id)}" transform="translate(${p.x},${p.y})" tabindex="0" role="button" aria-label="${esc(n.label)}"><rect class="gbox" width="${W}" height="${H}" rx="9"/><rect class="gbar" width="4" height="${H - 14}" x="7" y="7" rx="2"/><text class="gl" x="20" y="20">${esc(short(n.label, 27))}</text><text class="gs" x="20" y="36">${esc(short(n.sub || "", 33))}</text>${n.risk ? `<circle class="grisk ${n.risk}" cx="${W - 13}" cy="13" r="5"><title>${n.risk} risk</title></circle>` : ""}<title>${esc(n.label)}${n.sub ? " — " + esc(n.sub) : ""}</title></g>`;
    }).join("");
    return `<svg class="gsvg" viewBox="0 0 ${width} ${height}" style="max-width:${width}px"><defs>${[["ar", "#b9c4bd"], ["aa", "#1f6f54"], ["ah", "#c75f55"]].map(([id, c]) => `<marker id="${id}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto"><path d="M0 0 L10 5 L0 10 z" fill="${c}"/></marker>`).join("")}</defs>${edges}${heads}${nodes}</svg>`;
  }

  function renderGraph(r) {
    if (!data.explorer.nodes.length) return `<div class="panel empty-big"><p>This scan bundle has no code graph. Load a scan served by <code>guardian serve</code> or <code>guardian web</code> to explore it.</p></div>`;
    const focus = r.p.get("focus"), sel = r.p.get("sel"), all = r.p.get("all") === "1";
    const model = graphModel(focus, all);
    const crumbs = [`<button class="crumb" data-focus="">System</button>`, ...model.crumbs.map(([id, l], i) => `<span class="crumb-sep">›</span><button class="crumb ${i === model.crumbs.length - 1 ? "current" : ""}" data-focus="${esc(id)}">${esc(l)}</button>`)].join("");
    const hint = !focus ? "Click a module to see its main functions. Click a route group, package, service or secret to see details." : N.get(focus)?.t === "module" ? "Click a function to inspect it; double-click (or “Open function map”) to follow its calls." : "Click any box to inspect it; double-click to move the map onto it.";
    return `<div class="architecture-layout"><div class="architecture-main">
      <section class="panel graph-panel"><div class="graph-toolbar"><div class="crumbs">${crumbs}</div><div class="graph-search"><input id="gsearch" placeholder="Find a function, file, route, package…" autocomplete="off"><div id="gsearch-pop" class="search-pop" hidden></div></div></div>
      <div class="graph-legend"><span><i class="legend-dot blue"></i>Entry point</span><span><i class="legend-dot violet"></i>Your code</span><span><i class="legend-dot amber"></i>Service / secret</span><span><i class="legend-dot gray"></i>Package</span><span class="legend-sep"></span><span><i class="risk-dot critical"></i>Critical</span><span><i class="risk-dot high"></i>High</span><span><i class="risk-dot medium"></i>Medium</span><span><i class="edge-key hot"></i>Vulnerable code path</span></div>
      <div class="graph-scroll" id="graph-scroll">${graphSvg(model, sel)}</div>
      <div class="graph-caption"><span>${esc(hint)}</span><span>Arrows: caller → what it uses</span></div></section>
      ${renderStory()}
    </div><aside class="detail-panel side" id="side">${sideHtml(sel || focus)}</aside></div>`;
  }

  function renderStory() {
    const steps = (data.flows.narrative || []).map((n, i) => `<div class="story-step"><span class="story-num">${i + 1}</span><div><b>${esc(n.title)}</b><p>${esc(n.text)}</p>${refChips(n)}</div></div>`).join("");
    const byMod = new Map();
    for (const f of data.flows.routes || []) push(byMod, N.get(f.id)?.m || "", f);
    const routes = [...byMod].map(([m, rs]) => `<div class="route-group"><span class="stack-label">${esc(m ? modName(m) : "other")}</span><div class="route-chips">${rs.map(f => `<button class="route-chip ${f.risk ? "r-" + f.risk : ""}" data-node="${esc(f.id)}">${f.risk ? `<i class="risk-dot ${f.risk}"></i>` : ""}${esc(f.label)}</button>`).join("")}</div></div>`).join("");
    return panel("How the application flows", "A short explanation built from the call graph. Click a route to see its path highlighted and explained.", `<div class="story">${steps}</div>${routes ? `<div class="routes-all"><div class="detail-label">ALL ENTRY POINTS (${(data.flows.routes || []).length})</div>${routes}</div>` : ""}`);
  }

  // ---------- side panel
  function sideHtml(id) {
    const n = N.get(id);
    if (!id || !n) return overviewSide();
    const head = `<div class="detail-top"><span class="detail-type">${esc((kindName[n.t] || n.t || "").toUpperCase())}</span>${riskTag(n.risk)}</div><h3 class="side-title">${esc(n.l)}</h3>${n.f ? `<code class="detail-path">${esc(n.f)}${n.ln ? `:${n.ln}${n.end && n.end !== n.ln ? "-" + n.end : ""}` : ""}</code>` : n.path ? `<code class="detail-path">${esc(n.path)}</code>` : ""}`;
    const sec = (label, body) => body ? `<div class="detail-section"><div class="detail-label">${label}</div>${body}</div>` : "";
    const list = (items, max = 10) => items.length ? `<div class="side-list">${items.slice(0, max).join("")}${items.length > max ? `<span class="muted-small">+${items.length - max} more</span>` : ""}</div>` : "";
    const findingsBox = (n.findings || []).length ? `<div class="side-findings">${n.findings.map(fid => { const f = FIND.get(fid); return f ? `<button class="side-finding" data-finding="${esc(fid)}"><span class="risk-dot ${f.risk}"></span><span><b>${esc(fid)}</b> ${esc(short(f.kind === "vulnerability" ? `${f.package} ${f.version} · ${f.vulnId}` : f.title, 64))}</span></button>` : ""; }).join("")}</div>` : "";
    const nodeItems = es => es.map(e => nodeBtn(e.id, N.get(e.id)?.l, e.extra?.length ? `<small>${esc(short(e.extra.join(", "), 40))}</small>` : N.get(e.id)?.risk ? `<i class="risk-dot ${N.get(e.id).risk}"></i>` : ""));
    let body = "";
    if (n.t === "module") {
      const fns = fnsOfModule(n.id).sort((a, b) => (b.score || 0) - (a.score || 0));
      const files = data.explorer.nodes.filter(x => x.t === "file" && x.m === n.id);
      const routes = data.explorer.nodes.filter(x => (x.t === "route" || x.t === "cli") && x.m === n.id);
      body = `${n.purpose ? `<p class="detail-purpose">${esc(n.purpose)}</p>` : ""}<div class="detail-facts"><span><b>${files.length}</b> files</span><span><b>${fns.length}</b> functions</span><span><b>${routes.length}</b> entry points</span></div>
        ${sec("SECURITY", findingsBox)}
        ${(n.tags || []).length ? sec("OBSERVED TAGS", `<div class="tag-list">${n.tags.map(t => tag(t)).join("")}</div>`) : ""}
        ${sec("KEY FUNCTIONS", list(fns.slice(0, 10).map(f => nodeBtn(f.id, f.l, f.risk ? `<i class="risk-dot ${f.risk}"></i>` : ""))))}
        ${sec("FILES", list(files.map(f => nodeBtn(f.id, f.l)), 8))}
        ${sec("DEPENDS ON", list(nodeItems(out(n.id, "DEPENDS_ON")), 8))}
        ${sec("USED BY", list(nodeItems(inc(n.id, "DEPENDS_ON")), 8))}
        ${link("Open module map →", `data-focus="${esc(n.id)}"`, "primary-button wide")}`;
    } else if (n.t === "file") {
      const fns = out(n.id, "CONTAINS").map(e => N.get(e.id)).filter(Boolean).sort((a, b) => (a.ln || 0) - (b.ln || 0));
      body = `${n.purpose ? `<p class="detail-purpose">${esc(n.purpose)}</p>` : ""}<div class="detail-facts"><span><b>${n.loc || "?"}</b> lines</span><span><b>${fns.length}</b> functions</span></div>${sec("MODULE", n.m ? nodeBtn(n.m) : "")}${sec("SECURITY", findingsBox)}${sec("FUNCTIONS & CLASSES", list(fns.map(f => nodeBtn(f.id, f.l, `<small>:${f.ln || ""}</small>`)), 30))}${sec("PACKAGES IMPORTED", list(nodeItems(out(n.id, "IMPORTS_PKG")), 12))}`;
    } else if (n.t === "function" || n.t === "class") {
      const routes = [...inc(n.id, "HANDLES").map(e => e.id), ...(data.flows.routes || []).filter(f => f.steps?.includes(n.id) && f.handler !== n.id).map(f => f.id)];
      const hot = (data.security.hotspots || []).filter(h => h.function === n.id);
      body = `${n.purpose || n.doc ? `<p class="detail-purpose">${esc(n.purpose || n.doc)}</p>` : ""}
        ${sec("SECURITY", findingsBox + hot.map(h => `<div class="hot-box"><b>${esc(h.what)}</b> <small>${esc(h.calls.join(", "))}</small><p>${esc(h.why)}</p></div>`).join(""))}
        ${(n.tags || []).length ? sec("BEHAVIOUR", `<div class="tag-list">${n.tags.map(t => tag(t)).join("")}</div>`) : ""}
        ${sec("REACHED FROM", list([...new Set(routes)].map(id => nodeBtn(id, N.get(id)?.l, N.get(id)?.risk ? `<i class="risk-dot ${N.get(id).risk}"></i>` : "")), 8))}
        ${sec("CALLED BY", list(nodeItems(inc(n.id, "CALLS")), 8))}
        ${sec("CALLS", list(nodeItems(out(n.id, "CALLS")), 10))}
        ${sec("USES", list(nodeItems(out(n.id, "USES", "CONTACTS", "READS_ENV")), 10))}
        ${sec("WHERE", `${n.m ? nodeBtn(n.m, "module " + modName(n.m)) : ""}${n.file ? nodeBtn(n.file) : ""}`)}
        <div class="detail-section"><div class="detail-label">SOURCE</div><div id="src-box" class="code-box muted-small">Loading source…</div></div>
        ${link("Open function map →", `data-focus="${esc(n.id)}"`, "primary-button wide")}`;
    } else if (n.t === "route" || n.t === "cli") {
      const fl = FLOW.get(n.id) || {};
      body = `<p class="detail-purpose">${esc(fl.text || "")}</p>${sec("SECURITY", findingsBox)}${sec("HANDLER", n.h ? nodeBtn(n.h, N.get(n.h)?.l, `<small>${esc(N.get(n.h)?.f || "")}</small>`) : "")}${fl.input ? sec("INPUT", `<code class="detail-path">${esc(fl.input)}</code>`) : ""}${sec("PATH THROUGH THE CODE", (fl.steps || []).length ? `<div class="flow-chain">${fl.steps.map((s, i) => `<div class="chain-step"><span class="step-number">${String(i + 1).padStart(2, "0")}</span>${nodeBtn(s, N.get(s)?.l || s.split("::").pop())}</div>`).join("")}</div>` : "")}${sec("REACHES", list((fl.sinks || []).filter(s => N.has(s)).map(s => nodeBtn(s, N.get(s).l, N.get(s).risk ? `<i class="risk-dot ${N.get(s).risk}"></i>` : "")), 12))}${n.h ? link("Open handler map →", `data-focus="${esc(n.h)}"`, "primary-button wide") : ""}`;
    } else if (n.t === "package") {
      const p = data.sbom.find(x => x.id === n.id) || {};
      body = `<div class="package-status">${tag(n.direct ? "Direct dependency" : "Transitive", "blue")}${tag(n.used ? "Used in code" : "No code usage found", n.used ? "green" : "orange")}${n.dev ? tag("dev", "muted") : ""}</div><code class="detail-path">${esc(p.purl || n.id)}</code>
        ${sec("KNOWN VULNERABILITIES", (p.vulns || []).length ? `<div class="side-findings">${p.vulns.map(v => `<button class="side-finding" data-finding="${esc(v.id)}"><span class="risk-dot ${v.risk}"></span><span><b>${esc(v.vulnId)}</b> CVSS ${v.cvss ?? "?"} · ${esc(v.risk)}</span></button>`).join("")}</div>` : `<span class="muted-small">None known in OSV for ${esc(n.v || "this version")}.</span>`)}
        ${sec("USED BY", list(nodeItems(inc(n.id, "USES", "IMPORTS_PKG")), 12))}
        ${(p.reasons || []).length ? sec("BLAST RADIUS", `<span class="radius ${p.radius}"><i></i>${esc(p.radius || "")}</span><ul class="reason-list">${p.reasons.map(x => `<li>${esc(x)}</li>`).join("")}</ul>`) : ""}
        ${link("Open in SBOM →", `data-pkg="${esc(n.id)}"`, "primary-button wide")}`;
    } else if (n.t === "service" || n.t === "env" || n.t === "table") {
      body = `<p class="detail-purpose">${n.t === "service" ? "An external system this code connects to." : n.secret ? "A secret-like value read from the environment. Code that reads it can leak or misuse it." : "Configuration read from the environment."}</p>${sec(n.t === "service" ? "CONTACTED BY" : "READ BY", list(nodeItems(inc(n.id, "CONTACTS", "READS_ENV", "READS", "WRITES")), 14))}`;
    }
    return head + body;
  }
  function overviewSide() {
    const s = data.security, risky = data.explorer.nodes.filter(n => (n.t === "function" || n.t === "class") && n.risk).sort(byRisk);
    return `<div class="detail-top"><span class="detail-type">WHERE TO LOOK FIRST</span></div><h3 class="side-title">Riskiest code</h3><p class="detail-purpose">Functions that call a vulnerable library function, or that do something risky (shell commands, network calls) on a path reachable from users.</p><div class="side-list">${risky.slice(0, 12).map(n => nodeBtn(n.id, n.l, `<i class="risk-dot ${n.risk}"></i><small>${esc(modName(n.m))}</small>`)).join("") || `<span class="muted-small">No risky functions found.</span>`}</div>${(s.hotspots || []).length ? `<div class="detail-section"><div class="detail-label">CODE HOTSPOTS</div><div class="side-list">${s.hotspots.slice(0, 6).map(h => nodeBtn(h.function, h.label, `<small>${esc(h.category)}</small>`)).join("")}</div></div>` : ""}`;
  }

  function afterGraph(r) {
    const sel = r.p.get("sel") || r.p.get("focus");
    const n = N.get(sel);
    if (n && (n.t === "function" || n.t === "class")) loadSource(n);
    const sc = document.querySelector("#graph-scroll"), g = sel && sc?.querySelector(`[data-gnode="${CSS.escape(sel)}"]`);
    if (g && sc) { const m = g.transform.baseVal[0]?.matrix, svg = sc.querySelector("svg"), k = svg.getBoundingClientRect().width / (svg.viewBox.baseVal.width || 1) || 1; if (m) { sc.scrollLeft = Math.max(0, m.e * k - sc.clientWidth / 2 + W * k / 2); sc.scrollTop = Math.max(0, m.f * k - sc.clientHeight / 2); } }
  }
  async function loadSource(n) {
    const box = document.querySelector("#src-box");
    if (!box || !n.f) return;
    if (mode === "static") { box.textContent = "Source is shown when the dashboard is served by guardian serve or guardian web."; return; }
    try {
      let lines = srcCache.get(n.f);
      if (!lines) {
        const url = mode === "web" ? `/api/scans/${encodeURIComponent(scanId)}/files/${n.f.split("/").map(encodeURIComponent).join("/")}` : `/source/${n.f.split("/").map(encodeURIComponent).join("/")}`;
        const res = await fetch(url); if (!res.ok) throw new Error(res.status === 404 ? "source not available for this scan" : `HTTP ${res.status}`);
        const j = await res.json(); lines = j.start && j.start > 1 ? [...Array(j.start - 1).fill(""), ...j.lines] : j.lines; srcCache.set(n.f, lines);
      }
      const a = Math.max(1, n.ln || 1), b = Math.min(lines.length, Math.max(a, n.end || a + 20), a + 70);
      const hotLines = new Set([...(data.security.hotspots || []).filter(h => h.function === n.id).flatMap(h => h.lines), ...(data.security.vulnerabilities || []).flatMap(v => v.sites).filter(s => s.function === n.id).map(s => parseInt(s.lines))]);
      const cur = document.querySelector("#src-box"); if (!cur) return;
      cur.className = "code-box";
      cur.innerHTML = `<pre>${lines.slice(a - 1, b).map((t, i) => `<span class="cl ${hotLines.has(a + i) ? "hot" : ""}"><i>${a + i}</i>${esc(t)}</span>`).join("")}</pre>${b - a + 1 < (n.end || 0) - a + 1 ? `<small>…function continues to line ${n.end}</small>` : ""}`;
    } catch (e) { const cur = document.querySelector("#src-box"); if (cur) cur.textContent = `Source unavailable: ${e.message}`; }
  }

  // ---------- search
  function searchHits(q) {
    q = q.toLowerCase().trim(); if (!q) return [];
    const kinds = ["module", "route", "cli", "function", "class", "file", "package", "service", "env"];
    return data.explorer.nodes.filter(n => kinds.includes(n.t) && ((n.l || "").toLowerCase().includes(q) || (n.f || "").toLowerCase().includes(q))).sort((a, b) => ((a.l || "").toLowerCase().startsWith(q) ? 0 : 1) - ((b.l || "").toLowerCase().startsWith(q) ? 0 : 1) || kinds.indexOf(a.t) - kinds.indexOf(b.t)).slice(0, 14);
  }
  function openNode(id) {
    const n = N.get(id);
    if (!n) { if (id?.startsWith("svc:")) { const s = data.explorer.nodes.find(x => x.t === "service" && x.l === id.slice(4)); if (s) return openNode(s.id); } return; }
    const cur = route(), inGraph = cur.view === "architecture" && (cur.tab || "graph") === "graph", focus = cur.p.get("focus") || "";
    if (n.t === "module") return go("architecture", "graph", { focus: n.id, sel: n.id });
    if (n.t === "function" || n.t === "class") {
      if (inGraph && focus && (focus === n.m || focus === n.id || graphHas(focus, n.id))) return go("architecture", "graph", { focus, sel: n.id, all: cur.p.get("all") });
      return go("architecture", "graph", { focus: n.m || n.id, sel: n.id, all: n.m && fnsOfModule(n.m).length > 16 ? 1 : undefined });
    }
    if (n.t === "route" || n.t === "cli") return go("architecture", "graph", { focus: inGraph && focus ? focus : (n.m || ""), sel: n.id });
    if (n.t === "file") return go("architecture", "graph", { focus: n.m || "", sel: n.id });
    return go("architecture", "graph", { focus: inGraph ? focus : "", sel: n.id, all: cur.p.get("all") });
  }
  const graphHas = (focus, id) => graphModel(focus, true).cols.some(c => c.nodes.some(n => n.id === id));

  // ------------------------------------------------------------------ SBOM
  function renderSbom(r) {
    const q = (r.p.get("q") || "").toLowerCase(), f = r.p.get("f") || "all", sel = r.p.get("sel");
    const all = data.sbom;
    const filters = { all: () => true, vulnerable: p => p.vulns?.length, direct: p => p.direct, transitive: p => !p.direct, unused: p => p.direct && !p.usedByFiles, dev: p => p.dev };
    const rows = all.filter(filters[f] || filters.all).filter(p => !q || `${p.name} ${p.version} ${p.purl}`.toLowerCase().includes(q)).sort((a, b) => (RISK[b.risk] ?? -1) - (RISK[a.risk] ?? -1) || a.name.localeCompare(b.name));
    const cnt = k => all.filter(filters[k]).length;
    const p = all.find(x => x.id === sel) || null;
    const chip = (k, l) => `<button class="filter-chip ${f === k ? "active" : ""}" data-sbom-f="${k}">${l} <small>${cnt(k)}</small></button>`;
    return `<div class="sbom-metrics"><div><span>Components</span><b>${all.length}</b></div><div><span>Direct</span><b>${cnt("direct")}</b></div><div><span>Transitive</span><b>${cnt("transitive")}</b></div><div class="warn"><span>With known vulnerabilities</span><b>${cnt("vulnerable")}</b></div><div><span>Declared but unused</span><b>${cnt("unused")}</b></div></div>
      <div class="architecture-layout"><div class="architecture-main"><section class="panel"><div class="panel-header sbom-head"><div><h2>Software bill of materials</h2><p>Every package this repository installs, with the version scanned and the vulnerabilities known for it</p></div><button class="quiet-button" id="cdx-download">⤓ CycloneDX JSON</button></div>
      <div class="sbom-toolbar"><input id="sbom-q" placeholder="Filter packages…" value="${esc(r.p.get("q") || "")}"><div class="filter-chips">${chip("all", "All")}${chip("vulnerable", "Vulnerable")}${chip("direct", "Direct")}${chip("transitive", "Transitive")}${chip("unused", "Unused")}${chip("dev", "Dev")}</div></div>
      <div class="sbom-table"><div class="table-head"><span>PACKAGE</span><span>VERSION</span><span>RELATIONSHIP</span><span>USED IN CODE</span><span>KNOWN VULNERABILITIES</span><span>DECLARED IN</span></div>
      ${rows.map(x => `<button class="sbom-row ${x.id === sel ? "row-selected" : ""}" data-pkg="${esc(x.id)}"><span><b>${esc(x.name)}</b>${x.group ? `<small>${esc(x.group)}</small>` : ""}</span><span><code>${esc(x.version)}</code></span><span>${x.direct ? tag("direct", "blue") : `${tag("transitive", "muted")}${x.requiredBy?.length ? `<small>via ${esc(x.requiredBy.slice(0, 2).join(", "))}</small>` : ""}`}${x.dev ? tag("dev", "muted") : ""}</span><span>${x.usedByFiles ? `${x.usedByFiles} file${x.usedByFiles > 1 ? "s" : ""}` : `<span class="muted-small">${x.direct ? "not imported" : "—"}</span>`}</span><span>${x.vulns?.length ? `${riskTag(x.vulns[0].risk)} <small>${x.vulns.length} · ${esc(x.vulns[0].vulnId)}</small>` : `<span class="muted-small">none known</span>`}</span><span class="muted-small">${esc(x.declaredIn || "")}</span></button>`).join("") || `<div class="empty-state">No packages match.</div>`}</div></section></div>
      <aside class="detail-panel side">${p ? sbomSide(p) : `<div class="detail-top"><span class="detail-type">SBOM</span></div><h3 class="side-title">What is this?</h3><p class="detail-purpose">A software bill of materials lists every third-party component in the build. Guardian checks each <b>name + version</b> against the OSV vulnerability database (GitHub advisories, PyPA, CVE). Select a package to see where your code uses it.</p>`}</aside></div>`;
  }
  function sbomSide(p) {
    const fns = (p.functions || []).map(id => nodeBtn(id, N.get(id)?.l || id.split("::").pop(), N.get(id)?.risk ? `<i class="risk-dot ${N.get(id).risk}"></i>` : ""));
    return `<div class="detail-top"><span class="detail-type">PACKAGE</span>${riskTag(p.risk)}</div><h3 class="side-title">${esc(p.name)} <span class="version-label">${esc(p.version)}</span></h3><code class="detail-path">${esc(p.purl)}</code>
      <div class="package-status">${tag(p.direct ? "Direct" : "Transitive", "blue")}${tag(p.usedByFiles ? `Used in ${p.usedByFiles} files` : "No code usage", p.usedByFiles ? "green" : "orange")}${p.dev ? tag("dev only", "muted") : ""}</div>
      <div class="detail-section"><div class="detail-label">KNOWN VULNERABILITIES</div>${(p.vulns || []).length ? `<div class="side-findings">${p.vulns.map(v => `<button class="side-finding" data-finding="${esc(v.id)}"><span class="risk-dot ${v.risk}"></span><span><b>${esc(v.vulnId)}</b> CVSS ${v.cvss ?? "?"} · project risk ${esc(v.risk)}</span></button>`).join("")}</div><p class="fix-note">${esc(p.vulns[0].fix || "")}</p>` : `<span class="muted-small">No known vulnerabilities for this version in OSV.</span>`}</div>
      ${fns.length ? `<div class="detail-section"><div class="detail-label">FUNCTIONS USING IT</div><div class="side-list">${fns.slice(0, 14).join("")}</div></div>` : ""}
      ${p.declaredIn ? `<div class="detail-section"><div class="detail-label">DECLARED</div><code class="detail-path">${esc(p.declaredIn)}${p.spec ? "  " + esc(p.spec) : ""}</code></div>` : ""}
      ${(p.requiredBy || []).length ? `<div class="detail-section"><div class="detail-label">PULLED IN BY</div>${p.requiredBy.map(x => tag(x, "muted")).join("")}</div>` : ""}
      ${(p.reasons || []).length ? `<div class="detail-section"><div class="detail-label">BLAST RADIUS</div><span class="radius ${p.radius}"><i></i>${esc(p.radius)}</span><ul class="reason-list">${p.reasons.map(x => `<li>${esc(x)}</li>`).join("")}</ul></div>` : ""}
      ${N.has(p.id) ? link("Show in graph →", `data-node="${esc(p.id)}"`, "primary-button wide") : ""}`;
  }
  function downloadCdx() {
    const vulns = [];
    for (const p of data.sbom) for (const v of p.vulns || []) vulns.push({ id: v.vulnId, "bom-ref": `${v.id}`, ratings: [{ score: v.cvss, severity: v.band || v.risk, method: "CVSSv31" }], affects: [{ ref: p.purl }], analysis: { detail: `project risk: ${v.risk}` } });
    const bom = { bomFormat: "CycloneDX", specVersion: "1.5", version: 1, metadata: { timestamp: new Date().toISOString(), tools: [{ name: "guardian" }], component: { type: "application", name: data.repo.name, version: data.repo.commit } }, components: data.sbom.map(p => ({ type: "library", "bom-ref": p.purl, name: p.name, version: p.version, purl: p.purl, scope: p.dev ? "optional" : "required", properties: [{ name: "guardian:direct", value: String(!!p.direct) }] })), vulnerabilities: vulns };
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([JSON.stringify(bom, null, 2)], { type: "application/json" }));
    a.download = `${data.repo.name || "sbom"}.cdx.json`; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  }

  // ------------------------------------------------------------------ modules tab
  function renderModules() {
    const mods = [...data.modules].sort((a, b) => (RISK[N.get(b.id)?.risk] ?? -1) - (RISK[N.get(a.id)?.risk] ?? -1) || a.name.localeCompare(b.name));
    return panel(`Module inventory <span class="count-inline">${mods.length}</span>`, "Purpose cards and structural tags — click a module to open its map", `<div class="module-table"><div class="table-head"><span>MODULE</span><span>PURPOSE</span><span>FILES</span><span>TAGS</span></div>${mods.map(x => `<button class="module-row" data-node="${esc(x.id)}"><span class="module-cell"><i class="legend-dot ${x.color}"></i><b>${esc(x.name)}</b>${N.get(x.id)?.risk ? riskTag(N.get(x.id).risk) : ""}<small>${esc(x.path)}</small></span><span class="module-purpose">${esc(x.purpose)}</span><span>${x.files}</span><span class="table-tags">${(x.tags || []).slice(0, 3).map(t => tag(t, "muted")).join("")}</span></button>`).join("")}</div>`);
  }

  // ------------------------------------------------------------------ risk detection (slide steps 3-5)
  const PRES_CLS = { "Confirmed in code": "p-conf", "Likely present": "p-likely", "Possible": "p-poss", "Installed only": "p-inst" };
  const presBar = p => p ? `<div class="pres"><div class="pres-bar"><i class="${PRES_CLS[p.label] || ""}" style="width:${p.score}%"></i></div><b>${p.score}%</b><small>${esc(p.label)}</small></div>` : "";
  const sevNum = x => (RISK[x.risk] ?? -1) * 1000 + (x.presence?.score || 0);
  const attention = x => x.kind === "vulnerability" ? (RISK[x.risk] >= 1 || (x.presence?.score || 0) >= 55) : RISK[x.risk] >= 1 || x.suspicion === "high";
  const tabOf = id => id.startsWith("F-") ? "vulns" : "suspicious";

  function renderRisk(r) {
    const tab = r.tab || "vulns", s = data.security;
    const evCount = (s.vulnerabilities || []).length + (s.anomalies || []).length + (s.code || []).length;
    const steps = [["vulns", "3", "Detect vulnerabilities", "Known CVEs from public databases, checked against your code", (s.vulnerabilities || []).length],
      ["suspicious", "4", "Suspicious report", "Supply-chain anomalies, code vulnerabilities, recent changes and risky code", (s.anomalies || []).length + (s.hotspots || []).length + (s.code || []).length],
      ["evidence", "5", "Evidence report", "Each finding, how it connects, and how it was investigated", evCount]];
    const head = title("RISK DETECTION", "Risks <span class='title-suffix'>& evidence</span>", "What appears risky in this repository, and the evidence behind every finding.");
    const stepper = `<div class="steps">${steps.map(([k, n, l, d, c]) => `<button class="step ${tab === k ? "active" : ""}" data-goto="risk" data-tab="${k}"><span class="step-n">${n}</span><span><b>${l} <small>${c}</small></b><small>${d}</small></span></button>`).join("")}</div>`;
    const body = tab === "suspicious" ? riskSuspicious(r) : tab === "evidence" ? riskEvidence(r) : riskVulns(r);
    const open = r.p.get("open");
    return head + stepper + body + (open ? modalHtml(open, tab) : "");
  }

  function riskVulns(r) {
    const s = data.security, all = s.vulnerabilities || [];
    if (!s.vulnDbRan) return `<div class="panel empty-big"><p>Stage 4 (vulnerability matching) did not run for this scan.</p></div>`;
    const pf = r.p.get("p"), rf = r.p.get("risk");
    const cnt = l => all.filter(v => v.presence?.label === l).length;
    const hideInst = !pf && !r.p.get("inst"), hidden = hideInst ? all.filter(v => v.presence?.label === "Installed only" && (!rf || v.risk === rf)).length : 0;
    let rows = all.filter(v => (!pf || v.presence?.label === pf) && (!rf || v.risk === rf) && !(hideInst && v.presence?.label === "Installed only")).sort((a, b) => (b.presence?.score || 0) - (a.presence?.score || 0) || (RISK[b.risk] ?? -1) - (RISK[a.risk] ?? -1) || (b.cvss || 0) - (a.cvss || 0));
    const card = (label, value, attrs = "", cls = "") => `<button class="sum-card ${cls}" ${attrs}><span>${label}</span><b>${value}</b></button>`;
    const pchip = l => `<button class="filter-chip ${pf === l ? "active" : ""}" data-risk-p="${pf === l ? "" : esc(l)}"><i class="pres-dot ${PRES_CLS[l]}"></i>${l} <small>${cnt(l)}</small></button>`;
    const rchip = k => `<button class="filter-chip ${rf === k ? "active" : ""}" data-risk-r="${rf === k ? "" : k}"><i class="risk-dot ${k}"></i>${k} <small>${all.filter(v => v.risk === k).length}</small></button>`;
    return `<div class="method-strip"><span class="m-step"><b class="m-num">1</b> Every package name + exact version from the SBOM</span><i>→</i><span class="m-step"><b class="m-num">2</b> Looked up in <b>OSV</b> (GitHub Advisories, PyPA, CVE/NVD)</span><i>→</i><span class="m-step"><b class="m-num">3</b> Checked in your code: imported? vulnerable function called? reachable from a route?</span><i>→</i><span class="m-step"><b class="m-num">4</b> Presence score + project risk</span></div>
      <div class="sum-row">${card("Packages checked", s.packagesChecked || data.sbom.length, 'data-goto="architecture" data-tab="sbom"')}${card("Advisories matched", all.length, 'data-risk-p=""')}${card("Confirmed in code", cnt("Confirmed in code"), `data-risk-p="Confirmed in code"`, "c-conf")}${card("Likely present", cnt("Likely present"), `data-risk-p="Likely present"`, "c-likely")}${card("Installed only", cnt("Installed only"), `data-risk-p="Installed only"`, "c-inst")}</div>
      <section class="panel"><div class="panel-header"><div><h2>Vulnerability report</h2><p>Vulnerabilities that are really present in this code base, most certain first. Click a row to see how it is linked to your modules and files.</p></div></div>
      <div class="table-filters"><div class="filter-chips">${["Confirmed in code", "Likely present", "Possible", "Installed only"].map(pchip).join("")}</div><div class="filter-chips">${["critical", "high", "medium", "low"].map(rchip).join("")}</div></div>
      <div class="vtable"><div class="vt-head"><span>ID</span><span>VULNERABILITY</span><span>ADVISORY</span><span>CVSS</span><span>PRESENCE IN YOUR CODE</span><span>PROJECT RISK</span><span>FIX</span></div>
      ${rows.map(v => `<button class="vt-row" data-open="${esc(v.id)}"><span class="mono">${esc(v.id)}</span><span><b>${esc(v.package)} ${esc(v.version)}</b><small>${esc(short(v.summary || v.title.replace(`${v.package} ${v.version}: `, ""), 95))}</small></span><span><span class="mono">${esc(v.vulnId)}</span><small>${esc((v.aliases || []).find(a => a.startsWith("CVE")) || "")}</small></span><span>${v.cvss ?? "?"}<small>${esc(v.band || "")}</small></span><span>${presBar(v.presence)}</span><span>${riskTag(v.risk)}</span><span class="fix-cell">${v.fixed?.length ? `≥ ${esc(v.fixed[0])}` : `<span class="muted-small">none listed</span>`}</span></button>`).join("") || `<div class="empty-state">No vulnerabilities match these filters.</div>`}${hidden ? `<button class="show-more" data-inst="1">Show ${hidden} more matches in packages your code never imports (installed only)</button>` : ""}</div></section>`;
  }

  function riskSuspicious() {
    const s = data.security, an = [...(s.anomalies || [])].sort((a, b) => sevNum(b) - sevNum(a));
    const flagCls = f => /dependency|image|action/.test(f) ? "fl-dep" : /outbound|network|secret/.test(f) ? "fl-net" : "fl-code";
    const anomalies = !s.anomalyRan ? `<div class="empty-state">Stage 5 (supply-chain anomalies) did not run for this scan.</div>` : an.length ? `<div class="vtable"><div class="vt-head at"><span>ID</span><span>SUBJECT</span><span>WHAT WAS SEEN</span><span>CHECKS</span><span>SUSPICION</span><span>RISK</span></div>${an.map(a => `<button class="vt-row at" data-open="${esc(a.id)}"><span class="mono">${esc(a.id)}</span><span><b>${esc(a.componentName || a.component)}</b><small>${esc(a.component.split(":")[0])}</small></span><span><small class="wrap">${esc(short(a.capability || a.title, 150))}</small></span><span>${(a.signals || []).slice(0, 3).map(g => `<span class="sig">${esc(g.check)}</span>`).join("")}</span><span class="cap">${esc(a.suspicion || "")}</span><span>${riskTag(a.risk)}</span></button>`).join("")}</div>` : `<div class="empty-state">No supply-chain anomalies were found.</div>`;
    const recent = (s.recent || []).filter(c => c.flags.length || c.findings.length).slice(0, 8);
    const commits = recent.map(c => `<div class="commit-row"><div class="commit-top"><code>${esc(c.sha)}</code><b>${esc(short(c.title, 80))}</b><span class="muted-small">${esc(c.date)}${c.author ? " · " + esc(c.author) : ""}</span></div>${c.flags.length ? `<div class="flags">${[...new Map(c.flags.map(f => [f.flag + f.label, f])).values()].slice(0, 8).map(f => f.id ? `<button class="flag ${flagCls(f.flag)}" data-node="${esc(f.id)}">${esc(f.flag)}: ${esc(short(f.label, 40))}</button>` : `<span class="flag ${flagCls(f.flag)}">${esc(f.flag)}: ${esc(short(f.label, 40))}</span>`).join("")}</div>` : ""}${c.findings.length ? `<div class="flags"><span class="muted-small">Findings touching this commit:</span>${c.findings.slice(0, 6).map(id => `<button class="ref-chip danger" data-open="${esc(id)}">${esc(id)}</button>`).join("")}</div>` : ""}</div>`).join("");
    const hot = (s.hotspots || []).map(h => `<button class="list-row" data-open="${esc(h.id)}"><span class="risk-dot ${h.level}"></span><span><b>${esc(h.label)}</b><small>${esc(h.what)} · ${esc(h.file)}:${h.line || ""}${h.public ? " · reachable from a route" : ""}</small></span>${riskTag(h.level)}</button>`).join("");
    const codeNotes = [...(s.code || [])].sort((a, b) => (RISK[b.risk] ?? -1) - (RISK[a.risk] ?? -1)).map(c => `<button class="list-row" data-open="${esc(c.id)}"><span class="finding-symbol notable">!</span><span><b>SQL injection in ${esc(c.function)}() · ${esc(c.file)}:${esc(c.line)}</b><small>Code vulnerability (CWE-89) · ${esc(c.risk)} · ${esc(short((c.reasons || [])[0] || "", 70))}</small></span>${riskTag(c.risk)}</button>`).join("");
    const notes = codeNotes + (s.notes || []).map(n => `<button class="list-row" data-open="${esc(n.id)}"><span class="finding-symbol ${n.severity}">${n.severity === "notable" ? "!" : n.severity === "review" ? "?" : "i"}</span><span><b>${esc(n.title)}</b><small>${esc(n.category)}</small></span></button>`).join("");
    const code = [...(s.code || [])].sort((a, b) => (RISK[b.risk] ?? -1) - (RISK[a.risk] ?? -1)).map(c => `<button class="vt-row at" data-open="${esc(c.id)}"><span class="mono">${esc(c.id)}</span><span><b>${esc(c.function)}()</b><small>${esc(c.file)}:${esc(c.line)}</small></span><span><small class="wrap">${esc(short(c.title, 150))}</small></span><span>${tag(c.cwe || "CWE-89", "orange")}</span><span><small>${esc(short((c.reasons || [])[0] || "", 60))}</small></span><span>${riskTag(c.risk)}</span></button>`).join("");
    const codePanel = (s.code || []).length ? panel("Code vulnerabilities in your own code", "Found by Guardian's code analysis (it parses the code, no database): SQL queries built by pasting user input into text (CWE-89). Each one has a code fix on the Remediation page.", `<div class="vtable"><div class="vt-head at"><span>ID</span><span>WHERE</span><span>WHAT WAS SEEN</span><span>TYPE</span><span>WHY THIS PRIORITY</span><span>RISK</span></div>${code}</div>`) : "";
    return `${codePanel}${panel("Supply-chain anomalies", "Behaviour checks that need no database: typosquatted names, install scripts, hash or lockfile changes, untrusted images, risky CI workflows, new outbound destinations", anomalies)}
      <div class="sus-grid">${panel("Recent changes", "Commits that added dependencies, network calls, routes, modules or images, and findings tied to them", `<div class="commit-list">${commits || `<div class="empty-state small">No flagged changes in the scanned history.</div>`}</div>`)}
      <div>${panel("Risky code in this repository", "Calls in your own code that no vulnerability database covers (shell, eval, network, files)", `<div class="list">${hot || `<div class="empty-state small">No risky calls found.</div>`}</div>`)}
      ${panel("Dependency & code observations", "Questions the investigator answered from the code (unused or undeclared packages, new modules, outbound data)", `<div class="list scroll">${notes || `<div class="empty-state small">None.</div>`}</div>`)}</div></div>`;
  }

  function riskEvidence(r) {
    const s = data.security, mode = r.p.get("show") || "attention";
    const all = [...(s.vulnerabilities || []), ...(s.anomalies || []), ...(s.code || [])].sort((a, b) => sevNum(b) - sevNum(a));
    const rows = mode === "all" ? all : all.filter(attention);
    const connSum = x => { const c = x.connections || [], k = t => c.filter(y => y.kind === t).length; return [k("commit") && `${k("commit")} commit${k("commit") > 1 ? "s" : ""}`, k("anomaly") && `${k("anomaly")} anomal${k("anomaly") > 1 ? "ies" : "y"}`, k("hotspot") && `${k("hotspot")} risky call`, x.siblings && `${x.siblings} more CVEs in package`, x.sites?.length && `${x.sites.length} code site${x.sites.length > 1 ? "s" : ""}`].filter(Boolean).join(" · ") || "—"; };
    const evSum = x => { const c = x.claims || []; return c.length ? `<span class="ev-ok">✓ ${c.filter(y => y.verified).length}/${c.length}</span> verified` : `<span class="muted-small">no claims</span>`; };
    return `<div class="method-strip"><span class="m-step">Each row is one finding from steps 3 and 4. <b>Evidence</b> = claims whose cited lines were re-read from the repository and confirmed. <b>Investigation</b> = the steps the investigator agent took: reading the advisory, querying the knowledge graph, searching and reading code, then an independent verification pass.</span></div>
      <section class="panel"><div class="panel-header"><div><h2>Evidence report</h2><p>${rows.length} finding${rows.length === 1 ? "" : "s"} · click one to see where it was found, what it connects to, and how the evidence was gathered</p></div><div class="filter-chips"><button class="filter-chip ${mode !== "all" ? "active" : ""}" data-ev-show="attention">Needs attention <small>${all.filter(attention).length}</small></button><button class="filter-chip ${mode === "all" ? "active" : ""}" data-ev-show="all">All <small>${all.length}</small></button><button class="quiet-button" id="ev-download">⤓ Report JSON</button></div></div>
      <div class="vtable"><div class="vt-head ev"><span>#</span><span>FINDING</span><span>FOUND IN</span><span>RISK</span><span>CONFIDENCE</span><span>CONNECTED TO</span><span>EVIDENCE</span><span>STEPS</span></div>
      ${rows.map(x => `<button class="vt-row ev" data-open="${esc(x.id)}"><span class="mono">${esc(x.id)}</span><span><b>${esc(x.kind === "vulnerability" ? `${x.package} ${x.version} · ${x.vulnId}` : (x.componentName || x.component))}</b><small>${esc(short(x.kind === "vulnerability" ? x.explanation : x.capability || x.title, 110))}</small></span><span>${x.kind === "vulnerability" ? tag("Vulnerability report", "blue") : x.kind === "code" ? tag("Code analysis", "orange") : tag("Suspicious report", "amber")}</span><span>${riskTag(x.risk)}</span><span>${x.presence ? `<b>${x.presence.score}%</b> <small>${esc(x.presence.label)}</small>` : `<span class="cap">${esc(x.confidence || "")}</span>`}</span><span><small class="wrap">${esc(connSum(x))}</small></span><span>${evSum(x)}</span><span class="mono">${(x.trace || []).length || "—"}</span></button>`).join("") || `<div class="empty-state">Nothing needs attention. Switch to “All”.</div>`}</div></section>`;
  }

  // ---------- popup windows
  function modalHtml(id, tab) {
    const x = FIND.get(id);
    if (!x) return "";
    const body = tab === "evidence" && (x.kind === "vulnerability" || x.kind === "anomaly") ? evidenceModal(x) : x.kind === "vulnerability" ? vulnModal(x) : x.kind === "anomaly" ? anomalyModal(x) : x.kind === "hotspot" ? hotspotModal(x) : x.kind === "code" ? codeModal(x) : noteModal(x);
    return `<div class="modal-back" id="modal-back"><div class="modal" role="dialog" aria-modal="true"><button class="modal-x" id="modal-x" aria-label="Close">×</button>${body}</div></div>`;
  }
  const msec = (label, body) => body ? `<div class="m-sec"><div class="detail-label">${label}</div>${body}</div>` : "";

  function linkChain(v) {
    const pkg = N.get(v.component), siteFns = new Set((v.sites || []).map(s => s.function));
    const users = pkg ? inc(v.component, "USES", "IMPORTS_PKG").map(e => N.get(e.id)).filter(Boolean) : [];
    const files = [...new Set([...(v.files || []).map(f => `file:${f}`), ...users.map(u => u.t === "file" ? u.id : u.file).filter(Boolean)])].filter(f => N.has(f));
    const fns = [...new Set([...siteFns, ...users.filter(u => u.t === "function" || u.t === "class").map(u => u.id)])].filter(f => N.has(f));
    const mods = [...new Set([...fns, ...files].map(id => N.get(id)?.m).filter(Boolean))];
    const col = (label, items) => `<div class="chain-col"><div class="chain-h">${label}</div>${items.length ? items.join("") : `<span class="muted-small">—</span>`}</div>`;
    const item = (id, lab, hot, sub = "") => `<button class="chain-item ${hot ? "hot" : ""}" data-node="${esc(id)}">${esc(short(lab, 34))}${sub ? `<small>${esc(sub)}</small>` : ""}</button>`;
    const declared = (v.path || []).filter(p => !p.startsWith("pkg:")).map(p => `<span class="chain-item plain">${esc(p)}</span>`);
    return `<div class="chain">${col("Declared in", declared)}<i class="chain-arrow">→</i>${col("Package", [pkg ? `<button class="chain-item hot" data-pkg="${esc(v.component)}">${esc(v.package)} ${esc(v.version)}</button>` : `<span class="chain-item plain">${esc(v.package)} ${esc(v.version)}</span>`])}<i class="chain-arrow">→</i>${col("Files", files.slice(0, 8).map(f => item(f, N.get(f).l, (v.files || []).includes(N.get(f).l))))}<i class="chain-arrow">→</i>${col("Functions", fns.sort((a, b) => siteFns.has(b) - siteFns.has(a)).slice(0, 8).map(f => item(f, N.get(f).l, siteFns.has(f), siteFns.has(f) ? "calls vulnerable code" : "uses the package")))}<i class="chain-arrow">→</i>${col("Modules", mods.slice(0, 6).map(m => item(m, modName(m), false)))}<i class="chain-arrow">→</i>${col("Reachable from", (v.entryIds || []).slice(0, 6).map((id, i) => N.has(id) ? item(id, v.entries[i], true) : `<span class="chain-item plain">${esc(v.entries[i])}</span>`))}</div>
      <p class="muted-small chain-note">Highlighted boxes are on the vulnerable path. ${fns.length ? "Click any box to open it in the architecture graph." : "No file in this repository imports the package, so the vulnerable code is installed but never loaded by your code."}</p>`;
  }
  function vulnModal(v) {
    const cve = (v.aliases || []).filter(a => a.startsWith("CVE"));
    return `<div class="m-head"><div class="eyebrow">VULNERABILITY REPORT · ${esc(v.id)} · from OSV</div><h2>${esc(v.package)} ${esc(v.version)} <span class="m-sub">${esc(v.vulnId)}</span></h2><div class="m-tags">${riskTag(v.risk)}${cve.map(a => tag(a, "muted")).join("")}${v.kev ? tag("Known exploited (CISA KEV)", "orange") : ""}</div><p class="m-lead">${esc(v.summary || v.title)}</p></div>
      <div class="m-grid"><div class="pres-card"><div class="detail-label">PRESENCE IN YOUR CODE</div><div class="pres-big ${PRES_CLS[v.presence?.label] || ""}">${v.presence?.score ?? "?"}<span>%</span></div><b>${esc(v.presence?.label || "")}</b><ul class="factor-list">${(v.presence?.factors || []).map(f => `<li><span class="pts ${f.points < 0 ? "neg" : ""}">${f.points > 0 ? "+" : ""}${f.points}</span>${esc(f.text)}</li>`).join("")}</ul></div>
      <div class="vuln-facts col"><span><small>CVSS</small><b>${v.cvss ?? "?"} ${esc(v.band || "")}</b></span><span><small>PROJECT RISK</small><b>${esc(v.risk)}</b></span><span><small>IN YOUR CODE</small><b>${esc(usageLabel(v))}</b></span><span><small>REACHABILITY</small><b>${esc((v.reachability || "").replace(/_/g, " "))}</b></span><span><small>FIXED IN</small><b>${esc((v.fixed || []).join(", ") || "—")}</b></span><span><small>PUBLISHED</small><b>${esc(v.published || "—")}</b></span></div></div>
      ${msec("HOW IT IS LINKED TO YOUR CODE", linkChain(v))}
      ${msec("WHERE YOUR CODE CALLS IT", (v.sites || []).length ? `<div class="site-list">${v.sites.map(s => `<div class="site"><div>${nodeBtn(s.function, s.label)}<small>${esc(s.file)}:${esc(s.lines)}</small></div>${s.code ? `<code>${esc(s.code)}</code>` : ""}</div>`).join("")}</div>` : "")}
      ${msec("WHY THIS RISK", `<p class="plain">${esc(v.explanation || "")}</p>${v.rule ? `<p class="muted-small">Rule: ${esc(v.rule)}</p>` : ""}`)}
      ${(v.unknowns || []).length ? msec("NOT VERIFIED", `<ul class="reason-list">${v.unknowns.map(u => `<li>${esc(u)}</li>`).join("")}</ul>`) : ""}
      <div class="fix-box"><b>Fix</b> ${esc(v.recommendation || "Upgrade to a fixed version.")}</div>
      ${(v.references || []).filter(Boolean).length ? msec("REFERENCES", v.references.filter(Boolean).map(u => `<a class="ref-link" href="${esc(u)}" target="_blank" rel="noopener">${esc(short(u, 80))} ↗</a>`).join("")) : ""}
      <div class="finding-actions">${(v.sites || [])[0] ? link("Show in architecture graph →", `data-node="${esc(v.sites[0].function)}"`, "primary-button") : ""}${link("Evidence report →", `data-evidence="${esc(v.id)}"`, "quiet-button")}${link("Open in SBOM", `data-pkg="${esc(v.component)}"`, "quiet-button")}${mode === "web" ? link("Plan the fix →", `data-remfor="${esc(v.id)}"`, "quiet-button") : ""}</div>`;
  }
  function anomalyModal(a) {
    return `<div class="m-head"><div class="eyebrow">SUSPICIOUS REPORT · ${esc(a.id)} · behaviour check</div><h2>${esc(a.componentName || a.component)}</h2><div class="m-tags">${riskTag(a.risk)}${(a.detectors || []).map(d => tag(d, "muted")).join("")}</div><p class="m-lead">${esc(a.capability || a.title)}</p></div>
      <div class="vuln-facts"><span><small>SUSPICION</small><b>${esc(a.suspicion || "?")}</b></span><span><small>EXPOSURE</small><b>${esc((a.exposure || "").replace(/_/g, " "))}</b></span><span><small>CONFIDENCE</small><b>${esc(a.confidence || "")}</b></span><span><small>REVIEW</small><b>${esc(a.review || "—")}</b></span></div>
      ${msec("SIGNALS", `<div class="sig-list">${(a.signals || []).map(g => `<div class="sig-row"><span class="sig">${esc(g.detector)} · ${esc(g.check)}</span><span>${esc(g.text || "")}</span><small>${esc(g.strength || "")}</small></div>`).join("")}</div>`)}
      ${msec("WHAT WAS SEEN", `<p class="plain">${esc(a.explanation || "")}</p>${a.exposureNote ? `<p class="muted-small">${esc(a.exposureNote)}</p>` : ""}`)}
      ${a.normal ? msec("POSSIBLE NORMAL EXPLANATION", `<p class="plain">${esc(a.normal)}</p>`) : ""}
      ${msec("EVIDENCE", `<div class="evidence-list">${(a.evidence || []).map(e => `<span class="evidence-chip"><span>⌖</span>${esc(e.file || "")}${e.lines ? ":" + esc(e.lines) : ""}</span>`).join("")}</div>`)}
      <div class="fix-box"><b>Recommendation</b> ${esc(a.recommendation || "")}</div>
      <div class="finding-actions">${a.function && N.has(a.function) ? link("Show in architecture graph →", `data-node="${esc(a.function)}"`, "primary-button") : N.has(a.component) ? link("Show in graph →", `data-node="${esc(a.component)}"`, "primary-button") : ""}${link("Evidence report →", `data-evidence="${esc(a.id)}"`, "quiet-button")}${mode === "web" ? link("Plan the fix →", `data-remfor="${esc(a.id)}"`, "quiet-button") : ""}</div>`;
  }
  function codeModal(c) {
    return `<div class="m-head"><div class="eyebrow">CODE VULNERABILITY · ${esc(c.id)} · ${esc(c.cwe || "CWE-89")} SQL injection</div><h2>${esc(c.function)}() in ${esc(c.file)}</h2><div class="m-tags">${riskTag(c.risk)}${tag("found by Guardian's code analysis", "orange")}</div></div>
      ${msec("WHAT WAS SEEN", `<p class="plain">The query is built by pasting values into the SQL text, so an input like <code>' OR '1'='1</code> changes the query itself (e.g. a login without the password).</p>${diffHtml(`--- vulnerable (${c.file}:${c.line})\n+++ fix Guardian proposes (parameterized query)\n-${c.old}\n+${c.new}`)}`)}
      ${msec("WHY THIS PRIORITY", `<ul class="reason-list">${(c.reasons || []).map(x => `<li>${esc(x)}</li>`).join("")}</ul>`)}
      ${msec("WHERE", `<p class="plain">${(c.sites || []).map(x => `<code>${esc(x)}</code>`).join(" ")}</p>`)}
      <div class="finding-actions">${mode === "web" ? link("Plan the fix → (Remediation)", `data-remfor="${esc(c.id)}"`, "primary-button") : ""}</div>`;
  }
  function hotspotModal(h) {
    return `<div class="m-head"><div class="eyebrow">SUSPICIOUS REPORT · ${esc(h.id)} · risky code</div><h2>${esc(h.label)}</h2><div class="m-tags">${riskTag(h.level)}${tag(h.category, "muted")}</div><p class="m-lead">${esc(h.what)}: <code>${esc(h.calls.join(", "))}</code> at ${esc(h.file)}:${esc(h.lines.join(", "))}.</p></div>
      ${msec("WHY IT MATTERS", `<p class="plain">${esc(h.why)}</p>`)}
      ${msec("REACHABLE FROM", h.reachableFrom.length ? `<div class="route-chips">${h.reachableFrom.map(x => tag(x, "violet")).join("")}</div>` : `<span class="muted-small">No public route reaches it (internal or CLI only).</span>`)}
      <div class="open-question"><span>?</span><div><b>Not a confirmed vulnerability</b><p>No database lists bugs in your own code. This flags the risky call so a reviewer can check whether untrusted input reaches it.</p></div></div>
      <div class="finding-actions">${link("Show in architecture graph →", `data-node="${esc(h.function)}"`, "primary-button")}</div>`;
  }
  function noteModal(n) {
    return `<div class="m-head"><div class="eyebrow">INVESTIGATOR OBSERVATION · ${esc(n.category || "")}</div><h2>${esc(n.title)}</h2><div class="m-tags">${tag(n.status === "unresolved" ? "Unresolved" : "Answered", n.status === "unresolved" ? "orange" : "green")}</div><p class="m-lead">${esc(n.text || "")}</p></div>${msec("EVIDENCE REVIEWED", `<div class="evidence-list">${(n.evidence || []).map(e => `<span class="evidence-chip"><span>⌖</span>${esc(e)}</span>`).join("")}</div>`)}`;
  }
  function evidenceModal(x) {
    const isV = x.kind === "vulnerability";
    const conn = (x.connections || []).map(c => c.kind === "commit" ? `<div class="conn"><span class="conn-k">commit</span><span>${esc(c.label)}</span><small>${esc(c.date || "")}</small></div>` : `<button class="conn" data-open-item="${esc(c.id)}"><span class="conn-k">${esc(c.kind)}</span><span><b>${esc(c.id)}</b> ${esc(short(FIND.get(c.id) ? (FIND.get(c.id).kind === "vulnerability" ? `${FIND.get(c.id).package} ${FIND.get(c.id).vulnId}` : FIND.get(c.id).title) : "", 80))}</span>${FIND.get(c.id) ? riskTag(FIND.get(c.id).risk) : ""}</button>`).join("");
    const code = isV ? (x.sites || []).map(s => nodeBtn(s.function, s.label, `<small>${esc(s.file)}:${esc(s.lines)}</small>`)).join("") : (x.function && N.has(x.function) ? nodeBtn(x.function) : "") + (N.has(x.component) ? nodeBtn(x.component) : "");
    const claims = (x.claims || []).map(c => `<div class="claim ${c.verified ? "ok" : "bad"}"><span class="claim-i">${c.verified ? "✓" : "✕"}</span><div><b>${esc(c.text)}</b>${c.evidence.length ? `<div class="evidence-list">${c.evidence.map(e => `<span class="evidence-chip"><span>⌖</span>${esc(e)}</span>`).join("")}</div>` : ""}${c.lines.length ? `<code class="claim-code">${c.lines.map(esc).join("\n")}</code>` : ""}${c.reason ? `<small>${esc(c.reason)}</small>` : ""}</div></div>`).join("");
    const steps = (x.trace || []).map((t, i) => `<div class="tstep ${t.ok ? "" : "fail"}"><span class="tnum">${i + 1}</span><div><div class="ttop"><span class="tstage">${esc(t.stage || "")}</span><b>${esc(t.action || "")}</b>${t.tool ? `<code>${esc(t.tool)}</code>` : ""}</div>${t.input ? `<small class="tin">${esc(t.input)}</small>` : ""}<p>${esc(t.result)}</p></div></div>`).join("");
    return `<div class="m-head"><div class="eyebrow">EVIDENCE REPORT · ${esc(x.id)}</div><h2>${esc(isV ? `${x.package} ${x.version} · ${x.vulnId}` : (x.componentName || x.component))}</h2><div class="m-tags">${riskTag(x.risk)}${isV && x.presence ? tag(`${x.presence.score}% · ${x.presence.label}`, "blue") : tag(`suspicion ${x.suspicion || "?"}`, "amber")}${tag(`confidence ${x.confidence || "?"}`, "muted")}</div><p class="m-lead">${esc(isV ? x.explanation : x.explanation || x.capability)}</p></div>
      <div class="ev-flow"><button class="ev-box" data-open-item="${esc(x.id)}"><small>FOUND IN</small><b>${isV ? "Vulnerability report (step 3)" : "Suspicious report (step 4)"}</b><span>Open the finding ↗</span></button><i>→</i><div class="ev-box"><small>WHERE IN THE CODE</small>${code || `<span class="muted-small">${isV ? "Package installed; not loaded by your code" : "Repository metadata"}</span>`}</div><i>→</i><div class="ev-box"><small>CONFIDENCE BECAUSE</small>${(x.confidenceReasons || []).map(r => `<span>${esc(r)}</span>`).join("") || "<span>—</span>"}</div></div>
      ${msec("CONNECTED TO", conn ? `<div class="conn-list">${conn}</div>` : `<span class="muted-small">No related commits or findings.</span>`)}
      ${msec(`EVIDENCE · ${(x.claims || []).filter(c => c.verified).length} of ${(x.claims || []).length} claims verified against the repository`, claims || `<span class="muted-small">This finding was classified in the light pass (no agent claims).</span>`)}
      ${msec(`HOW THE INVESTIGATOR GATHERED IT · ${(x.trace || []).length} steps`, steps ? `<div class="trace">${steps}</div>` : `<span class="muted-small">Classified by fixed rules from the SBOM and the graph, without an agent investigation (low-priority match).</span>`)}
      ${suggestBox(x)}`;
  }
  function downloadEvidence() {
    const s = data.security, pick = x => { const { trace, claims, connections, presence, ...rest } = x; return { ...rest, presence, connections, claims, investigation: trace }; };
    const rep = { repository: data.repo.name, commit: data.repo.commit, generated: new Date().toISOString(), vulnerabilities: (s.vulnerabilities || []).map(pick), suspicious: (s.anomalies || []).map(pick), riskyCode: s.hotspots || [] };
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([JSON.stringify(rep, null, 2)], { type: "application/json" }));
    a.download = `${data.repo.name || "guardian"}-evidence-report.json`; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  }

  // ------------------------------------------------------------------ page 4: remediation (Day 2)
  const REM = { scan: null, list: null, detail: new Map(), loading: false, err: null, timer: null, msg: null };
  const remApi = (p, opts) => fetch(`/api/scans/${encodeURIComponent(scanId)}${p}`, opts).then(async r => { const j = await r.json().catch(() => ({})); if (!r.ok) throw new Error(typeof j.detail === "string" ? j.detail : `HTTP ${r.status}`); return j; });
  const reviewer = () => localStorage.getItem("guardian-reviewer") || "reviewer";
  const CONF_CLS = { high: "green", medium: "amber", low: "orange" };
  const confTag = (label, c) => c ? `<span class="conf-pill ${c}">${label} <b>${esc(c)}</b></span>` : "";
  const DEC_CLS = { "Act": "act", "Attend": "attend", "Track*": "trackstar", "Track": "track" };
  const decTag = d => d ? `<span class="dec-tag ${DEC_CLS[d] || ""}">${esc(d)}</span>` : "";
  const TAB_LABEL = { decide: "Needs your decision", ready: "Ready", auto: "Auto-planned", unresolved: "Unresolved", decided: "Decided" };
  const STATUS_LABEL = { awaiting_proposal_review: "Proposal awaiting review", awaiting_patch_review: "Tested patch awaiting approval", applied: "Applied to a fix branch", rejected: "Rejected" };
  const remFor = fid => (REM.list?.items || []).find(i => i.finding_ids.includes(fid));

  async function loadRem(rid, quiet) {
    if (mode !== "web" || !scanId) return;
    if (REM.scan !== scanId) { REM.scan = scanId; REM.list = null; REM.detail.clear(); }
    try {
      [REM.list, REM.queue, REM.bulk] = await Promise.all([remApi("/remediations"), remApi("/queue").catch(() => null), remApi("/bulk-approve").catch(() => null)]);
      if (rid) REM.detail.set(rid, await remApi(`/remediations/${encodeURIComponent(rid)}`));
      REM.err = null;
    } catch (e) { REM.err = e.message; }
    const cur = route();
    if (cur.view === "remediate" && !(quiet && document.activeElement?.tagName === "TEXTAREA")) render();
    const working = (REM.list?.items || []).some(i => i.working) || !!REM.queue?.running || (REM.queue?.pending || []).length;
    clearTimeout(REM.timer);
    if (working && route().view === "remediate") REM.timer = setTimeout(() => loadRem(route().p.get("open"), true), 1500);
  }

  function renderRemediate(r) {
    const head = title("REMEDIATION", "Fix <span class='title-suffix'>& approve</span>", "Every finding gets a prioritised, checked fix. High-priority items that are not certain wait for your decision; nothing is applied without your approval of the tested patch.");
    const flow = `<div class="method-strip rm-flow">${["Prioritized risk", "Recommended fix", "Human approval", "Build & test", "Rescan", "Verified remediation"].map((s, i) => `<span class="m-step"><b class="m-num">${i + 1}</b> ${s}</span>`).join("<i>→</i>")}</div>`;
    if (mode !== "web") return head + `<div class="panel empty-big"><p>Remediation needs the Guardian server (approvals, sandbox validation and the agent run there):</p><pre class="cmd">python -m guardian.cli web --root output/scans</pre></div>`;
    if (REM.scan !== scanId || (!REM.list && !REM.err)) { loadRem(r.p.get("open")); return head + flow + `<div class="panel empty-big"><p>Loading remediation plan…</p></div>`; }
    if (REM.err && !REM.list) return head + `<div class="banner-warn">${esc(REM.err)}</div>`;
    if (!REM.list.available) return head + flow + `<div class="panel empty-big"><p>This scan has no remediation plan yet. Run <code>python -m guardian.cli remediate output/scans/${esc(scanId)}</code> (new scans do this automatically).</p></div>`;
    const tab = r.p.get("tab") || (REM.list.counts.decide ? "decide" : "all"), c = REM.list.counts;
    const items = REM.list.items.filter(i => tab === "all" || i.tab === tab).sort((a, b) => a.rank - b.rank);
    const chip = (k, l, n) => `<button class="filter-chip ${tab === k ? "active" : ""}" data-rm-tab="${k}">${l} <small>${n}</small></button>`;
    const rows = items.map(i => `<button class="vt-row rm" data-rm-open="${esc(i.rid)}"><span class="mono">${esc(i.rid)}<small>#${i.rank}</small></span><span><b>${esc(i.target_label)}</b><small>${esc(short(i.action || "", 110))}</small><small class="muted-small">${i.finding_ids.map(esc).join(" · ")}${i.author && i.author !== "template" ? " · by agent" : ""}${i.target_kind === "build_health" ? " · build health (not a CVE)" : i.target_kind === "code" ? " · code change in your app (CWE-89)" : ""}</small></span><span>${decTag(i.decision)}</span><span>${riskTag(i.priority)}${i.stage_risk !== i.priority ? `<small>rules: ${esc(i.stage_risk)}</small>` : ""}</span><span>${confTag("", i.finding_confidence)}</span><span>${confTag("", i.fix_confidence)}</span><span class="rm-status">${i.working ? `<span class="spin"></span> ${esc(i.working.what)}` : esc(STATUS_LABEL[i.status] || i.status || "")}${i.branch ? `<small class="mono">${esc(i.branch)}</small>` : ""}${i.tab === "decide" && i.gate_reasons.length ? `<small>${esc(i.gate_reasons.join(" · "))}</small>` : ""}</span></button>`).join("");
    const open = r.p.get("open");
    return head + flow + queueStrip() + `<section class="panel"><div class="panel-header"><div><h2>Remediation plan</h2><p>${REM.list.items.length} remediations for ${REM.list.items.reduce((n, i) => n + i.finding_ids.length, 0)} findings · one upgrade can fix several CVEs · workflow engine: ${esc(REM.list.engine || "")}</p></div></div>
      <div class="table-filters"><div class="filter-chips">${chip("decide", "Needs your decision", c.decide)}${chip("ready", "Ready", c.ready)}${chip("auto", "Auto-planned", c.auto)}${chip("unresolved", "Unresolved", c.unresolved)}${chip("decided", "Decided", c.decided)}${chip("all", "All", REM.list.items.length)}</div></div>
      <div class="vtable"><div class="vt-head rm"><span>ID</span><span>REMEDIATION</span><span>DECISION</span><span>PRIORITY</span><span>FINDING CONF.</span><span>FIX CONF.</span><span>STATUS</span></div>${rows || `<div class="empty-state">Nothing in this tab.</div>`}</div></section>`
      + (open ? remModal(open) : "");
  }

  function diffHtml(d) {
    return `<pre class="diff">${d.split("\n").map(l => `<span class="${l.startsWith("+++") || l.startsWith("---") ? "dh" : l.startsWith("@@") ? "dc" : l.startsWith("+") ? "da" : l.startsWith("-") ? "dd" : ""}">${esc(l)}</span>`).join("\n")}</pre>`;
  }
  const CHK_LABEL = { patch_applies: "Patch applies", scope_ok: "Only allowed files", candidate_clean: "New version has no known vulns", constraints_resolve: "Dependency constraints resolve", available: "Version on the index", runtime_compatible: "Python version compatible", lockfile_consistent: "Lockfile matches manifest", security_check: "Security check on patched files", ai_critic: "Independent AI review", build: "Build", tests: "Tests (no regressions)", rescan_resolved: "Rescan: finding resolved", no_new_vulns: "Rescan: nothing new introduced", install: "Dependencies install", deps_compatible: "Installed set is consistent", proof_of_fix: "Proof-of-fix probe", security_tests: "Guardian security tests (before → after)", target_install: "Installs on the target Python", target_boot: "Starts on the target Python" };

  // ---- validation report: what each check proves, how it is run, and its raw evidence
  const METHOD = { static: ["STATIC", "reads the files and package metadata; runs nothing"], dynamic: ["DYNAMIC", "runs the code in a throwaway sandbox"], rescan: ["RESCAN", "runs the whole Guardian scan again on the patched copy (OSV database + supply-chain checks)"], ai: ["AI", "a second model reviews the patch; advisory only"] };
  const CHECK_INFO = {
    patch_applies: { m: "static", proves: "The diff is well-formed and applies to the exact files in the repository at HEAD.", how: "git apply --check on a scratch copy of the repository.", unknown: "" },
    scope_ok: { m: "static", proves: "The patch only touches files this kind of fix is allowed to change (the skill's file list), so a fix cannot quietly edit unrelated code.", how: "Every changed path is matched against the allowed paths of the skill that produced the fix.", unknown: "" },
    lockfile_consistent: { m: "static", proves: "The manifest and the lockfile agree after the patch, so the version that gets installed is the version that was reviewed.", how: "Compares the pinned version in requirements*.txt with the lockfile entry.", unknown: "" },
    build: { m: "static", proves: "The patched project still compiles and its dependency files are valid.", how: "python -m compileall on every file; every requirement line is parsed; changed workflow files must be valid YAML.", unknown: "" },
    security_check: { m: "static", proves: "The specific change that removes the risk is really in the patched files (the new pin, the removed package, the safe API call).", how: "Reads the patched files and checks the target: e.g. the manifest now pins the fixed version, no unsafe yaml.load( call is left.", unknown: "No automatic check exists for this kind of change; a reviewer has to read the diff." },
    candidate_clean: { m: "static", proves: "The new version does not bring its own known vulnerabilities.", how: "OSV lookup for the exact target version. The sandbox rescan settles it when the static lookup could not run.", unknown: "OSV could not be queried when the fix was planned (offline). Run the sandbox validation: the rescan looks the version up." },
    available: { m: "static", proves: "The target version exists on the package index and is not yanked.", how: "Release list from PyPI (or the configured index). Settled by the sandbox when the install downloads it.", unknown: "The release list was not available. The sandbox install proves it by downloading the version." },
    runtime_compatible: { m: "static", proves: "The new version supports the project's Python version.", how: "The release's requires_python against the project's Python (Dockerfile, .python-version, CI, or the running interpreter).", unknown: "requires_python was not available. A successful sandbox install proves compatibility with the Python it used." },
    constraints_resolve: { m: "static", proves: "No other dependency pins a range that excludes the new version.", how: "Reads the lockfile's dependency constraints; in the sandbox, pip check verifies the whole installed set.", unknown: "There is no lockfile, so the dependents' constraints are unknown statically. pip check in the sandbox settles it." },
    install: { m: "dynamic", proves: "The patched dependency set really installs, from the real index, on a real Python.", how: "A throwaway virtual environment (uv) is created next to the worktree. The project's requirements at HEAD are installed first, then the patched requirements; Python versions are tried in order (project pin, current, 3.12, 3.11) until the original set installs.", unknown: "" },
    deps_compatible: { m: "dynamic", proves: "After the upgrade every installed package's own requirements are still satisfied: no hidden version conflict.", how: "pip check on the patched environment, compared with pip check before the patch. Conflicts that already existed, and those caused by the test runner Guardian adds, do not count.", unknown: "" },
    tests: { m: "dynamic", proves: "The application still behaves as its own test-suite expects: no regression.", how: "The repository's own tests (test_*.py, *_test.py, tests.py) run with pytest in the sandbox environment, before and after the patch. A test that already failed before is not a regression. Guardian does not write these tests; they are the project's.", unknown: "Test files exist but none ran (collection failed)." },
    proof_of_fix: { m: "dynamic", proves: "The vulnerable behaviour itself is gone, not just the version number: the same probe shows the bug on the old version and not on the new one.", how: "An AI agent writes a small probe script per CVE from the advisory text. It passes a safety check (no network, process, shell, eval, file deletion or version reading), then runs in two isolated environments: old version and new version. If it cannot show the difference, both outputs go back to the agent (up to 3 tries). The verdict comes from the observed output, never from the model.", unknown: "The agent could not write a probe that reproduces the bug on the old version. That is not evidence against the fix: the rescan and the tests still apply." },
    rescan_resolved: { m: "rescan", proves: "Guardian itself no longer reports the finding on the patched code.", how: "The full scan (SBOM, code map, OSV matching, supply-chain checks) runs again on the patched worktree, with the same vulnerability source as the original scan, and the findings are compared one by one.", unknown: "The rescan could not decide (e.g. no vulnerability data, or the risk was only reduced)." },
    no_new_vulns: { m: "rescan", proves: "The fix does not introduce a new vulnerability or a new supply-chain warning.", how: "Findings of the rescan that the original scan did not have. A new CVE or verified harmful behaviour fails; a metadata-only change signal (e.g. project URLs changed in the new release) needs a person to look.", unknown: "The rescan found a new warning that is not proof of harm; read it below." },
    security_tests: { m: "dynamic", proves: "Tests Guardian wrote for this fix behave as expected on the code before and after it: T1 exploit and T2 guard fail before and pass after, T3 feature passes on both.", how: "One pytest file per fix in tests/guardian/, run in the original environment (before) and the patched one (after). T1 comes from a curated reference exploit or from a proof-of-fix probe that was proven; T1 and T3 are kept only if the expected result was observed. The tests are committed with the fix.", unknown: "Fewer than two tests could be kept, or there was no before environment, so fail → pass could not be observed." },
    target_install: { m: "dynamic", proves: "The patched dependencies install on the Python the project says it runs on (its Dockerfile, .python-version or runtime.txt).", how: "A fresh environment on the target Python; the patched requirements are installed from the real index.", unknown: "" },
    target_boot: { m: "dynamic", proves: "The patched app really starts on the target Python and answers HTTP requests: an old pin can install and still crash at import.", how: "Flask/FastAPI/Django is detected, the database is created on a temporary SQLite file, the server is started on a free local port, and / plus up to 5 parameter-free GET routes are requested. Healthy = no 5xx and at least one 2xx/3xx.", unknown: "" },
    ai_critic: { m: "ai", proves: "An independent model, given the evidence and the diff, agrees that the patch removes the cited vulnerable path.", how: "One structured call to a second model with the evidence pack and all check results. Answers citing unknown evidence are rejected. Advisory only: it can lower confidence but never raise it on its own.", unknown: "The model was unsure." },
  };
  const VQ = [
    ["Is the change correct and contained?", ["patch_applies", "scope_ok", "lockfile_consistent", "build"]],
    ["Does it remove the vulnerability?", ["security_check", "security_tests", "rescan_resolved", "proof_of_fix", "candidate_clean", "ai_critic"]],
    ["Does it break anything or add new risk?", ["target_install", "target_boot", "install", "deps_compatible", "tests", "available", "runtime_compatible", "constraints_resolve", "no_new_vulns"]],
  ];
  const SANDBOX_KEYS = ["build", "install", "deps_compatible", "tests", "proof_of_fix", "security_tests", "rescan_resolved", "no_new_vulns"];
  const ICON = { pass: "✓", fail: "✕", unknown: "?", unsure: "?", "n/a": "–", skipped: "–", pending: "…" };
  const pre = (t, cls = "") => t ? `<pre class="vlog ${cls}">${esc(t)}</pre>` : "";
  const kv = (k, val) => val ? `<div class="vkv"><small>${esc(k)}</small><span>${val}</span></div>` : "";

  function chkEvidence(k, c, p, v) {
    const ev = [];
    if (c.confirmed_by) ev.push(kv("Before the sandbox", esc(c.static_detail || "")), kv("Settled by", "the sandbox run"));
    if (k === "patch_applies" && p.diff) ev.push(kv("Diff", `${(p.diff.match(/^\+[^+]/gm) || []).length} line(s) added, ${(p.diff.match(/^-[^-]/gm) || []).length} removed in ${(p.edits || []).map(e => esc(e.path)).join(", ")}`));
    if (k === "install" && v) {
      const at = (v.env?.attempts || v.install?.attempts || []);
      if (at.length) ev.push(kv("Python versions tried", at.map(a => `${a.ok ? "✓" : "✕"} ${esc(a.python)}${a.ok ? "" : ` <small>(${esc(short(a.error || "", 90))})</small>`}`).join("<br>")));
      ev.push(kv("Environment", esc([v.install?.tool && `${v.install.tool} venv`, v.install?.python && `Python ${v.install.python}`].filter(Boolean).join(" · "))));
      ev.push(kv("Command", v.install?.command ? `<code>${esc(v.install.command)}</code>` : ""));
      if (v.install?.log?.trim()) ev.push(pre(v.install.log));
    }
    if (k === "deps_compatible" && v?.deps_check) {
      const d = v.deps_check;
      ev.push(kv("New conflicts", d.new?.length ? d.new.map(esc).join("<br>") : "none"));
      if (d.preexisting?.length) ev.push(kv("Already there before the patch", d.preexisting.map(esc).join("<br>")));
      if (d.ignored_tool?.length) ev.push(kv("Ignored (from Guardian's test runner)", d.ignored_tool.map(esc).join("<br>")));
    }
    if (k === "tests" && v?.tests) {
      const t = v.tests;
      ev.push(kv("Test files (from the repository)", (t.files || []).map(f => `<code>${esc(f)}</code>`).join(" ") || "none found"));
      ev.push(kv("Command", t.after?.command ? `<code>${esc(t.after.command)}</code>` : ""));
      ev.push(kv("Before the patch", esc(t.before?.summary || "")), kv("After the patch", esc(t.after?.summary || "")));
      if (t.after?.log) ev.push(`<details class="vsub"><summary>pytest output after the patch</summary>${pre(t.after.log)}</details>`);
    }
    if (k === "proof_of_fix" && v?.probe) {
      const pr = v.probe;
      ev.push(kv("Versions", `${esc(pr.package || "")} ${esc(pr.old || "")} (vulnerable) vs ${esc(pr.new || "")} (fixed)${pr.python ? ` · Python ${esc(pr.python)}` : ""}${pr.model ? ` · written by ${esc(pr.model)}` : ""}`));
      if (pr.llm_error) ev.push(kv("LLM", esc(pr.llm_error)));
      const VB = { proven: ["proven", "green"], still_vulnerable: ["probe still triggers on the new version", "orange"], not_reproduced: ["could not reproduce", "muted"], error: ["no runnable probe", "muted"] };
      ev.push((pr.probes || []).map(r => `<div class="probe-card"><div class="probe-top"><b>${esc(r.vuln_id || "")}</b> ${esc(short(r.summary || "", 80))} ${tag((VB[r.verdict] || [r.verdict || "?"])[0], (VB[r.verdict] || [, "muted"])[1])}${r.tries ? `<small>${r.tries} attempt(s)</small>` : ""}</div>
        ${r.what ? `<p class="muted-small">${esc(r.what)}</p>` : ""}${r.why ? `<p class="muted-small">${esc(r.why)}</p>` : ""}
        ${r.code ? `<div class="probe-runs"><span><small>ON ${esc(pr.old || "OLD")}</small>${tag(r.old?.marker || "—", r.old?.marker === "VULNERABLE" ? "orange" : "muted")}</span><span><small>ON ${esc(pr.new || "NEW")}</small>${tag(r.new?.marker || "—", r.new?.marker === "SAFE" ? "green" : "muted")}</span></div>
        <details class="vsub"><summary>Probe script and output</summary>${pre(r.code, "code")}<small>Output on ${esc(pr.old || "")}:</small>${pre(r.old?.output || "")}<small>Output on ${esc(pr.new || "")}:</small>${pre(r.new?.output || "")}</details>` : ""}</div>`).join(""));
    }
    if ((k === "rescan_resolved" || k === "no_new_vulns") && v?.rescan) {
      const rs = v.rescan;
      if (k === "rescan_resolved") {
        ev.push(kv("Resolved", (rs.resolved || []).map(esc).join(", ") || "none"));
        if (rs.remaining?.length) ev.push(kv("Still present", rs.remaining.map(x => `${esc(x.finding_id)} ${esc(x.before || "")} → ${esc(x.after || "")}`).join("<br>")));
        ev.push(kv("Vulnerabilities in the whole project", `${rs.vulns_before ?? "?"} before → ${rs.vulns_after ?? "?"} after`));
        if (rs.package) ev.push(kv(`Known vulnerabilities left in ${esc(rs.package)}`, (rs.package_vulns_after || []).map(esc).join(", ") || "none"));
      } else {
        ev.push(kv("New findings", (rs.new || []).map(n => `${n.hard ? "✕" : "?"} ${esc(n.title || "")} <small>(${esc(n.risk || "")})</small>${(n.signals || []).length ? `<br><small>${n.signals.map(s => `${esc(s.check)} · ${esc(s.strength)}${s.behaviour ? " · behaviour seen" : ""}`).join(" — ")}</small>` : ""}`).join("<br>") || "none"));
      }
      ev.push(kv("SBOM diff", [...(rs.sbom_diff?.changed || []).map(x => `changed ${esc(x)}`), ...(rs.sbom_diff?.added || []).map(x => `added ${esc(x)}`), ...(rs.sbom_diff?.removed || []).map(x => `removed ${esc(x)}`)].join("<br>") || "no component changed"));
    }
    if (k === "security_tests" && v?.security_tests) ev.push(secTests(v.security_tests, true));
    if (k === "target_install" && v?.target_install) { const t = v.target_install; ev.push(kv("Target", esc(`Python ${t.python} — ${t.target?.source || ""}`)), kv("Command", t.command ? `<code>${esc(t.command)}</code>` : ""), kv("Result", esc(t.ok ? `installed in ${t.seconds}s` : t.error))); }
    if (k === "ai_critic" && c.evidence_ids?.length) ev.push(kv("Evidence cited", c.evidence_ids.map(esc).join(", ")));
    return ev.join("");
  }

  function chkRow(k, c, p, v, pending) {
    const info = CHECK_INFO[k] || { m: "static", proves: "", how: "" }, [mlab, mdesc] = METHOD[info.m];
    const st = pending ? "pending" : c.status;
    const detail = pending ? "not run yet: runs in the sandbox after you approve the proposal" : (c.detail || "");
    const why = (st === "unknown" || st === "unsure") && info.unknown ? `<div class="vwhy"><b>Why “?”</b> ${esc(info.unknown)}</div>` : "";
    return `<details class="vchk ${st}"><summary><span class="chk ${st}">${ICON[st] || "·"}</span><b>${esc(CHK_LABEL[k] || k)}</b><span class="vm ${info.m}" title="${esc(mdesc)}">${mlab}</span><small>${esc(detail)}</small></summary>
      <div class="vbody"><div class="vkv"><small>What it proves</small><span>${esc(info.proves)}</span></div><div class="vkv"><small>How it is checked</small><span>${esc(info.how)}</span></div>${pending ? "" : chkEvidence(k, c, p, v)}${why}</div></details>`;
  }

  function validationReport(p, v) {
    const checks = p.checks || {};
    const qs = VQ.map(([q, keys]) => {
      const rows = keys.map(k => checks[k] && checks[k].status !== "n/a" ? [k, checks[k], false] : (!v && SANDBOX_KEYS.includes(k) && p.edits?.length && !["n/a"].includes(checks[k]?.status) ? [k, {}, true] : null)).filter(Boolean);
      if (!rows.length) return "";
      const sts = rows.filter(r => !r[2]).map(r => r[1].status);
      const gst = sts.includes("fail") ? "fail" : rows.some(r => r[2]) || sts.some(s => s === "unknown" || s === "unsure") ? "unknown" : "pass";
      const head = { pass: "yes — all checks pass", fail: "no — a check failed", unknown: rows.some(r => r[2]) ? "not fully answered yet — sandbox not run" : "partly — some checks could not decide" }[gst];
      return `<div class="vq"><div class="vq-head"><span class="chk ${gst}">${ICON[gst]}</span><b>${esc(q)}</b><small>${head}</small></div>${rows.map(([k, c, pend]) => chkRow(k, c, p, v, pend)).join("")}</div>`;
    }).join("");
    const fc = p.fix_confidence;
    const rules = [["high", "Everything passes, the sandbox passed, and something actually executed the changed code: the project's tests ran or a proof-of-fix probe showed the bug gone. (Or: static checks pass, the AI critic agrees, same-major version bump, nothing unknown.)"],
      ["medium", "Nothing failed, but something is still open: a check is unknown, the sandbox has not run, or nothing executed the changed code."],
      ["low", "Any check failed, the AI critic disagrees, or there is no code change (escalation)."]];
    const explain = `<details class="vsub fc-explain"><summary>How fix confidence is decided</summary><p class="muted-small">Fixed rules on the check results above; the AI cannot set it.</p><ul class="fc-rules">${rules.map(([lv, t]) => `<li class="${lv === fc ? "on" : ""}">${confTag("", lv)} ${esc(t)}</li>`).join("")}</ul><p class="muted-small"><b>This fix:</b> ${esc((p.fix_confidence_reasons || []).join("; "))}</p></details>`;
    const runlog = v ? `<details class="vsub"><summary>Sandbox run log · ${esc(v.status)}${v.commit ? ` · commit ${esc(v.commit.slice(0, 8))}` : ""}</summary>${v.detail ? `<p class="muted-small">${esc(v.detail)}</p>` : ""}<ol class="val-steps">${(v.steps || []).map(s => `<li>${esc(s.msg)}</li>`).join("")}</ol></details>` : "";
    const sbom = v?.rescan ? `<div class="sbom-diff"><span><small>SBOM REMOVED</small>${(v.rescan.sbom_diff.removed || []).map(x => tag(x, "orange")).join("") || "—"}</span><span><small>SBOM CHANGED</small>${(v.rescan.sbom_diff.changed || []).map(x => tag(x, "blue")).join("") || "—"}</span><span><small>SBOM ADDED</small>${(v.rescan.sbom_diff.added || []).map(x => tag(x, "amber")).join("") || "—"}</span><span><small>FINDINGS</small>${v.rescan.before_total} → ${v.rescan.after_total}</span></div>` : "";
    const legend = `<div class="vlegend">${Object.entries(METHOD).map(([k, [l, d]]) => `<span><span class="vm ${k}">${l}</span> ${esc(d)}</span>`).join("")}</div>`;
    return `<p class="muted-small">Click any check to see what it proves, how it was run and the raw evidence.</p>${legend}<div class="vq-list">${qs}</div>${sbom}${explain}${runlog}`;
  }

  function priorityExplain(f) {
    if (f.decision_model === "guardian-code") return `<details class="vsub"><summary>How this priority was computed</summary><p class="pe-step">1. Guardian parsed the code (AST) and found SQL built by string formatting and sent to the database (CWE-89).</p><p class="pe-step">2. Reachability: ${(f.priority_reasons || []).map(esc).join(" → ")}</p><p class="pe-step">3. Rule: reachable from an HTTP route and handles login/passwords → critical; reachable → high; setup scripts only → low.</p></details>`;
    const ins = f.decision_inputs || {}, by = f.decision_by || {}, why = f.decision_why || {};
    const IN = f.decision_model === "guardian-supplychain" ? [["suspicion", "Suspicion"], ["exposure", "Exposure"]] : [["exploitation", "Exploitation"], ["automatable", "Automatable"], ["technical_impact", "Technical impact"], ["mission", "Mission & well-being"]];
    const table = f.decision_model === "guardian-supplychain"
      ? `Guardian supply-chain table: suspicion <b>${esc(ins.suspicion)}</b> × exposure <b>${esc(String(ins.exposure || "").replace(/_/g, " "))}</b> → <b>${esc(f.decision)}</b>`
      : `SSVC-inspired table (CISA): row exploitation <b>${esc(ins.exploitation)}</b> · automatable <b>${esc(ins.automatable)}</b> · impact <b>${esc(ins.technical_impact)}</b>, column mission <b>${esc(ins.mission)}</b> → <b>${esc(f.decision)}</b>`;
    return `<details class="vsub"><summary>How this priority was computed</summary>
      <div class="pe-list">${IN.filter(([k]) => ins[k] != null).map(([k, l]) => `<div class="vkv"><small>${l} = ${esc(String(ins[k]).replace(/_/g, " "))} · ${by[k] === "ai" ? "decided by AI (checked against evidence)" : "decided by a fixed rule"}</small><span>${esc(why[k] || "")}</span></div>`).join("")}</div>
      <p class="pe-step">1. ${table}</p><p class="pe-step">2. Priority: ${(f.priority_reasons || []).map(esc).join(" → ")}</p>
      <p class="pe-step">3. Finding confidence: ${(f.confidence_reasons || []).map(esc).join(" → ")}</p></details>`;
  }

  function remModal(rid) {
    const u = REM.detail.get(rid);
    if (!u) { loadRem(rid); return `<div class="modal-back" id="modal-back"><div class="modal" role="dialog" aria-modal="true"><button class="modal-x" id="modal-x" aria-label="Close">×</button><div class="empty-state">Loading ${esc(rid)}…</div></div></div>`; }
    const p = u.proposals[u.current] || {}, paused = u.paused_at, v = u.validation;
    const IN_LABEL = { exploitation: "Exploitation", automatable: "Automatable", technical_impact: "Technical impact", mission: "Mission & well-being", suspicion: "Suspicion", exposure: "Exposure" };
    const why = (u.findings || []).map(f => `<div class="why-card"><div class="why-top"><b>${esc(f.finding_id)}</b> ${esc(short(f.title, 90))} ${decTag(f.decision)}${riskTag(f.priority)}${f.kind === "code" ? "" : `<button class="text-link" data-evidence="${esc(f.finding_id)}">View evidence →</button>`}</div>
      <div class="dp-row">${Object.entries(IN_LABEL).filter(([k]) => f.decision_inputs?.[k] != null).map(([k, l]) => `<span class="dp" title="${esc(f.decision_why?.[k] || "")}"><small>${l}</small><b>${esc(String(f.decision_inputs[k]).replace(/_/g, " "))}</b><i class="by ${f.decision_by?.[k]}">${f.decision_by?.[k] === "ai" ? "AI" : "rule"}</i></span>`).join("")}</div>
      <div class="dp-facts">${f.kind === "code" ? `<b>CWE-89 SQL injection</b> in your own code · ${(f.evidence || []).map(e => `<code>${esc(e.where)}</code>`).join(" ")}` : f.kind === "vulnerability" ? `CVSS <b>${f.cvss?.score ?? "?"}</b> · EPSS ${f.epss ? `<b>${f.epss.probability ?? "?"}</b> (pct ${f.epss.percentile ?? "?"})` : "<b>n/a</b>"} · KEV <b>${f.kev ? "yes" : "no"}</b>` : "CVSS / EPSS / KEV: <b>n/a</b> (supply-chain finding, no CVE)"} · sensitivity <b>${esc(f.sensitivity?.level || "")}</b> · model ${esc(f.decision_model)}</div>
      <ul class="reason-list">${(f.priority_reasons || []).map(x => `<li>${esc(x)}</li>`).join("")}${(f.confidence_reasons || []).slice(1).map(x => `<li>${esc(x)}</li>`).join("")}</ul>
      ${Object.entries(f.decision_why || {}).filter(([k]) => f.decision_by?.[k] === "ai").slice(0, 1).map(([, t]) => `<p class="muted-small ai-note"><span class="ai-badge">AI</span> ${esc(t)}</p>`).join("")}
      ${(f.history || []).filter(h => h.change_reason).slice(-1).map(h => `<p class="muted-small">History: ${esc(h.change_reason)}</p>`).join("")}${priorityExplain(f)}</div>`).join("");
    const er = p.expected_risk || {};
    const fix = `<div class="fix-head"><b>${esc(p.action || "")}</b><div class="m-tags">${tag(`v${p.version} · ${p.author === "template" ? "deterministic template" : p.author}`, p.author === "template" ? "muted" : "violet")}${p.skill ? tag(`skill: ${p.skill}`, "blue") : ""}${confTag("fix confidence", p.fix_confidence)}</div></div>
      <div class="risk-move">${riskTag(er.before)}<i>→</i>${er.after === "none" ? tag("resolved", "green") : riskTag(er.after)}<small>${esc(er.effect || "")}</small></div>
      ${p.feedback ? `<p class="muted-small">Your feedback: “${esc(p.feedback)}”</p>` : ""}
      ${p.diff ? diffHtml(p.diff) : `<div class="open-question"><span>!</span><div><b>No code change</b><p>${esc((p.notes || []).join(" ") || "Escalation: a person has to act. Use “Revise with agent” to draft a patch.")}</p></div></div>`}
      <div class="fix-grid">${msec("COMPATIBILITY", `<ul class="reason-list">${(p.compatibility || []).map(x => `<li>${esc(x)}</li>`).join("") || "<li>—</li>"}</ul>`)}${msec("ROLLBACK", `<p class="plain">${esc(p.rollback || "—")}</p>`)}</div>
      ${(p.notes || []).length && p.diff ? msec("NOTES", `<ul class="reason-list">${p.notes.map(x => `<li>${esc(x)}</li>`).join("")}</ul>`) : ""}
      ${(p.alternatives_rejected || []).length ? msec("ALTERNATIVES THE AGENT REJECTED", `<ul class="reason-list">${p.alternatives_rejected.map(a => `<li><b>${esc(a.candidate)}</b>: ${esc(a.why)}</li>`).join("")}</ul>`) : ""}
      ${(p.agent?.trace || []).length ? `<details class="agent-trace"><summary>How the agent worked · ${p.agent.tool_calls} tool calls · skills loaded: ${esc((p.agent.skills_loaded || []).join(", ") || "none")}</summary>${p.agent.trace.map((t, i) => `<div class="tstep ${t.ok ? "" : "fail"}"><span class="tnum">${i + 1}</span><div><div class="ttop"><code>${esc(t.tool)}</code></div><small class="tin">${esc(t.input)}</small><p>${esc(t.result)}</p></div></div>`).join("")}</details>` : ""}`;
    const valHead = v ? `<div class="val-box ${v.status}"><b>Sandbox validation: ${esc(v.status)}</b>${v.detail ? `<small>${esc(v.detail)}</small>` : ""}</div>` : "";
    const alts = u.candidates.filter(cd => cd.cid !== p.candidate_id || p.author !== "template").map(cd => `<div class="alt-row ${cd.excluded ? "excluded" : ""}"><span><b>${esc(cd.label)}</b><small>${esc([...(cd.notes || []), ...(cd.compatibility || [])].slice(0, 2).join(" · "))}</small></span>${!cd.excluded && paused === "proposal_review" && !u.working ? `<button class="quiet-button" data-rm-alt="${cd.cid}">Use this</button>` : cd.excluded ? tag("excluded", "muted") : ""}</div>`).join("");
    const agentN = u.proposals.filter(x => String(x.author).startsWith("agent")).length;
    let actions = "";
    if (u.working) actions = `<div class="working-box"><span class="spin"></span><b>${esc(u.working.what)}…</b><small>${esc(u.working.step || "")}</small></div>`;
    else if (u.status === "applied") actions = `<div class="val-box passed"><b>Applied.</b> ${esc(u.applied?.detail || "")}</div>`;
    else if (u.status === "rejected") actions = `<div class="val-box failed"><b>Rejected</b> at the ${esc(u.rejection?.stage || "")} stage by ${esc(u.rejection?.by || "")}: ${esc(u.rejection?.reason || "")}</div>`;
    else if (paused) {
      const stage = paused === "patch_review" ? "patch" : "proposal";
      const primary = stage === "proposal" ? (p.edits?.length ? `<button class="primary-button" data-rm-act="approve" data-stage="proposal">Approve proposal → validate in sandbox</button>` : "") : `<button class="primary-button" data-rm-act="approve" data-stage="patch">Approve tested patch → create fix branch</button><button class="quiet-button" data-rm-act="revalidate" data-stage="patch">Re-run validation</button>`;
      actions = `<div class="rm-actions"><div class="detail-label">${stage === "proposal" ? "STEP 1 OF 2 · APPROVE THE APPROACH" : "STEP 2 OF 2 · APPROVE THE TESTED CODE CHANGE"}</div>
        <div class="act-row">${primary}<label class="rv">reviewer <input id="rm-reviewer" value="${esc(reviewer())}"></label></div>
        <textarea id="rm-text" rows="2" placeholder="${stage === "patch" && v?.status !== "passed" ? "Reason (required to approve a patch whose validation did not pass, or to reject)" : "Tell the agent what to change (e.g. keep 5.x, switch to safe_load) — or a reason to reject"}"></textarea>
        <div class="act-row"><button class="quiet-button" data-rm-act="revise" data-stage="${stage}" ${agentN >= 3 ? "disabled" : ""}>✦ Revise with agent</button><button class="quiet-button" data-rm-act="regenerate" data-stage="${stage}" ${agentN >= 3 ? "disabled" : ""}>✦ Regenerate with agent</button><button class="quiet-button danger" data-rm-act="reject" data-stage="${stage}">Reject</button><small class="muted-small">${agentN}/3 agent proposals used · the agent uses the large model when available</small></div>
        ${REM.msg ? `<div class="banner-warn">${esc(REM.msg)}</div>` : ""}</div>`;
    }
    const tl = (u.audit || []).map(e => `<li><small>${esc((e.at || "").replace("T", " ").replace("Z", ""))}</small><b>${esc(e.event.replace(/_/g, " "))}</b> ${esc([e.stage, e.action, e.author, e.version && `v${e.version}`, e.status, e.reviewer && `by ${e.reviewer}`, e.reason && `“${e.reason}”`, e.feedback && `“${e.feedback}”`, e.branch, e.error].filter(Boolean).join(" · "))}</li>`).join("");
    const body = `<div class="m-head"><div class="eyebrow">REMEDIATION · ${esc(u.rid)} · covers ${u.finding_ids.map(esc).join(", ")}</div><h2>${esc(u.target_label)}</h2><div class="m-tags">${decTag(u.decision)}${riskTag(u.priority)}${confTag("finding confidence", u.finding_confidence)}${tag(TAB_LABEL[u.tab] || u.tab, u.tab === "decide" ? "orange" : "muted")}${tag(STATUS_LABEL[u.status] || u.status, "muted")}</div>${(u.gate?.reasons || []).length && u.tab === "decide" ? `<p class="m-lead">Needs your decision because: ${esc(u.gate.reasons.join("; "))}.</p>` : ""}</div>
      ${u.last_agent_error ? `<div class="banner-warn"><b>The agent's last attempt was not used:</b> ${esc(u.last_agent_error)}</div>` : ""}${u.last_error ? `<div class="banner-warn">${esc(u.last_error)}</div>` : ""}
      ${actions}
      ${msec("PROPOSED FIX", fix)}
      ${msec(`VALIDATION · HOW WE KNOW THIS FIX IS SAFE · fix confidence ${esc(p.fix_confidence || "")}`, valHead + validationReport(p, v))}
      ${v?.security_tests ? msec("SECURITY TESTS · WRITTEN BY GUARDIAN · RUN BEFORE AND AFTER THE FIX", secTests(v.security_tests)) : p.edits?.length ? msec("SECURITY TESTS", `<p class="muted-small">Written and run in the sandbox during validation: T1 exploit (fail → pass), T2 guard (fail → pass), T3 feature (pass → pass).</p>`) : ""}
      ${u.build_health ? msec("WHY THIS FIX · BUILD HEALTH", buildHealthBox(u.build_health)) : msec("WHY THIS PRIORITY", why)}
      ${alts ? msec("OTHER CANDIDATES", `<div class="alt-list">${alts}</div>`) : ""}
      ${u.proposals.length > 1 ? msec("EARLIER PROPOSALS", `<ul class="reason-list">${u.proposals.slice(0, -1).map(x => `<li>v${x.version} · ${esc(x.author)} · ${esc(x.action)} · fix confidence ${esc(x.fix_confidence)}</li>`).join("")}</ul>`) : ""}
      ${msec("AUDIT TRAIL", `<ol class="timeline">${tl || "<li>—</li>"}</ol>`)}`;
    return `<div class="modal-back" id="modal-back"><div class="modal wide" role="dialog" aria-modal="true"><button class="modal-x" id="modal-x" aria-label="Close">×</button>${body}</div></div>`;
  }

  async function remDecide(rid, body) {
    REM.msg = null;
    const name = document.querySelector("#rm-reviewer")?.value.trim(); if (name) localStorage.setItem("guardian-reviewer", name);
    try {
      await remApi(`/remediations/${encodeURIComponent(rid)}/decision`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ reviewer: reviewer(), ...body }) });
    } catch (e) { REM.msg = e.message; }
    await loadRem(rid);
  }
  function bindRem(r) {
    app.querySelectorAll("[data-rm-tab]").forEach(el => el.addEventListener("click", () => go("remediate", "", { tab: el.dataset.rmTab })));
    app.querySelectorAll("[data-rm-open]").forEach(el => el.addEventListener("click", () => { REM.msg = null; go("remediate", "", { tab: r.p.get("tab"), open: el.dataset.rmOpen }); loadRem(el.dataset.rmOpen); }));
    const rid = r.p.get("open");
    app.querySelectorAll("[data-rm-act]").forEach(el => el.addEventListener("click", () => {
      const text = document.querySelector("#rm-text")?.value.trim() || "", a = el.dataset.rmAct;
      const body = { stage: el.dataset.stage, action: a };
      if (a === "revise") { body.feedback = text; body.large = true; }
      if (a === "regenerate") { body.feedback = text || null; body.large = true; }
      if (a === "reject" || a === "approve") body.reason = text || null;
      remDecide(rid, body);
    }));
    app.querySelectorAll("[data-rm-alt]").forEach(el => el.addEventListener("click", () => remDecide(rid, { stage: "proposal", action: "alternative", alternative: +el.dataset.rmAlt })));
    app.querySelectorAll("[data-remfor]").forEach(el => el.addEventListener("click", ev => { ev.stopPropagation(); const it = remFor(el.dataset.remfor); go("remediate", "", it ? { tab: "all", open: it.rid } : {}); }));
    app.querySelectorAll("[data-suggest]").forEach(el => el.addEventListener("click", async ev => {
      ev.stopPropagation(); const fid = el.dataset.suggest, box = document.querySelector("#sg-text"), msg = document.querySelector("#sg-msg");
      if (!box.value.trim()) { msg.textContent = "Write what the fix should do first."; return; }
      try {
        const row = await remApi(`/findings/${encodeURIComponent(fid)}/suggest`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ feedback: box.value.trim(), reviewer: reviewer(), large: true }) });
        REM.scan = null; go("remediate", "", { tab: "all", open: row.rid });
      } catch (e) { msg.textContent = e.message; }
    }));
  }
  const suggestBox = x => mode === "web" ? `<div class="m-sec suggest"><div class="detail-label">SUGGEST A REMEDIATION</div><p class="muted-small">Your suggestion goes to the remediation agent for this finding; the new proposal is checked and waits for your approval on the Remediation page.</p><textarea id="sg-text" rows="2" placeholder="e.g. keep PyYAML 5.x and switch the loader to yaml.safe_load"></textarea><div class="act-row"><button class="primary-button" data-suggest="${esc(x.id)}">✦ Send to remediation agent</button><button class="quiet-button" data-remfor="${esc(x.id)}">Go to remediation →</button><small id="sg-msg" class="muted-small"></small></div></div>` : "";

  // ------------------------------------------------------------------ page 4 additions: queue, security tests, build health
  const RES = { pass: ["✓", "ok"], fail: ["✕", "bad"], error: ["✕", "bad"], skip: ["–", "muted"], "not run": ["·", "muted"] };
  const resMark = x => { const [i, c] = RES[x] || ["?", "muted"]; return `<span class="tres ${c}" title="${esc(x)}">${i} ${esc(x)}</span>`; };
  const KIND_INFO = { T1: ["exploit", "violet"], T2: ["guard, not proof", "blue"], T3: ["feature", "green"] };
  function queueStrip() {
    const q = REM.queue; if (!q) return "";
    const bh = q.build_health;
    const run = q.running ? `<span class="spin"></span> <b>${q.running === "@build_health" ? "Checking build health (does it install on the target Python?)" : `Auto-validating ${esc(q.running)} in the sandbox`}…</b> <small>${q.position} of ${q.total}${q.pending.length ? ` · next: ${q.pending.slice(0, 4).map(x => esc(x === "@build_health" ? "build health" : x)).join(", ")}` : ""}</small>` :
      `<b>Auto-validation</b> <small>${q.policy === "off" ? "off (GUARDIAN_AUTO_VALIDATE=off)" : `${q.done.length} run${q.done.length === 1 ? "" : "s"} done · Critical/High fixes with a patch are validated before you open them`}</small>`;
    const bhLine = bh && bh.target ? `<div class="bh-line ${bh.status === "ok" ? "ok" : "warn"}"><b>Build health · Python ${esc(bh.target.version)}</b> <small>${esc(bh.target.source)}</small> — ${bh.status === "ok" ? "the project installs ✓" : bh.status === "fixable" ? `<span class="bad">✕ does not install</span> (${esc(bh.before?.error || "")}). <button class="text-link" data-rm-open="B-001">B-001 makes it install and run: ${bh.bumps.map(b => esc(`${b.package} ${b.from} → ${b.to}`)).join(", ")} →</button>` : `<span class="bad">✕</span> ${esc(bh.detail || "")}`}</div>` : "";
    const nb = (REM.bulk?.items || []).length;
    const bulk = `<button class="primary-button" id="rm-approve-all" ${nb ? "" : "disabled"} title="Approves the proposal and the tested patch of every fix whose sandbox validation passed, then builds the fixed repository">✓ Approve all validated fixes (${nb})</button>`;
    return `<div class="queue-strip">${run}<button class="quiet-button" id="rm-validate-all">Validate all with a patch</button>${bulk}</div>${REM.bulkMsg ? `<div class="banner-warn">${esc(REM.bulkMsg)}</div>` : ""}${bhLine}`;
  }
  function secTests(st, compact) {
    const rows = (st.tests || []).map(t => `<div class="st-row ${t.kept ? "" : "dropped"} ${t.kept && !t.as_expected ? "notexp" : ""}"><span class="st-kind"><b>${t.kind}</b><small>${KIND_INFO[t.kind][0]}</small></span><span><b>${esc(t.title)}</b><small><code>${esc(t.name)}</code> · ${t.source === "curated" ? "curated reference exploit" : t.source.startsWith("ai:") ? `written by ${esc(t.source.slice(3))}` : "template (no AI)"}${t.vuln_id ? ` · ${esc(t.vuln_id)}` : ""}</small>${t.note ? `<small class="bad">${esc(t.note)}</small>` : ""}</span><span><small>expected</small>${esc(t.expected)}</span><span><small>before</small>${resMark(t.before)}</span><span><small>after</small>${resMark(t.after)}</span><span>${t.as_expected ? tag("as expected", "green") : t.kept ? tag("NOT as expected", "orange") : tag("dropped", "muted")}</span></div>`).join("");
    const n = (st.tests || []).filter(t => t.kept).length;
    return `${compact ? "" : `<p class="muted-small">${n} test${n === 1 ? "" : "s"} kept in <code>${esc(st.file || "")}</code>${st.python ? ` · Python ${esc(st.python)}` : ""}. A test counts only when Guardian <b>ran it on both versions and saw the expected result</b>; T1 and T3 tests that did not behave as expected are dropped, never hidden.</p>`}<div class="st-list">${rows || `<div class="empty-state small">${esc(st.detail || "no tests")}</div>`}</div>${st.code && !compact ? `<details class="vsub"><summary>Test file committed with the fix</summary>${pre(st.code, "code")}</details>` : ""}${!compact && st.after_run?.log ? `<details class="vsub"><summary>pytest output (after)</summary>${pre(st.after_run.log)}</details>` : ""}`;
  }
  function buildHealthBox(bh) {
    return `<p class="plain">The project does not install on <b>Python ${esc(bh.target?.version)}</b> (${esc(bh.target?.source)}). This is <b>not a vulnerability</b>: old pins have no wheel for that Python, so the app cannot be deployed as written. The report keeps it separate from the vulnerability fixes.</p>
      <div class="vkv"><small>Install before</small><span class="bad">${esc(bh.before?.error || "")}</span></div>
      ${(bh.bumps || []).map(b => `<div class="vkv"><small>${esc(b.package)} ${esc(b.from)} → ${esc(b.to)}${b.kind === "runtime" ? " · crashed at import" : " · no wheel"}</small><span>${esc(b.why)}</span></div>`).join("")}
      <div class="vkv"><small>Install after the bumps</small><span class="${bh.after?.ok ? "ok" : "bad"}">${bh.after?.ok ? `✓ installs${bh.after.boot === "healthy" ? " and starts" : ""} on Python ${esc(bh.after.python)}` : esc(bh.detail || "")}</span></div>`;
  }

  // ------------------------------------------------------------------ page 5: fixed repository
  const FX = { scan: null, data: null, err: null, timer: null, msg: null, busy: false };
  async function loadFixed() {
    if (mode !== "web" || !scanId) return;
    if (FX.scan !== scanId) { FX.scan = scanId; FX.data = null; }
    try { FX.data = await remApi("/fixed-repo"); FX.err = null; } catch (e) { FX.err = e.message; }
    FX.at = Date.now();
    if (["fixed", "report"].includes(route().view)) render();
    clearTimeout(FX.timer);
    if (FX.data?.status === "running" && route().view === "fixed") FX.timer = setTimeout(loadFixed, 2000);
  }
  const arrow = (a, b, good) => `<span class="ba"><span>${esc(a ?? "?")}</span><i>→</i><b class="${good ? "ok" : ""}">${esc(b ?? "?")}</b></span>`;
  function renderFixed() {
    const head = title("FIXED REPOSITORY", "Fixed <span class='title-suffix'>repository</span>", "The approved fixes combined into one repository, one commit each, then installed, tested, started and rescanned before and after. Download it, or run it.");
    if (mode !== "web") return head + `<div class="panel empty-big"><p>Needs the Guardian server: <code>python -m guardian.cli web --root output/scans</code></p></div>`;
    if (FX.scan === scanId && FX.data && Date.now() - (FX.at || 0) > 8000 && FX.data.status !== "running") loadFixed();
    if (FX.scan !== scanId || (!FX.data && !FX.err)) { loadFixed(); return head + `<div class="panel empty-big"><p>Loading…</p></div>`; }
    if (FX.err && !FX.data) return head + `<div class="banner-warn">${esc(FX.err)}</div>`;
    const d = FX.data, inc = d.ready_to_build || [];
    const buildBtn = `<button class="primary-button" id="fx-build" ${!inc.length || d.status === "running" ? "disabled" : ""}>${d.status === "done" ? "Rebuild fixed repository" : "Build fixed repository"}</button>`;
    const notInc = (d.not_included || []).length ? `<details class="vsub"><summary>Not included (${d.not_included.length}): not approved, rejected or no code change</summary><div class="fx-list">${d.not_included.map(x => `<div class="fx-row"><span class="mono">${esc(x.rid)}</span><span><b>${esc(x.label)}</b><small>${esc(x.action || "")}</small></span>${riskTag(x.priority)}<small>${esc(x.why)}</small></div>`).join("")}</div></details>` : "";
    const msg = FX.msg ? `<div class="banner-warn">${esc(FX.msg)}</div>` : "";
    if (d.status === "none" || (d.status === "failed" && !d.included)) {
      return head + msg + panel("Ready to build", inc.length ? `${inc.length} approved fix${inc.length > 1 ? "es" : ""} will be combined` : "No approved fix yet", `${d.detail ? `<div class="banner-warn">${esc(d.detail)}</div>` : ""}${inc.length ? `<div class="fx-list">${inc.map(x => `<div class="fx-row"><span class="mono">${esc(x.rid)}</span><b>${esc(x.label)}</b></div>`).join("")}</div>` : `<p class="muted-small">Approve the proposal and then the tested patch of at least one remediation on the ${link("Remediation", 'data-goto="remediate"')} page.</p>`}<div class="act-row">${buildBtn}</div><p class="muted-small">Takes about 3–5 minutes: compose → install before/after on the target Python → all tests before/after → boot check → combined rescan → zip.</p>${notInc}`);
    }
    const STEPS = [["compose", "Compose"], ["install", "Install"], ["tests", "Tests"], ["boot", "Boot"], ["rescan", "Rescan"], ["publish", "Publish"]];
    const seen = new Set((d.steps || []).map(s => s.key)), last = (d.steps || []).slice(-1)[0];
    const progress = `<div class="fx-steps">${STEPS.map(([k, l]) => `<span class="fx-step ${seen.has(k) ? (d.status === "running" && last?.key === k ? "run" : "done") : ""}">${seen.has(k) && !(d.status === "running" && last?.key === k) ? "✓" : d.status === "running" && last?.key === k ? '<span class="spin"></span>' : "·"} ${l}</span>`).join("<i>→</i>")}</div>`;
    if (d.status === "running") return head + panel("Building the fixed repository…", esc(last?.msg || "starting"), `${progress}<ol class="val-steps">${(d.steps || []).map(s => `<li>${esc(s.msg)}</li>`).join("")}</ol>`);
    const s = d.summary || {}, t = d.tests || {}, rs = d.rescan || {}, ins = d.install || {}, bt = d.boot || {};
    const codeCard = s.code ? `<div class="metric-card"><div class="metric-top"><span>SQL INJECTION IN THE CODE</span></div><div class="metric-value">${arrow(s.code[0], s.code[1], s.code[1] < s.code[0])}</div><div class="metric-foot">sites found by Guardian (CWE-89) · fixed by changing the code</div></div>` : "";
    const strip = `<div class="metric-grid fx-strip ${s.code ? "five" : ""}">${codeCard}
      <div class="metric-card"><div class="metric-top"><span>KNOWN VULNERABILITIES</span></div><div class="metric-value">${arrow(s.vulns?.[0], s.vulns?.[1], s.vulns?.[1] < s.vulns?.[0])}</div><div class="metric-foot">${(rs.resolved || []).length} resolved · ${(rs.new || []).filter(n => n.hard).length} new</div></div>
      <div class="metric-card"><div class="metric-top"><span>CRITICAL / HIGH</span></div><div class="metric-value">${arrow(s.critical_high?.[0], s.critical_high?.[1], s.critical_high?.[1] < s.critical_high?.[0])}</div><div class="metric-foot">by Guardian priority</div></div>
      <div class="metric-card"><div class="metric-top"><span>TESTS</span></div><div class="metric-value">${arrow(`${s.tests?.project_before ?? "?"}/${s.tests?.project_total ?? "?"}`, `${s.tests?.project_after ?? "?"}/${s.tests?.project_total ?? "?"}`, !s.tests?.regressions)}</div><div class="metric-foot">+ ${s.tests?.new ?? 0} new security tests, ${s.tests?.new_as_expected ?? 0} as expected · <b class="${s.tests?.regressions ? "bad" : "ok"}">${s.tests?.regressions ?? 0} regressions</b></div></div>
      <div class="metric-card"><div class="metric-top"><span>APP ON PYTHON ${esc(s.python || "")}</span></div><div class="metric-value fx-app"><span class="${s.app_ok?.[0] ? "ok" : "bad"}">${s.app_ok?.[0] ? "✓" : "✕"} ${esc(s.app?.[0] || "")}</span><i>→</i><b class="${s.app_ok?.[1] ? "ok" : "bad"}">${s.app_ok?.[1] ? "✓" : "✕"} ${esc(s.app?.[1] || "")}</b></div><div class="metric-foot">${esc(d.target?.source || "")}</div></div></div>`;
    const pub = d.publish || {};
    const dl = `<div class="fx-dl"><a class="primary-button" href="/api/scans/${encodeURIComponent(scanId)}/fixed-repo/download?what=zip">⬇ Download fixed repo (.zip)</a><a class="quiet-button" href="/api/scans/${encodeURIComponent(scanId)}/fixed-repo/download?what=patch">⬇ Download patches</a><span class="fx-branch">branch <code>${esc(pub.branch || "")}</code> <button class="text-link" id="fx-copy" data-copy="${esc(pub.branch || "")}">copy</button><small>${esc((pub.commit || "").slice(0, 8))} · not checked out, not pushed</small></span></div>
      <pre class="cmd">unzip ${esc(scanId)}-fixed-repo.zip && cd ${esc(d.repo_name || "repo")}-fixed\npip install -r requirements.txt pytest\npytest -m guardian tests/guardian     # Guardian's security tests</pre>
      ${liveBlock(d)}`;
    const incl = `<div class="vtable"><div class="vt-head fx"><span>FIX</span><span>WHAT CHANGED</span><span>FINDINGS</span><span>SECURITY TESTS</span><span>COMMIT</span></div>${(d.included || []).map(r => `<button class="vt-row fx" data-rm-jump="${esc(r.rid)}"><span class="mono">${esc(r.rid)}</span><span><b>${esc(r.label)}</b><small>${esc(r.action || "")}</small>${r.kind === "build_health" ? tag("build health", "amber") : ""}</span><span><small>${esc(r.vuln_ids.slice(0, 4).join(", ") || "—")}${r.vuln_ids.length > 4 ? ` +${r.vuln_ids.length - 4}` : ""}</small></span><span>${esc(r.tests_summary)}</span><span class="mono">${esc((r.commit || "").slice(0, 8))}<small>by ${esc(Object.values(r.approvers || {}).join(" / "))}</small></span></button>`).join("")}${(d.skipped || []).map(x => `<div class="vt-row fx skipped"><span class="mono">${esc(x.rid)}</span><span><b>${esc(x.label)}</b></span><span></span><span class="bad">${esc(x.why)}</span><span>skipped</span></div>`).join("")}</div>`;
    const byFile = new Map();
    for (const m of t.matrix || []) push(byFile, m.guardian ? m.test.split("::")[0] : "project tests", m);
    const matrix = [...byFile].map(([f, ms]) => `<details class="vsub"><summary>${esc(f)} · ${ms.filter(m => m.as_expected).length}/${ms.length} as expected</summary><div class="st-list">${ms.map(m => `<div class="st-row ${m.as_expected ? "" : "notexp"}"><span class="st-kind"><b>${esc(m.kind === "project" ? "P" : m.kind)}</b></span><span><code>${esc(m.test.split("::")[1] || m.test)}</code></span><span><small>expected</small>${esc(m.expected)}</span><span><small>before</small>${resMark(m.before)}</span><span><small>after</small>${resMark(m.after)}</span><span>${m.as_expected ? tag("as expected", "green") : tag("NOT as expected", "orange")}</span></div>`).join("")}</div></details>`).join("");
    const bootRow = (lab, i, b) => `<div class="fx-ba"><b>${lab}</b><span>${i?.ok ? `<span class="ok">✓ installs</span> on Python ${esc(i.python)} <small>(${esc(i.seconds)}s)</small>` : `<span class="bad">✕ does not install</span> on Python ${esc(i?.python || "")}: <code>${esc(i?.error || "")}</code>`}</span><span>${b?.status === "healthy" ? `<span class="ok">✓ running</span>` : `<span class="bad">${esc(b?.status || "")}</span>`} <small>${esc(short(b?.detail || "", 160))}</small></span></div>`;
    const proof = `<h3 class="fx-h">Install and boot on the target Python ${esc(d.target?.version || "")}</h3>${bootRow("Before", ins.before, bt.before)}${bootRow("After", ins.after, bt.after)}
      ${(bt.after?.routes || []).length ? `<div class="fx-routes">${bt.after.routes.map(r => `<span class="${(r.status || 0) >= 500 || !r.status ? "bad" : "ok"}"><code>GET ${esc(r.path)}</code> ${esc(r.status || r.error || "")}${r.title ? ` <small>“${esc(short(r.title, 30))}”</small>` : ""}</span>`).join("")}</div>` : ""}
      ${t.on_target ? `<p class="muted-small">All tests on the target Python ${esc(t.on_target.python)}: ${t.on_target.passed}/${t.on_target.total} pass.</p>` : ""}
      <h3 class="fx-h">Tests before → after <small>(Python ${esc(t.python || "")}, the same environment for both)</small></h3>${matrix || `<p class="muted-small">No tests ran.</p>`}
      <h3 class="fx-h">Combined rescan</h3>${rs.error ? `<div class="banner-warn">${esc(rs.error)}</div>` : `<div class="sbom-diff"><span><small>VULNERABILITIES</small>${rs.vulns_before} → ${rs.vulns_after}</span><span><small>SUPPLY-CHAIN FINDINGS</small>${rs.supply_before} → ${rs.supply_after}</span><span><small>RESOLVED</small>${(rs.resolved || []).length}</span><span><small>NEW</small>${(rs.new || []).map(n => tag(`${n.title}${n.hard ? "" : " (metadata only)"}`, n.hard ? "orange" : "muted")).join("") || "none"}</span></div><div class="sbom-diff"><span><small>SBOM CHANGED</small>${(rs.sbom_diff?.changed || []).map(x => tag(x, "blue")).join("") || "—"}</span><span><small>ADDED</small>${(rs.sbom_diff?.added || []).map(x => tag(x, "amber")).join("") || "—"}</span><span><small>REMOVED</small>${(rs.sbom_diff?.removed || []).map(x => tag(x, "orange")).join("") || "—"}</span></div>`}
      <details class="vsub"><summary>Build log</summary><ol class="val-steps">${(d.steps || []).map(x => `<li>${esc(x.msg)}</li>`).join("")}</ol></details>`;
    return head + msg + (d.status === "failed" ? `<div class="banner-warn"><b>The last build failed:</b> ${esc(d.detail || "")}</div>` : "") + (d.stale ? `<div class="banner-warn">More fixes were approved since this build. <b>Rebuild</b> to include them.</div>` : "") + strip
      + panel("Download and run", `${pub.commits || 0} commits on top of ${esc((d.head || "").slice(0, 8))} · GUARDIAN_FIXES.md included`, dl, buildBtn)
      + panel("Included fixes", "One commit per fix, with its security tests. Click one to open it on the Remediation page.", incl + notInc)
      + panel("Proof", "Everything below was run by Guardian, before and after", proof);
  }
  function liveBlock(d) {
    if (!d || d.status !== "done") return "";
    const row = (which, lab, cfg, cls) => {
      const live = (d.live || {})[which];
      const head = `<span class="lv-lab ${cls}">${lab}</span>`;
      if (live) return `<div class="lv-row">${head}<span class="live-dot ${cls}"></span><a href="${esc(live.url)}" target="_blank" rel="noopener">${esc(live.url)} ↗</a><small>Python ${esc(live.python)} · stops by itself after ${live.stops_after_min} min</small><button class="quiet-button danger" data-fx-stop="${which}">Stop</button></div>`;
      return `<div class="lv-row">${head}<button class="${which === "after" ? "primary-button" : "quiet-button"}" data-fx-run="${which}" ${cfg ? "" : "disabled"}>▶ Run ${which === "after" ? "fixed" : "original (vulnerable)"} app</button><small>${cfg ? esc(cfg.note || `Python ${cfg.python}`) : "not available"}</small></div>`;
    };
    return `<div class="fx-live"><div class="detail-label">SEE IT LIVE · BOTH VERSIONS SIDE BY SIDE${FX.busy ? ' <span class="spin"></span>' : ""}</div>${row("before", "BEFORE", d.run_before, "vuln")}${row("after", "AFTER", d.run, "fixed")}<p class="muted-small">Each version runs from its own sandbox copy with a temporary SQLite database on 127.0.0.1; nothing is exposed outside this machine.</p></div>`;
  }
  function bindFixed() {
    document.querySelector("#fx-build")?.addEventListener("click", async () => { FX.msg = null; try { FX.data = await remApi("/fixed-repo", { method: "POST" }); } catch (e) { FX.msg = e.message; } loadFixed(); });
    app.querySelectorAll("[data-fx-run]").forEach(el => el.addEventListener("click", async () => { FX.busy = true; FX.msg = null; render(); try { await remApi(`/fixed-repo/run?which=${el.dataset.fxRun}`, { method: "POST" }); } catch (e) { FX.msg = e.message; } FX.busy = false; loadFixed(); }));
    app.querySelectorAll("[data-fx-stop]").forEach(el => el.addEventListener("click", async () => { await remApi(`/fixed-repo/run?which=${el.dataset.fxStop}`, { method: "DELETE" }).catch(() => 0); loadFixed(); }));
    document.querySelector("#fx-copy")?.addEventListener("click", e => { navigator.clipboard?.writeText(e.target.dataset.copy); e.target.textContent = "copied"; });
    app.querySelectorAll("[data-rm-jump]").forEach(el => el.addEventListener("click", () => go("remediate", "", { tab: "all", open: el.dataset.rmJump })));
    document.querySelector("#rm-approve-all")?.addEventListener("click", async () => {
      const items = REM.bulk?.items || [];
      if (!items.length) return;
      const ok = confirm(`Approve ${items.length} validated fix(es) as "${reviewer()}"?\n\n` + items.map(i => `${i.rid}  ${i.action || i.label}  (validation ${i.validation})`).join("\n")
        + "\n\nEach gets both approvals (proposal + tested patch). Fixes that failed validation are not included and still need your decision. Then the fixed repository is built.");
      if (!ok) return;
      try {
        await remApi("/bulk-approve", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ reviewer: reviewer(), build: true }) });
        REM.bulkMsg = `Approving ${items.length} fix(es)… the fixed repository build starts right after.`; render();
        const t0 = Date.now();
        while (Date.now() - t0 < 120000) {
          await new Promise(r => setTimeout(r, 1500));
          const f = await remApi("/fixed-repo").catch(() => null);
          if (f?.status === "running") { REM.bulkMsg = null; FX.scan = null; go("fixed"); return; }
        }
        REM.bulkMsg = null; loadRem();
      } catch (e) { REM.bulkMsg = e.message; render(); }
    });
    document.querySelector("#rm-validate-all")?.addEventListener("click", async () => { try { REM.queue = await remApi("/remediations/validate-all", { method: "POST" }); } catch (e) { REM.msg = e.message; } loadRem(); });
  }

  // ------------------------------------------------------------------ page 6: report
  const RP = { scan: null, data: null, err: null };
  async function loadReport() {
    try { RP.data = await remApi("/remediation-report"); RP.err = null; } catch (e) { RP.err = e.message; }
    RP.at = Date.now();
    if (route().view === "report") render();
  }
  function renderReport() {
    const dl = mode === "web" ? `<div class="act-row"><a class="primary-button" href="/api/scans/${encodeURIComponent(scanId)}/remediation-report/download?format=html">⬇ Download report (HTML)</a><a class="quiet-button" href="/api/scans/${encodeURIComponent(scanId)}/remediation-report/download?format=md">Markdown</a></div>` : "";
    const head = title("REPORT", "Remediation <span class='title-suffix'>report</span>", "One page for a security lead: what was fixed, how it was checked, and what risk remains.", dl);
    if (mode !== "web") return head + `<div class="panel empty-big"><p>Needs the Guardian server.</p></div>`;
    if (RP.scan === scanId && RP.data && Date.now() - (RP.at || 0) > 8000) loadReport();
    if (RP.scan !== scanId) { RP.scan = scanId; RP.data = null; loadReport(); return head + `<div class="panel empty-big"><p>Building the report…</p></div>`; }
    if (RP.err) return head + `<div class="banner-warn">${esc(RP.err)}</div>`;
    if (!RP.data) return head + `<div class="panel empty-big"><p>Building the report…</p></div>`;
    const r = RP.data, h = r.header;
    const tbl = (cols, rows) => `<table class="rp-table"><tr>${cols.map(c => `<th>${c}</th>`).join("")}</tr>${rows.map(x => `<tr>${x.map(c => `<td>${c}</td>`).join("")}</tr>`).join("")}</table>`;
    const tm = x => (x.tests || []).map(t => `<span class="tres ${t.as_expected ? "ok" : "bad"}">${t.kind} ${esc(t.before)}→${esc(t.after)}</span>`).join(" ") || "—";
    return head + `<section class="panel rp">
      <div class="rp-meta">${esc(h.repo || "")} ${h.repo_url ? `· <a href="${esc(h.repo_url.replace(/\.git$/, ""))}" target="_blank" rel="noopener">${esc(h.repo_url.replace(/^https:\/\//, "").replace(/\.git$/, ""))}</a>` : ""} · commit <code>${esc(h.commit_before)}</code> → ${h.fixed_branch ? `branch <code>${esc(h.fixed_branch)}</code>` : "no fixed branch yet"} · approved by ${esc((h.approvers || []).join(", ") || "—")}</div>
      <div class="rp-verdict">${esc(h.verdict)}</div>
      ${FX.scan === scanId && FX.data ? liveBlock(FX.data) : (loadFixed(), "")}${FX.msg ? `<div class="banner-warn">${esc(FX.msg)}</div>` : ""}
      ${r.before_after.length ? `<h3>Before → after</h3>${tbl(["", "Before", "After"], r.before_after.map(x => [esc(x.what), esc(x.before ?? "—"), `<b>${esc(x.after ?? "—")}</b>`]))}` : ""}
      <h3>What Guardian fixed</h3>${r.fixed.length ? tbl(["Fix", "Findings", "Priority · why", "Tests", "Fix confidence", "Approved by"], r.fixed.map(x => [`<b>${esc(x.rid)}</b> ${esc(x.action)}`, `<small>${esc(x.vuln_ids.join(", "))}</small>`, `${riskTag(x.priority)}<br><small>${esc(x.why)}</small>`, tm(x), esc(x.fix_confidence || ""), esc(Object.values(x.approvers || {}).join(" / "))])) : `<p class="muted-small">None yet.</p>`}
      ${r.build_health.length ? `<h3>Build health <small>(not vulnerability fixes)</small></h3><p class="muted-small">${esc(r.build_health_note)}</p>${tbl(["Fix", "Tests", "Approved by"], r.build_health.map(x => [`<b>${esc(x.rid)}</b> ${esc(x.action)}`, tm(x), esc(Object.values(x.approvers || {}).join(" / "))]))}` : ""}
      <h3>Remaining and accepted risk</h3>${r.remaining.length ? tbl(["Item", "Priority", "Status", "Reason"], r.remaining.map(x => [`<b>${esc(x.rid)}</b> ${esc(x.label)}<br><small>${esc(x.findings.join(", "))}</small>`, riskTag(x.priority), esc(x.status), esc(x.reason || "") + (x.by ? ` <small>(${esc(x.by)})</small>` : "")])) : `<p class="muted-small">Nothing remaining.</p>`}
      ${r.new_findings.length ? `<p class="muted-small"><b>New in the rescan:</b> ${r.new_findings.map(n => esc(`${n.title} (${n.risk}${n.hard ? "" : ", metadata only, needs a look"})`)).join("; ")}</p>` : ""}
      ${r.test_matrix.length ? `<h3>Test evidence</h3><details class="vsub"><summary>${r.test_matrix.length} tests, before → after</summary>${tbl(["Test", "Expected", "Before", "After", ""], r.test_matrix.map(m => [`<code>${esc(m.test)}</code>`, esc(m.expected), resMark(m.before), resMark(m.after), m.as_expected ? tag("as expected", "green") : tag("NOT as expected", "orange")]))}</details>` : ""}
      <h3>Audit trail</h3><details class="vsub"><summary>${r.audit.length} events: proposals, decisions, validations, commits</summary>${tbl(["When", "Item", "Event"], r.audit.map(a => [`<small>${esc((a.at || "").replace("T", " ").replace("Z", ""))}</small>`, esc(a.rid || ""), `${esc((a.event || "").replace(/_/g, " "))} <small>${esc(a.text)}</small>`]))}</details>
      <h3>How it was checked</h3><ol class="rp-methods">${r.methods.map(m => `<li>${esc(m)}</li>`).join("")}</ol></section>`;
  }

  // ------------------------------------------------------------------ new scan + progress (guardian web)
  function renderNewScan() {
    if (mode !== "web") return `${title("NEW SCAN", "Scan a <span class='title-suffix'>repository</span>", "")}<div class="panel scan-card"><h2>Scanning from a link needs the full Guardian server</h2><p>This page was opened ${mode === "serve" ? "with <code>guardian serve</code>, which only shows one finished scan" : "as a file"}. Start the server that can clone and scan repositories:</p><pre class="cmd">python -m guardian.cli web --root output/scans</pre><p>Then open <b>http://127.0.0.1:8000/</b> and paste a GitHub link here.</p></div>`;
    const rows = scans.map(s => { const fd = s.findings || {}; return `<button class="scan-row ${s.scan_id === scanId ? "row-selected" : ""}" data-open-scan="${esc(s.scan_id)}" data-status="${esc(s.status)}"><span><b>${esc(s.repo)}</b><small>${esc(s.scan_id)}</small></span><span>${s.status === "done" ? tag("done", "green") : s.status === "running" ? tag("running…", "blue") : tag(s.status || "?", "orange")}</span><span>${esc((s.created_at || "").replace("T", " ").replace("Z", ""))}</span><span>${["critical", "high"].map(k => fd[k] ? `<span class="sev-inline ${k}">${fd[k]} ${k}</span>` : "").join(" ") || `<span class="muted-small">—</span>`}</span><span class="muted-small err">${esc(short(s.error || "", 90))}</span></button>`; }).join("");
    return `${title("NEW SCAN", "Scan a <span class='title-suffix'>repository</span>", "Paste a GitHub link to a Python project, or the path of a folder on this machine. Guardian clones it, builds the SBOM, maps the code, matches vulnerabilities and checks the supply chain.")}
      <section class="panel scan-card"><form id="scan-form"><label class="detail-label" for="scan-input">GITHUB LINK OR LOCAL FOLDER</label><div class="scan-input-row"><input id="scan-input" required placeholder="https://github.com/owner/repo" autocomplete="off"><button class="primary-button" type="submit">Start scan →</button></div>
      <div class="scan-options"><label><input type="checkbox" id="scan-ai"> AI explanations (uses the configured LLM key; slower, about 5–10 min on a free tier)</label><label><input type="checkbox" id="scan-offline"> Offline — skip OSV and PyPI lookups (no vulnerability data)</label></div>
      <div class="scan-examples"><span>Try:</span><button type="button" class="ref-chip" data-example="https://github.com/miguelgrinberg/microblog">miguelgrinberg/microblog</button><button type="button" class="ref-chip" data-example="https://github.com/pallets/flask">pallets/flask</button><button type="button" class="ref-chip" data-example="https://github.com/psf/requests">psf/requests</button></div>
      <div id="scan-error" class="banner-warn" hidden></div></form>
      <p class="muted-small">Guardian analyses Python repositories (requirements.txt, pyproject.toml, setup.py, Pipfile or poetry.lock plus Python source). Repositories in other languages are stopped right after cloning, with an explanation. A scan without AI explanations takes about 2–3 minutes.</p></section>
      ${scans.length ? panel("Previous scans", "Click one to open it", `<div class="scan-table">${rows}</div>`) : ""}`;
  }
  function renderProgress(r) {
    return `${title("SCAN IN PROGRESS", "Scanning <span class='title-suffix'>repository</span>", "")}<section class="panel scan-card" id="progress-box"><div class="empty-state">Starting…</div></section>`;
  }
  function startPolling(id) {
    if (!id) return;
    const tick = async () => {
      try {
        const [m, ev] = await Promise.all([fetch(`/api/scans/${encodeURIComponent(id)}`).then(r => r.json()), fetch(`/api/scans/${encodeURIComponent(id)}/events?tail=10&types=log,error`).then(r => r.json())]);
        const box = document.querySelector("#progress-box"); if (!box) return;
        const st = m.stages || {}, icon = s => ({ done: "✓", running: "◌", failed: "✕", pending: "·" })[s] || "·";
        const clone = m.repo_url ? `<div class="stage-row ${Object.values(st).some(s => s.status !== "pending") ? "done" : m.status === "failed" ? "failed" : "running"}"><span class="stage-icon">${Object.values(st).some(s => s.status !== "pending") ? "✓" : m.status === "failed" ? "✕" : "◌"}</span><b>Clone</b><small>${esc(m.repo_url)}</small></div>` : "";
        box.innerHTML = `<h2>${esc(m.repo)} <small class="muted-small">${esc(m.scan_id)}</small></h2><div class="stage-list">${clone}${Object.entries(st).map(([k, s]) => `<div class="stage-row ${s.status}"><span class="stage-icon">${icon(s.status)}</span><b>Stage ${k} · ${esc(s.name)}</b><small>${esc(s.summary || "")}${s.duration_s ? ` · ${s.duration_s}s` : ""}</small></div>`).join("")}</div>
          ${m.status === "failed" ? `<div class="banner-warn"><b>Scan stopped.</b> ${esc(m.error || (ev.filter(e => e.type === "error").pop() || {}).message || "See the server log.")}</div>${link("← Try another repository", 'data-goto="scan"', "quiet-button")}` : ""}
          <div class="log-box">${ev.filter(e => e.type === "log").map(e => `<div>${esc(e.message)}</div>`).join("")}</div>`;
        if (m.status === "done") { clearInterval(pollTimer); location.href = `${location.pathname}?scan=${encodeURIComponent(id)}#/overview`; }
        if (m.status === "failed") clearInterval(pollTimer);
      } catch (e) { /* server restarting: keep polling */ }
    };
    tick(); pollTimer = setInterval(tick, 1500);
  }
  async function submitScan(e) {
    e.preventDefault();
    const path = document.querySelector("#scan-input").value.trim(), err = document.querySelector("#scan-error");
    err.hidden = true;
    try {
      const res = await fetch("/api/scans", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ path, offline: document.querySelector("#scan-offline").checked, llm: document.querySelector("#scan-ai").checked ? "auto" : "offline" }) });
      const j = await res.json();
      if (!res.ok) throw new Error(typeof j.detail === "string" ? j.detail : JSON.stringify(j.detail));
      scans = await fetch("/api/scans").then(r => r.json()).catch(() => scans);
      go("progress", "", { id: j.scan_id });
    } catch (ex) { err.hidden = false; err.textContent = ex.message; }
  }

  // ------------------------------------------------------------------ events
  function bind(r) {
    app.querySelectorAll("[data-goto]").forEach(el => el.addEventListener("click", () => { const v = el.dataset.goto; go(v, el.dataset.tab, el.dataset.risk ? { risk: el.dataset.risk } : {}); window.scrollTo(0, 0); }));
    app.querySelectorAll("[data-node]").forEach(el => el.addEventListener("click", ev => { ev.stopPropagation(); openNode(el.dataset.node); }));
    app.querySelectorAll("[data-focus]").forEach(el => el.addEventListener("click", () => go("architecture", "graph", { focus: el.dataset.focus, sel: el.dataset.focus })));
    app.querySelectorAll("[data-finding],[data-open-item]").forEach(el => el.addEventListener("click", ev => { ev.stopPropagation(); const id = el.dataset.finding || el.dataset.openItem; go("risk", tabOf(id), { open: id }); }));
    app.querySelectorAll("[data-open]").forEach(el => el.addEventListener("click", ev => { ev.stopPropagation(); const cur = route(); go("risk", cur.tab || "vulns", { ...Object.fromEntries(cur.p), open: el.dataset.open }); }));
    app.querySelectorAll("[data-evidence]").forEach(el => el.addEventListener("click", ev => { ev.stopPropagation(); go("risk", "evidence", { open: el.dataset.evidence }); }));
    app.querySelectorAll("[data-risk-p],[data-risk-r]").forEach(el => el.addEventListener("click", () => { const cur = route(), q = Object.fromEntries(cur.p); delete q.open; if ("riskP" in el.dataset) q.p = el.dataset.riskP; else q.risk = el.dataset.riskR; go("risk", "vulns", q); }));
    app.querySelectorAll("[data-inst]").forEach(el => el.addEventListener("click", () => { const q = Object.fromEntries(route().p); q.inst = 1; go("risk", "vulns", q); }));
    app.querySelectorAll("[data-ev-show]").forEach(el => el.addEventListener("click", () => go("risk", "evidence", { show: el.dataset.evShow })));
    document.querySelector("#ev-download")?.addEventListener("click", downloadEvidence);
    const closeModal = () => { const cur = route(), q = Object.fromEntries(cur.p); delete q.open; go(cur.view, cur.tab, q); };
    document.querySelector("#modal-x")?.addEventListener("click", closeModal);
    document.querySelector("#modal-back")?.addEventListener("click", e => { if (e.target.id === "modal-back") closeModal(); });
    document.body.classList.toggle("modal-open", !!document.querySelector("#modal-back"));
    app.querySelectorAll("[data-pkg]").forEach(el => el.addEventListener("click", ev => { ev.stopPropagation(); const cur = route(); go("architecture", "sbom", { sel: el.dataset.pkg, q: cur.tab === "sbom" ? cur.p.get("q") : "", f: cur.tab === "sbom" ? cur.p.get("f") : "" }); }));
    app.querySelectorAll("[data-sbom-f]").forEach(el => el.addEventListener("click", () => go("architecture", "sbom", { f: el.dataset.sbomF, q: r.p.get("q") })));
    app.querySelectorAll("[data-open-scan]").forEach(el => el.addEventListener("click", () => el.dataset.status === "running" ? go("progress", "", { id: el.dataset.openScan }) : (location.href = `${location.pathname}?scan=${encodeURIComponent(el.dataset.openScan)}#/overview`)));
    app.querySelectorAll("[data-example]").forEach(el => el.addEventListener("click", () => { document.querySelector("#scan-input").value = el.dataset.example; }));
    document.querySelector("#scan-form")?.addEventListener("submit", submitScan);
    if (r) bindRem(r);
    bindFixed();
    document.querySelector("#cdx-download")?.addEventListener("click", downloadCdx);
    const sq = document.querySelector("#sbom-q");
    if (sq) { let t; sq.addEventListener("input", () => { clearTimeout(t); t = setTimeout(() => { go("architecture", "sbom", { q: sq.value, f: r.p.get("f"), sel: r.p.get("sel") }); setTimeout(() => { const n = document.querySelector("#sbom-q"); if (n) { n.focus(); n.setSelectionRange(n.value.length, n.value.length); } }, 0); }, 250); }); }
    // graph nodes
    app.querySelectorAll("[data-gnode]").forEach(el => {
      const id = el.dataset.gnode;
      const click = () => {
        const cur = route(), focus = cur.p.get("focus") || "", sel = cur.p.get("sel");
        if (id === "more:fns") return go("architecture", "graph", { focus, sel, all: 1 });
        if (id === "more:sbom") return go("architecture", "sbom", { f: "vulnerable" });
        if (id.startsWith("grp:")) return go("architecture", "graph", { focus: id.slice(4), sel: id.slice(4) });
        const n = N.get(id);
        if (n?.t === "module" && !focus) return go("architecture", "graph", { focus: id, sel: id });
        go("architecture", "graph", { focus, sel: id, all: cur.p.get("all") });
      };
      el.addEventListener("click", click);
      el.addEventListener("dblclick", () => { const n = N.get(id); if (n && ["function", "class", "module", "package", "service", "env"].includes(n.t)) go("architecture", "graph", { focus: id, sel: id }); });
      el.addEventListener("keydown", e => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); click(); } });
    });
    const gs = document.querySelector("#gsearch"), pop = document.querySelector("#gsearch-pop");
    if (gs) {
      gs.addEventListener("input", () => { const hits = searchHits(gs.value); pop.hidden = !hits.length; pop.innerHTML = hits.map(n => `<button data-hit="${esc(n.id)}"><span class="hit-kind">${esc(kindName[n.t] || n.t)}</span><b>${esc(n.l)}</b><small>${esc(n.t === "function" || n.t === "class" ? `${n.f || ""}` : n.t === "package" ? n.v || "" : n.m ? modName(n.m) : "")}</small>${n.risk ? `<i class="risk-dot ${n.risk}"></i>` : ""}</button>`).join(""); pop.querySelectorAll("[data-hit]").forEach(b => b.addEventListener("mousedown", ev => { ev.preventDefault(); openNode(b.dataset.hit); })); });
      gs.addEventListener("keydown", e => { if (e.key === "Enter") { const first = pop.querySelector("[data-hit]"); if (first) openNode(first.dataset.hit); } if (e.key === "Escape") pop.hidden = true; });
      gs.addEventListener("blur", () => setTimeout(() => { pop.hidden = true; }, 150));
    }
  }

  // ------------------------------------------------------------------ shell events + loading
  document.querySelector("#navigation").addEventListener("click", e => { const item = e.target.closest("[data-view]"); if (item) { go(item.dataset.view); window.scrollTo(0, 0); } });
  document.querySelector("#new-scan-button").addEventListener("click", () => go("scan"));
  document.querySelector("#repo-switcher").addEventListener("click", () => go("scan"));
  document.querySelector("#import-button").addEventListener("click", () => document.querySelector("#file-input").click());
  document.querySelector("#file-input").addEventListener("change", async e => {
    const file = e.target.files[0]; if (!file) return;
    const status = document.querySelector("#import-status");
    try {
      const parsed = JSON.parse(await file.text());
      if (!parsed.repo || !Array.isArray(parsed.modules)) throw new Error("Expected a Guardian dashboard bundle (ui_bundle.json) with repo and modules.");
      data = normalize(parsed); buildIndex(); setPill("LOADED SCAN");
      status.hidden = false; status.className = "import-status success"; status.textContent = `Loaded ${file.name}.`;
      go("overview");
    } catch (err) { status.hidden = false; status.className = "import-status error"; status.textContent = err instanceof SyntaxError ? "Could not read this file as JSON." : err.message; }
    e.target.value = "";
  });
  function setPill(text) { document.querySelector(".demo-pill").innerHTML = `<i></i> ${text}`; }

  async function boot() {
    if (data) buildIndex();
    if (!location.protocol.startsWith("http")) { mode = "static"; return render(); }
    try {                                                    // guardian web: a list of scans
      const res = await fetch("/api/scans");
      if (!res.ok) throw new Error();
      scans = await res.json(); mode = "web";
      document.body.classList.add("mode-web");
      const pick = scans.find(s => s.scan_id === scanId) || scans.find(s => s.pinned && s.status === "done") || scans.find(s => s.status === "done");
      if (!pick) { data = null; setPill("NO SCAN"); if (!location.hash.includes("progress")) location.hash = "#/scan"; return render(); }
      scanId = pick.scan_id;
      if (pick.status === "running") { data = null; setPill("SCANNING"); location.hash = `#/progress?id=${encodeURIComponent(scanId)}`; return render(); }
      const d = await fetch(`/api/scans/${encodeURIComponent(scanId)}/dashboard`);
      if (!d.ok) { data = null; setPill("SCAN FAILED"); location.hash = `#/progress?id=${encodeURIComponent(scanId)}`; return render(); }
      data = normalize(await d.json()); buildIndex(); setPill(pick.demo ? "DEMO SCAN" : "LIVE SCAN");
      loadRem(new URLSearchParams(location.hash.split("?")[1] || "").get("open")).then(() => { const n = REM.list?.counts?.decide; const el = document.querySelector("#rem-count"); if (el) el.textContent = n || ""; });
      return render();
    } catch { /* not guardian web */ }
    try {                                                    // guardian serve: one scan
      const b = await fetch("/ui-bundle").then(r => (r.ok ? r.json() : null));
      if (b && b.repo && Array.isArray(b.modules)) { data = normalize(b); buildIndex(); mode = "serve"; setPill("LIVE SCAN"); }
    } catch { /* static demo */ }
    render();
  }
  document.addEventListener("keydown", e => { if (e.key === "Escape" && document.querySelector("#modal-back")) document.querySelector("#modal-x").click(); });
  boot();
})();
