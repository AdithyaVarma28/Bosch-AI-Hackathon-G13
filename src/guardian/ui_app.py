"""Guardian web app: one page for the whole flow (served by `guardian serve` at /).

Dashboard -> New scan (live pipeline) -> Run (pipeline, human approvals, report, remediation report)
-> Heal agent (start/resume, pending approvals for the current iteration, live fixes and agent decisions).
Every decision goes through POST /runs/{id}/decisions with the exact plan hash the reviewer saw.
"""

APP_HTML = r"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Guardian</title>
<style>
:root{--bg:#f5f6f8;--card:#fff;--ink:#162029;--sub:#5d6874;--line:#e1e5ea;--soft:#eef1f4;--accent:#0b6e99;--accent-ink:#fff;
--ok:#1a7f37;--warn:#b26b00;--bad:#c62828;--p0:#c62828;--p1:#e4572e;--p2:#d9a400;--p3:#5b8def;--fact:#e6f3ea;--inf:#fff4dc;--unk:#eef0f3;
--mono:ui-monospace,SFMono-Regular,Consolas,monospace;--shadow:0 1px 2px rgba(0,0,0,.06)}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#0e1317;--card:#161c22;--ink:#e5eaee;--sub:#95a1ac;--line:#28313a;--soft:#1d252d;
--accent:#4fb3e0;--accent-ink:#06202c;--fact:#16301f;--inf:#3a2d10;--unk:#232a31}}
:root[data-theme="dark"]{--bg:#0e1317;--card:#161c22;--ink:#e5eaee;--sub:#95a1ac;--line:#28313a;--soft:#1d252d;--accent:#4fb3e0;--accent-ink:#06202c;
--fact:#16301f;--inf:#3a2d10;--unk:#232a31}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
a{color:var(--accent)}header{position:sticky;top:0;z-index:5;background:var(--card);border-bottom:1px solid var(--line);display:flex;gap:16px;
align-items:center;padding:10px 20px;flex-wrap:wrap}header b.brand{font-size:17px}nav{display:flex;gap:4px;flex-wrap:wrap}
nav a{padding:6px 12px;border-radius:8px;text-decoration:none;color:var(--sub);font-weight:600}nav a.on{background:var(--soft);color:var(--ink)}
.rv{margin-left:auto;display:flex;gap:6px;align-items:center;font-size:12px;color:var(--sub)}
main{max-width:1240px;margin:0 auto;padding:16px 20px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px;margin-bottom:14px;box-shadow:var(--shadow);overflow-x:auto}
h1{font-size:20px;margin:0 0 4px}h2{font-size:16px;margin:0 0 10px}h3{font-size:14px;margin:14px 0 6px}
.sub{color:var(--sub);font-size:12px}.mono{font-family:var(--mono);font-size:12px}
table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:7px 8px;border-bottom:1px solid var(--line);vertical-align:top}th{font-size:12px;color:var(--sub);font-weight:600}
tr.click{cursor:pointer}tr.click:hover{background:var(--soft)}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:10px}.kpi{border:1px solid var(--line);border-radius:10px;padding:10px 12px;background:var(--card)}
.kpi b{display:block;font-size:24px}.grid2{display:grid;grid-template-columns:1fr 1fr;gap:14px}
@media (max-width:860px){.grid2{grid-template-columns:1fr}main{padding:12px 16px}header{padding:10px 16px}.rv{margin-left:0}}
.badge{display:inline-block;padding:1px 8px;border-radius:10px;font-size:11px;font-weight:700;color:#fff;background:#7a8590;white-space:nowrap}
.P0{background:var(--p0)}.P1{background:var(--p1)}.P2{background:var(--p2);color:#222}.P3{background:var(--p3)}
.s-ok,.s-applied,.s-Verified,.s-validated,.s-threshold_met,.s-approved,.s-done{background:var(--ok)}
.s-degraded,.s-Partially,.s-awaiting_approval,.s-running,.s-skipped,.s-deferred,.s-Awaiting{background:var(--warn)}
.s-failed,.s-Not,.s-rejected,.s-Rejected,.s-rolled_back,.s-stopped,.s-escalated,.s-Escalated,.s-diff_mismatch{background:var(--bad)}
button,.btn{font:inherit;border:1px solid var(--line);background:var(--card);color:var(--ink);border-radius:8px;padding:6px 12px;cursor:pointer;font-weight:600}
button.pri{background:var(--accent);border-color:var(--accent);color:var(--accent-ink)}button.danger{color:var(--bad)}button:disabled{opacity:.5;cursor:not-allowed}
input,select,textarea{font:inherit;color:var(--ink);background:var(--card);border:1px solid var(--line);border-radius:8px;padding:6px 8px}
input[type=text],textarea{width:100%}label{display:block;margin:6px 0}.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
.claim{padding:6px 10px;border-radius:8px;margin:4px 0}.claim.fact{background:var(--fact)}.claim.inference{background:var(--inf)}.claim.unknown{background:var(--unk)}
pre{white-space:pre-wrap;word-break:break-word;background:var(--soft);padding:10px;border-radius:8px;max-height:380px;overflow:auto;margin:6px 0}
.tabs{display:flex;gap:4px;border-bottom:1px solid var(--line);margin-bottom:12px;flex-wrap:wrap}.tabs a{padding:8px 12px;text-decoration:none;color:var(--sub);
font-weight:600;border-bottom:2px solid transparent}.tabs a.on{color:var(--ink);border-color:var(--accent)}
iframe{width:100%;height:80vh;border:1px solid var(--line);border-radius:12px;background:var(--card)}
.stage{display:grid;grid-template-columns:150px 90px 1fr;gap:8px;padding:5px 0;border-bottom:1px dashed var(--line)}
.plan{border:1px solid var(--line);border-radius:12px;padding:14px;margin-bottom:12px}.plan.wait{border-color:var(--warn)}
.cand{border:1px solid var(--line);border-radius:8px;padding:8px 10px;margin:6px 0}.cand.fin{border-color:var(--accent)}
.msg{padding:8px 12px;border-radius:8px;margin:8px 0}.msg.err{background:#fdecea;color:#8a1c12}.msg.ok{background:var(--fact)}
.empty{padding:24px;text-align:center;color:var(--sub)}.log{max-height:300px;overflow:auto;font-family:var(--mono);font-size:12px}
</style></head><body>
<header><b class="brand">🛡 Guardian</b><nav id="nav"></nav>
<div class="rv">Reviewer <input id="reviewer" type="text" placeholder="your name" style="width:160px"></div></header>
<main id="main"></main>
<script>
const $=s=>document.querySelector(s);
const esc=s=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const badge=(s,cls)=>`<span class="badge ${esc(cls||("s-"+String(s||"").split(" ")[0]))}">${esc(String(s||"").replace(/_/g," "))}</span>`;
const band=b=>`<span class="badge ${esc(b)}">${esc(b||"?")}</span>`;
function store(k,v){try{if(v===undefined)return localStorage.getItem(k);localStorage.setItem(k,v)}catch(e){return null}}
async function api(path,opts={}){const r=await fetch(path,{headers:{"Content-Type":"application/json"},...opts,body:opts.body?JSON.stringify(opts.body):undefined});
 let d=null;try{d=await r.json()}catch(e){}if(!r.ok)throw new Error((d&&d.detail)||`${r.status} ${r.statusText}`);return d}
const reviewer=()=>($("#reviewer").value||"").trim();
$("#reviewer").value=store("guardian.reviewer")||"";$("#reviewer").onchange=()=>store("guardian.reviewer",reviewer());
let timers=[];function clearTimers(){timers.forEach(t=>clearInterval(t));timers=[];if(window._es){window._es.close();window._es=null}}
const NAV=[["#/","Dashboard"],["#/new","New scan"],["#/detect","Detection"],["#/remediate","Remediation"],["#/heal","Heal agent"],["#/chaos","Chaos"],["#/runs","Runs"]];
function nav(){const h=location.hash||"#/";$("#nav").innerHTML=NAV.map(([k,v])=>`<a href="${k}" class="${(h===k||(k!=="#/"&&h.startsWith(k)))?"on":""}">${v}</a>`).join("")}
window.onhashchange=route;
function route(){clearTimers();nav();const h=(location.hash||"#/").slice(1).split("/").filter(Boolean);
 const v=h[0]||"";if(!v)return dash();if(v==="new")return newScan();if(v==="runs")return runsView();if(v==="run")return runView(h[1],h[2]||"pipeline");if(v==="detect"||v==="remediate")return sectionView(v,h[1],h[2]);
 if(v==="heal")return healView(h[1]?decodeURIComponent(h[1]):null);if(v==="chaos")return chaosView(h[1]);dash()}
function fail(e){return `<div class="msg err">${esc(e.message||e)}</div>`}

/* ------------------------------------------------------------------ dashboard */
async function dash(){const m=$("#main");m.innerHTML=`<div class="empty">Loading…</div>`;
 let runs=[],clones=[];try{[runs,clones]=await Promise.all([api("/runs"),api("/clones")])}catch(e){m.innerHTML=fail(e);return}
 const waiting=runs.filter(r=>(r.plan_status||{}).awaiting_approval);const ver=runs.reduce((a,r)=>a+((r.verdicts||{})["Verified"]||0)+((r.verdicts||{})["Partially verified"]||0),0);
 m.innerHTML=`<section class="card"><h1>Software Supply Chain Guardian</h1><div class="sub">Detect what is in an application and what is risky (Day 1), then prioritize, investigate, plan fixes, get human approval, validate, rescan and verify (Day 2), and heal cloned repositories in a loop.</div>
 <div class="row" style="margin-top:12px"><a class="btn pri" href="#/new" style="text-decoration:none">New scan</a><a class="btn" href="#/detect" style="text-decoration:none">Detection: report · graph · SBOM</a>
 <a class="btn" href="#/remediate" style="text-decoration:none">Remediation & approval</a><a class="btn" href="#/heal" style="text-decoration:none">Heal agent</a><a class="btn" href="#/chaos" style="text-decoration:none">Chaos</a></div></section>
 <section class="kpis" style="margin-bottom:14px"><div class="kpi"><span class="sub">Runs</span><b>${runs.length}</b></div>
 <div class="kpi"><span class="sub">Runs waiting for approval</span><b>${waiting.length}</b></div><div class="kpi"><span class="sub">Verified / partially verified fixes</span><b>${ver}</b></div>
 <div class="kpi"><span class="sub">Clones (heal)</span><b>${clones.length}</b></div></section>
 ${waiting.length?`<section class="card"><h2>Needs your approval</h2><table><tr><th>Repository</th><th>Run</th><th>Plans waiting</th><th></th></tr>${waiting.map(r=>`<tr><td>${esc(r.repo)}</td><td class="mono">${esc(r.run_id)}</td><td>${r.plan_status.awaiting_approval}</td><td><a href="#/remediate/${esc(r.run_id)}/approvals">Review &amp; approve →</a></td></tr>`).join("")}</table></section>`:""}
 <div class="grid2"><section class="card"><h2>Recent runs</h2>${runsTable(runs.slice(0,8))}<p><a href="#/runs">All runs →</a></p></section>
 <section class="card"><h2>Cloned repositories</h2>${clonesTable(clones)}</section></div>`}
function runsTable(runs){if(!runs.length)return `<div class="empty">No runs yet. <a href="#/new">Start a scan</a>.</div>`;
 return `<table><tr><th>Repository</th><th>Run</th><th>Findings</th><th>Day 2</th></tr>${runs.map(r=>`<tr class="click" onclick="location.hash='#/run/${esc(r.run_id)}'">
 <td><b>${esc(r.repo)}</b><div class="sub">${esc(r.generated_at||"")}</div></td><td class="mono">${esc(r.run_id)}${r.status&&r.status!=="done"?" "+badge(r.status):""}</td>
 <td>${["P0","P1","P2","P3"].map(b=>(r.bands||{})[b]?band(b)+" "+(r.bands[b])+" ":"").join("")||"—"}</td>
 <td>${Object.entries(r.plan_status||{}).map(([k,v])=>badge(k)+" "+v).join(" ")||(r.day2?"":'<span class="sub">detection only</span>')}</td></tr>`).join("")}</table>`}
function clonesTable(cl){if(!cl.length)return `<div class="empty">No clones yet: scanning a GitHub URL creates one in output/clones.</div>`;
 return `<table><tr><th>Clone</th><th>Branch</th><th>Heal</th></tr>${cl.map(c=>`<tr class="click" onclick="location.hash='#/heal/${encodeURIComponent(c.name)}'">
 <td><b>${esc(c.name)}</b></td><td class="mono">${esc(c.branch||"")}</td><td>${c.heal?badge(c.heal.status)+` <span class="sub">it ${c.heal.iterations} · ${c.heal.fixes} fix(es) · ${c.heal.remaining??"?"} left</span>`:'<span class="sub">not started</span>'}</td></tr>`).join("")}</table>`}
async function runsView(){const m=$("#main");m.innerHTML=`<div class="empty">Loading…</div>`;try{const r=await api("/runs?limit=300");m.innerHTML=`<section class="card"><h2>All runs</h2>${runsTable(r)}</section>`}catch(e){m.innerHTML=fail(e)}}

/* ------------------------------------------------------------------ new scan */
async function newScan(){const m=$("#main");let clones=[];try{clones=await api("/clones")}catch(e){}
 m.innerHTML=`<section class="card"><h2>New scan</h2><div class="sub">One pipeline: detection (SBOM, dependency graph, vulnerabilities, suspicious changes, evidence) → prioritize → investigate (Threat Investigator agent) → advisory analysis (Advisory Analyst agent) → remediation plans → stops at the human approval gate.</div>
 <form id="f"><label>GitHub URL, local path, or a clone<input type="text" id="t" list="cl" placeholder="https://github.com/owner/repo" required></label>
 <datalist id="cl">${clones.map(c=>`<option value="${esc(c.path)}">${esc(c.name)}</option>`).join("")}</datalist>
 <div class="row"><label><input type="checkbox" id="rem" checked> Continue into Day 2 (remediation up to the approval gate)</label>
 <label><input type="checkbox" id="llm" checked> LLM agents (needs GROQ_API_KEY)</label><label><input type="checkbox" id="off"> Offline (cache only)</label>
 <label><input type="checkbox" id="fx"> Bundled demo snapshots (fixture)</label>
 <label>Sandbox <select id="sb"><option value="docker">docker</option><option value="none">none (verdict ≤ partially verified)</option><option value="local">local (runs repo code here)</option></select></label>
 <label>Plans per run <input type="number" id="mq" value="5" min="1" max="20" style="width:70px"></label></div>
 <div class="row" style="margin-top:10px"><button class="pri" type="submit">Start scan</button></div></form><div id="o"></div></section>`;
 $("#f").onsubmit=async ev=>{ev.preventDefault();$("#o").innerHTML="";try{const r=await api("/runs",{method:"POST",body:{repo_url:$("#t").value.trim(),remediate:$("#rem").checked,use_llm:$("#llm").checked,
  offline:$("#off").checked,fixture_snapshots:$("#fx").checked,sandbox:$("#sb").value,max_queue:+$("#mq").value||5}});location.hash=`#/run/${r.run_id}/pipeline`}catch(e){$("#o").innerHTML=fail(e)}}}

/* ------------------------------------------------------------------ run view */
const STAGES=[["Detect (Day 1)",[["ingest","clone / open the repository"],["cartographer","manifests, lockfiles, Docker, CI, history"],["resolver_sbom","resolved components + CycloneDX SBOM"],["code_index","imports, calls, routes, sinks"],["graph","declared / resolved / usage graph"],["dossier_agent","what the app is, exposure"],["supervisor","which detectors run, and why"],["vuln_intel","OSV advisories, KEV, EPSS"],["change_anomaly","lockfile tampering, source changes, new deps"],["package_signals","install scripts, typosquats, registry signals"],["container_ci","Dockerfile / compose / workflow rules"],["secrets","hard-coded credentials"],["discrepancies","declared vs imported"],["correlator","dedupe, attack class, P0–P3 band"],["evidence_agent","verified explanations"],["report","report.json / report.html"]]],
 ["Remediate (Day 2)",[["day2_start","policy, registry, advisory sources"],["prioritize","S10 risk score + confidence"],["investigate","S11 Threat Investigator agent"],["advisory_analysis","Advisory Analyst agent (6 questions)"],["remediation_plan","S12 candidates, simulation, tournament"],["approval_gate","S13 human approval (stops here)"],["validate","S14 sandbox build/test + S15 rescan"],["verify","S16 policy + independent verifier"],["remediation_report","Day 2 report, VEX"]]]];
/* Detection (Day 1) and Remediation (Day 2) are separate sections; each has a run picker and its own tabs.
   [key, label, kind, page] kind: d1 = report.html page, d2 = Day 2 page, native = rendered here */
const DETECT_TABS=[["findings","Findings report","d1","report"],["graph","Dependency graph","d1","graph"],["sbom","SBOM","d1","sbom"]];
const REM_TABS=[["overview","Overview","d2","overview"],["risk","1 Prioritize","d2","queue"],["threats","2 Threat investigation","d2","investigate"],
 ["advisories","Advisory analysis","d2","advisories"],["plans","3 Fix plans","d2","plans"],["approvals","Human approval","native"],
 ["validate","4 Validation","d2","validate"],["verify","5 Verification","d2","verify"],["audit","Audit trail","d2","audit"]];
async function pickRun(section,id,day2Only){const runs=(await api("/runs?limit=300").catch(()=>[])).filter(r=>r.status!=="running"&&(!day2Only||r.day2));
 if(!id&&runs.length){id=runs[0].run_id}return {runs,id}}
async function sectionView(section,id,tab){const m=$("#main");const detect=section==="detect";const TABS=detect?DETECT_TABS:REM_TABS;
 m.innerHTML=`<div class="empty">Loading…</div>`;const pr=await pickRun(section,id,!detect);id=pr.id;
 if(!id){m.innerHTML=`<section class="card"><h2>${detect?"Detection":"Remediation"}</h2><div class="empty">${detect?"No scans yet.":"No run has Day 2 data yet."} <a href="#/new">Start a scan</a>.</div></section>`;return}
 tab=TABS.find(t=>t[0]===tab)?tab:TABS[0][0];const t=TABS.find(x=>x[0]===tab);
 m.innerHTML=`<section class="card"><div class="row" style="justify-content:space-between;align-items:flex-start">
 <div><h1>${detect?"Detection: what is in the application and what is risky":"Remediation: prioritize, investigate, fix, approve, verify"}</h1>
 <div class="sub">${detect?"Day 1 · SBOM, dependency graph, vulnerabilities, suspicious changes, evidence":"Day 2 · S10–S16, human approval gate, independent verification"}</div></div>
 <label style="margin:0">Run <select id="rp" style="max-width:420px">${pr.runs.map(r=>`<option value="${esc(r.run_id)}" ${r.run_id===id?"selected":""}>${esc(r.repo)} · ${esc(r.run_id)}</option>`).join("")}</select></label></div>
 <div id="sumk" class="kpis" style="margin-top:12px"></div>
 <div class="row" style="margin-top:10px"><a class="btn" href="#/run/${esc(id)}/pipeline" style="text-decoration:none">Pipeline</a>
 ${detect?`<a class="btn" href="#/remediate/${esc(id)}" style="text-decoration:none">Remediation for this run →</a><a class="btn" href="/runs/${esc(id)}/sbom" target="_blank" style="text-decoration:none">CycloneDX JSON ↗</a><a class="btn" href="/runs/${esc(id)}/report" target="_blank" style="text-decoration:none">report.json ↗</a>`
  :`<a class="btn" href="#/detect/${esc(id)}" style="text-decoration:none">← Detection for this run</a><a class="btn" href="/runs/${esc(id)}/remediation" target="_blank" style="text-decoration:none">day2 report.json ↗</a>`}</div></section>
 <section class="card"><div class="tabs">${TABS.map(([k,v])=>`<a href="#/${section}/${esc(id)}/${k}" class="${tab===k?"on":""}">${v}</a>`).join("")}</div><div id="tb"></div></section>`;
 $("#rp").onchange=e=>{location.hash=`#/${section}/${e.target.value}/${tab}`};
 api(`/runs/${id}/report`).then(r=>{const S=r.summary||{},sb=((r.sbom||{}).report||{});const rem=r.remediation||{};
  $("#sumk").innerHTML=(detect?[["Repository",r.repo.name],["Components",S.components],["Direct / transitive",`${S.direct} / ${S.transitive}`],["Vulnerabilities",S.vulnerabilities],
   ["Supply-chain signals",S.supply_chain_signals],["Container / CI",S.container_ci],["Secrets",S.secrets],["SBOM confidence",sb.confidence||"?"]]
   :[["Repository",r.repo.name],["Plans",(rem.plans||[]).length],...Object.entries(rem.plan_status||{}).map(([k,v])=>[k.replace(/_/g," "),v]),...Object.entries(rem.verdicts||{})])
   .map(([k,v])=>`<div class="kpi"><span class="sub">${esc(k)}</span><b style="font-size:${String(v).length>12?"15px":"24px"}">${esc(v)}</b></div>`).join("")}).catch(()=>{});
 const tb=$("#tb");if(t[2]==="d1"){tb.innerHTML=`<iframe src="/runs/${id}/report.html?embed=1#${t[3]}" title="${esc(t[1])}" style="height:82vh"></iframe>`;return}
 if(t[2]==="d2"){tb.innerHTML=`<iframe src="/runs/${id}/remediation.html?embed=1#${t[3]}" title="${esc(t[1])}" style="height:82vh"></iframe>`;return}
 return approvalsPanel(id,tb,{})}
async function runView(id,tab){
 if(DETECT_TABS.find(t=>t[0]===tab)){location.hash=`#/detect/${id}/${tab}`;return}
 if(REM_TABS.find(t=>t[0]===tab)){location.hash=`#/remediate/${id}/${tab}`;return}
 const m=$("#main");
 m.innerHTML=`<section class="card"><div class="row" style="justify-content:space-between"><div><h1 id="rt">Run ${esc(id)}</h1><div class="sub" id="rs"></div></div>
 <div class="row"><a class="btn pri" href="#/detect/${esc(id)}" style="text-decoration:none">Detection: report · graph · SBOM</a><a class="btn pri" href="#/remediate/${esc(id)}" style="text-decoration:none">Remediation & approval</a></div></div>
 <h2 style="margin-top:12px">Pipeline</h2><div id="tb"></div></section>`;
 api(`/runs/${id}/report`).then(r=>{$("#rt").textContent=`${r.repo.name}`;$("#rs").textContent=`run ${id} · commit ${(r.repo.commit||"").slice(0,10)} · ${r.generated_at} · ${r.summary.components} components · ${r.summary.findings} findings`}).catch(()=>{$("#rs").textContent="running…"});
 return pipelinePanel(id,$("#tb"))}
function stageHtml(st,msgs){return STAGES.map(([g,list])=>`<h3>${g}</h3>${list.map(([n,d])=>`<div class="stage"><span class="mono">${n}</span><span>${st[n]?badge(st[n]):'<span class="sub">—</span>'}</span><span class="sub">${esc(msgs[n]||d)}</span></div>`).join("")}`).join("")}
async function pipelinePanel(id,tb){tb.innerHTML=`<div id="pl"></div><div id="pa" style="margin-top:12px"></div>`;const st={},msgs={};
 const draw=()=>{$("#pl").innerHTML=stageHtml(st,msgs)};draw();
 let live=null;try{live=await api(`/runs/${id}`)}catch(e){}
 if(live&&live.events!==undefined&&(live.status==="running"||live.day2==="running"||typeof live.events==="number")){
  const es=new EventSource(`/runs/${id}/events`);window._es=es;es.onmessage=ev=>{const e=JSON.parse(ev.data);if(e.node==="run"){es.close();after();return}
   st[e.node]=e.status;msgs[e.node]=e.message;draw()};es.onerror=()=>{es.close();after()}}else after();
 async function after(){try{const r=await api(`/runs/${id}/report`);
  $("#rt").textContent=r.repo.name;$("#rs").textContent=`run ${id} · commit ${(r.repo.commit||"").slice(0,10)} · ${r.generated_at} · ${r.summary.components} components · ${r.summary.findings} findings`;
  Object.entries((r.coverage||{}).node_status||{}).forEach(([k,v])=>{if(!st[k])st[k]=v});
  if(r.remediation){["day2_start","prioritize","investigate","advisory_analysis","remediation_plan","approval_gate","remediation_report"].forEach(k=>{if(!st[k])st[k]="ok"})}draw();
  const ps=(r.remediation||{}).plan_status||{};$("#pa").innerHTML=r.remediation?`<div class="msg ${ps.awaiting_approval?"":"ok"}">${ps.awaiting_approval?`${ps.awaiting_approval} plan(s) are waiting at the human approval gate. <a href="#/remediate/${id}/approvals">Review and approve →</a>`:"No plan is waiting for approval."}</div>`:`<div class="msg">Detection only. <button id="go2">Run Day 2 now</button></div>`;
  const b=$("#go2");if(b)b.onclick=async()=>{try{await api(`/runs/${id}/remediate`,{method:"POST",body:{}});location.hash=`#/remediate/${id}/approvals`}catch(e){$("#pa").innerHTML+=fail(e)}}}catch(e){}}}

/* ------------------------------------------------------------------ human approval (shared by run + heal) */
function ans(label,a){if(!a)return "";return `<tr><td>${esc(label)}</td><td><b>${esc(a.value)}</b></td><td><div class="claim ${esc(a.basis)}">${esc(a.text)} <span class="sub">(${esc(a.basis)}, ${esc(a.verifier_status)}, ${esc(a.by)})</span></div></td></tr>`}
async function approvalsPanel(id,box,opt){box.innerHTML=`<div class="empty">Loading plans…</div>`;let d;
 try{d=await api(`/runs/${id}/approvals`)}catch(e){box.innerHTML=fail(e)+(String(e.message).includes("no such table")||String(e.message).includes("report")?"":"");return}
 const plans=d.plans||[];if(!plans.length){box.innerHTML=`<div class="empty">No remediation plans for this run (nothing in the Fix-now bucket, or Day 2 has not run).</div>`;return}
 const waiting=plans.filter(p=>p.status==="awaiting_approval"),approved=plans.filter(p=>p.status==="approved");
 box.innerHTML=`<div class="msg">You approve an exact <b>plan hash</b>: its finalists, edits and diffs. If anything changes the plan gets a new hash and needs a new approval. Decisions are append-only and name the reviewer (top right).</div>
 ${opt.heal?"":`<div class="row" style="margin:8px 0">${approved.length?`<b>${approved.length} approved plan(s) ready.</b>`:""}<label>Sandbox <select id="vsb"><option>docker</option><option value="none">none</option><option>local</option></select></label>
 <label><input type="checkbox" id="vfx"> fixture snapshots</label><label><input type="checkbox" id="vllm" checked> LLM</label><button class="pri" id="vgo" ${approved.length?"":"disabled"}>Validate approved plans (S14–S16)</button><span id="vst" class="sub"></span></div>`}
 <div id="pm"></div>${plans.map((p,i)=>planCard(p,i,d)).join("")}`;
 plans.forEach((p,i)=>wirePlan(id,p,i,box,opt));
 const vg=$("#vgo");if(vg)vg.onclick=async()=>{try{await api(`/runs/${id}/remediate`,{method:"POST",body:{sandbox:$("#vsb").value,fixture_snapshots:$("#vfx").checked,use_llm:$("#vllm").checked}});
  $("#vst").textContent="validating… (sandbox build/test, rescan, verify)";const t=setInterval(async()=>{const r=await api(`/runs/${id}`).catch(()=>({}));if(r.day2&&r.day2!=="running"){clearInterval(t);approvalsPanel(id,box,opt)}},3000);timers.push(t)}catch(e){$("#vst").innerHTML=fail(e)}}}
function planCard(p,i,d){const rep=(d.reports||{})[p.plan_key];const wait=p.status==="awaiting_approval";
 const fins=p.finalists.map(c=>p.candidates.find(x=>x.id===c)).filter(Boolean);const others=p.candidates.filter(c=>!p.finalists.includes(c.id)&&c.diff&&!c.rejected_reason);
 const adv=p.finding_ids.map(f=>(d.advisories||{})[f]).filter(Boolean),inv=p.finding_ids.map(f=>(d.investigations||{})[f]).filter(Boolean);
 return `<div class="plan ${wait?"wait":""}" id="plan${i}"><div class="row" style="justify-content:space-between"><div><b>${esc(p.title)}</b><div class="sub mono">${esc(p.plan_key)} · rev ${p.revision} · hash ${esc(p.plan_hash.slice(0,16))}${p.parent_hash?" · parent "+esc(p.parent_hash.slice(0,12)):""}</div></div><div>${badge(p.status)} ${rep?badge(rep.verdict)+` <span class="sub">${esc(rep.confidence)}</span>`:""}</div></div>
 <div class="sub" style="margin:6px 0">${p.finding_ids.map(f=>(d.findings||{})[f]).filter(Boolean).slice(0,6).map(f=>band(f.band)+" "+esc(f.title)).join("<br>")}${p.finding_ids.length>6?`<br>… ${p.finding_ids.length-6} more`:""}</div>
 <h3>Candidate fixes</h3>${fins.map(c=>candHtml(c,i,true,wait)).join("")||'<div class="sub">No automatic fix passed simulation and policy: escalated.</div>'}
 ${others.length?`<details><summary class="sub">${others.length} other simulated candidate(s)</summary>${others.map(c=>candHtml(c,i,false,wait)).join("")}</details>`:""}
 ${p.candidates.filter(c=>c.action==="mitigate"||c.action==="escalate").map(c=>`<div class="cand"><span class="badge">${esc(c.action)}</span> ${esc(c.summary)} <span class="sub">(manual, never applied automatically)</span></div>`).join("")}
 ${adv.length?`<details><summary>Advisory Analyst (${adv.length})</summary>${adv.map(a=>`<h3>${esc(a.advisory_id)} <span class="sub">${esc(a.generated_by)}</span></h3><table>${ans("Relevant to this app?",a.relevance)}${ans("Vulnerable feature used?",a.feature_usage)}${ans("Workaround / mitigation?",a.mitigation_answer)}${ans("Installed version + usage path?",a.affects_installed)}${ans("Safest remediation",a.recommended)}<tr><td>Missing evidence</td><td colspan=2 class="sub">${esc((a.missing_evidence||[]).join("; "))}</td></tr></table>`).join("")}</details>`:""}
 ${inv.length?`<details><summary>Threat Investigator (${inv.length})</summary>${inv.map(v=>`<div class="claim inference"><b>${esc(v.verdict.replace(/_/g," "))}</b> by ${esc(v.verdict_by||"rules")} (rule baseline ${esc(v.rule_verdict||v.verdict)}): ${esc(v.verdict_reason)}${(v.guardrail_notes||[]).map(n=>`<div class="sub">guardrail: ${esc(n)}</div>`).join("")}</div>`).join("")}</details>`:""}
 ${(p.rationale||[]).length?`<details><summary>Rationale (${p.rationale.length} verified claims)</summary>${p.rationale.filter(c=>c.verifier_status!=="rejected").map(c=>`<div class="claim ${esc(c.type)}">${esc(c.text)}</div>`).join("")}</details>`:""}
 ${wait?`<div class="row" style="margin-top:10px"><button class="pri" data-act="approve">Approve selected</button><button data-act="reject" class="danger">Reject</button>
 <button data-act="accept">Accept risk…</button>${opt_skip()}<span class="sub">Default selection = all finalists (tournament picks the winner after sandbox validation).</span></div><div class="ar" style="display:none;margin-top:8px"><label>Reason<input type="text" class="ar-r"></label><label>Expires <input type="date" class="ar-e"></label><button data-act="accept-go">Record risk acceptance</button></div><div class="pmsg"></div>`:""}
 ${rep&&rep.chosen?`<div class="msg ok" style="margin-top:10px">Applied candidate: ${esc(rep.chosen.summary)} — ${esc(rep.verdict)} (${esc(rep.confidence)})${["Verified","Partially verified"].includes(rep.verdict)?` <button data-act="patch">Export patch</button>`:""}</div><div class="pmsg"></div>`:""}</div>`}
function opt_skip(){return ""}
function candHtml(c,i,fin,wait){const sim=c.simulation||{};return `<div class="cand ${fin?"fin":""}"><label style="margin:0">${wait?`<input type="checkbox" class="pick" value="${esc(c.id)}" ${fin?"checked":""}>`:""}
 <span class="badge">${esc(c.action)}</span> <b>${esc(c.summary)}</b></label><div class="sub">compatibility <b>${esc(c.compatibility)}</b> · score ${Math.round(c.score)} · target resolved in simulation: ${sim.target_resolved?"yes":"no"} · rollback: ${esc(c.rollback||"—")}</div>
 ${(c.compatibility_notes||[]).length?`<div class="sub">${esc(c.compatibility_notes.join(" · "))}</div>`:""}${c.diff?`<details><summary class="sub">diff ${esc((c.diff_sha256||"").slice(0,12))}</summary><pre class="mono">${esc(c.diff)}</pre></details>`:""}</div>`}
function wirePlan(id,p,i,box,opt){const el=$("#plan"+i);if(!el)return;const msg=el.querySelector(".pmsg");
 const need=()=>{if(!reviewer()){msg.innerHTML=fail("Enter your name in Reviewer (top right) first.");$("#reviewer").focus();return false}return true};
 const send=async body=>{try{const r=await api(`/runs/${id}/decisions`,{method:"POST",body:{plan:p.plan_key,plan_hash:p.plan_hash,reviewer:reviewer(),...body}});
  msg.innerHTML=`<div class="msg ok">${esc(body.decision)} recorded: rev ${r.revision}, hash ${esc(r.plan_hash.slice(0,12))}, status ${esc(r.status)}</div>`;setTimeout(()=>approvalsPanel(id,box,opt),900);if(opt.after)opt.after()}catch(e){msg.innerHTML=fail(e)}};
 el.querySelectorAll("[data-act]").forEach(b=>b.onclick=async()=>{const a=b.dataset.act;
  if(a==="approve"){if(!need())return;const picked=[...el.querySelectorAll(".pick:checked")].map(x=>x.value);if(!picked.length){msg.innerHTML=fail("Select at least one candidate.");return}
   const same=picked.length===p.finalists.length&&picked.every(x=>p.finalists.includes(x));
   if(!same&&!confirm("Approving a different set of candidates creates a new plan revision (new hash). Continue?"))return;
   send({decision:"approve",candidate:same?[]:picked,reason:"approved in the Guardian UI"})}
  if(a==="reject"){if(!need())return;const r=prompt("Reason for rejecting this plan?");if(r)send({decision:"reject",reason:r})}
  if(a==="accept"){el.querySelector(".ar").style.display="block"}
  if(a==="accept-go"){if(!need())return;const r=el.querySelector(".ar-r").value.trim(),e=el.querySelector(".ar-e").value;if(!r||!e){msg.innerHTML=fail("A reason and an expiry date are required.");return}send({decision:"accept_risk",reason:r,expires:e})}
  if(a==="patch"){if(!need())return;try{const r=await api(`/runs/${id}/patches`,{method:"POST",body:{plan:p.plan_key,reviewer:reviewer()}});msg.innerHTML=`<div class="msg ok">Patch exported (second approval recorded). Nothing was pushed.</div><pre class="mono">${esc(r.patch)}</pre>`}catch(e){msg.innerHTML=fail(e)}}})}

/* ------------------------------------------------------------------ heal agent */
async function healView(repo){const m=$("#main");let clones=[];try{clones=await api("/clones")}catch(e){m.innerHTML=fail(e);return}
 if(!repo){m.innerHTML=`<section class="card"><h2>Heal agent</h2><div class="sub">Applies human-approved, validated fixes to a cloned repository (branch guardian/heal-*), verifies each one in place with a rescan, rolls back and tries the next candidate on failure, and loops until the threshold is met. Pick a clone:</div>${clonesTable(clones)}</section>`;return}
 const c=clones.find(x=>x.name===repo)||{name:repo};
 m.innerHTML=`<section class="card"><div class="row" style="justify-content:space-between"><div><h1>Heal: ${esc(repo)}</h1><div class="sub mono">${esc(c.path||"")} · branch ${esc(c.branch||"")}</div></div><div id="hs"></div></div>
 <details ${c.heal?"":"open"}><summary><b>Settings</b></summary><div class="row"><label>Max iterations <input type="number" id="hi" value="3" min="1" max="10" style="width:64px"></label>
 <label>Retries per plan <input type="number" id="hr" value="2" min="0" max="5" style="width:64px"></label><label>Bands <input type="text" id="hb" value="P0,P1" style="width:90px"></label>
 <label>Stop at ≤ <input type="number" id="hm" value="0" min="0" style="width:64px"> remaining</label><label><input type="checkbox" id="hc"> count non-CVE signals</label>
 <label><input type="checkbox" id="hv"> apply only "Verified"</label><label>Sandbox <select id="hsb"><option value="none">none</option><option>docker</option><option>local</option></select></label>
 <label><input type="checkbox" id="hl" checked> LLM agents</label><label><input type="checkbox" id="ho"> offline</label><label><input type="checkbox" id="hf"> fixture snapshots</label></div></details>
 <div class="row" style="margin-top:10px"><button class="pri" id="hgo">Start / resume heal</button><button id="hskip">Continue without pending plans</button><span id="hmsg" class="sub"></span></div></section>
 <div id="happ"></div><div class="grid2"><section class="card"><h2>Live agent log</h2><div class="log" id="hlog"><span class="sub">Events appear here while the agent runs from this UI.</span></div></section>
 <section class="card"><h2>Fixes on the clone</h2><div id="hfix"></div></section></div>
 <section class="card"><h2>Iterations</h2><div id="hits"></div></section><section class="card"><h2>Full heal report</h2><iframe id="hrep" src="/heal/${encodeURIComponent(repo)}/report.html" title="Heal report" style="height:70vh"></iframe></section>`;
 const body=skip=>({repo,max_iterations:+$("#hi").value||3,max_retries:+$("#hr").value||0,bands:$("#hb").value.split(",").map(s=>s.trim()).filter(Boolean),
  max_remaining:+$("#hm").value||0,count_signals:$("#hc").checked,require_verified:$("#hv").checked,sandbox:$("#hsb").value,use_llm:$("#hl").checked,
  offline:$("#ho").checked,fixture_snapshots:$("#hf").checked,skip_pending:skip,reviewer:reviewer()||null});
 const start=async skip=>{$("#hmsg").textContent="";try{await api("/heal",{method:"POST",body:body(skip)});$("#hmsg").textContent="agent running…";
  $("#happ").innerHTML="";if(!timers.length)timers.push(setInterval(poll,3000));poll()}catch(e){$("#hmsg").innerHTML=fail(e)}};
 const FIELDS=["hi","hr","hb","hm","hc","hv","hsb","hl","ho","hf"],KEY="guardian.heal."+repo;
 try{const saved=JSON.parse(store(KEY)||"{}");FIELDS.forEach(f=>{const el=$("#"+f);if(f in saved){if(el.type==="checkbox")el.checked=saved[f];else el.value=saved[f]}})}catch(e){}
 const save=()=>store(KEY,JSON.stringify(Object.fromEntries(FIELDS.map(f=>{const el=$("#"+f);return [f,el.type==="checkbox"?el.checked:el.value]}))));
 FIELDS.forEach(f=>$("#"+f).addEventListener("change",save));
 $("#hgo").onclick=()=>{save();start(false)};$("#hskip").onclick=()=>{if(confirm("Skip the plans waiting in this iteration (not rejected; asked again next iteration) and continue?"))start(true)};
 let since=0,lastSig="";
 async function poll(){let s=null;try{s=await api(`/heal/${encodeURIComponent(repo)}`)}catch(e){
   const ev=await api(`/heal/${encodeURIComponent(repo)}/events`).catch(()=>({}));
   $("#hs").innerHTML=badge(ev.process==="running"?"running":"not started")+(ev.process==="running"?' <span class="sub">first scan in progress</span>':"");
   $("#hfix").innerHTML=`<div class="empty">No fixes yet.</div>`;if(ev.process==="running"&&!timers.length)timers.push(setInterval(poll,3000));return}
  const running=s.process==="running",elsewhere=!running&&s.status==="running";
  $("#hs").innerHTML=badge(running||elsewhere?"running":s.status)+` <span class="sub">${esc(running?"agent running from this UI":elsewhere?
   `running in another process (CLI) · iteration ${s.iterations.length}`:(s.stop_reason||""))}</span>`;
  $("#hgo").disabled=running||elsewhere;$("#hskip").disabled=running||elsewhere;if(!running)$("#hmsg").textContent="";
  if(elsewhere&&!timers.length)timers.push(setInterval(poll,5000));
  $("#hits").innerHTML=`<table><tr><th>#</th><th>Scan (opens the full run: findings, graph, SBOM, Day 2)</th><th>Remaining</th><th>Risk</th><th>Applied</th></tr>${s.iterations.map(i=>{const rid=i.run_dir?i.run_dir.split(/[\\/]/).pop():"";
   return `<tr><td>${i.n}</td><td>${rid?`<a href="#/run/${esc(rid)}/pipeline">${esc(rid)}</a> · <a href="#/detect/${esc(rid)}/findings">report</a> · <a href="#/detect/${esc(rid)}/graph">graph</a> · <a href="#/detect/${esc(rid)}/sbom">SBOM</a> · <a href="#/remediate/${esc(rid)}/approvals">approval</a>`:"—"}</td><td>${i.remaining??"—"}</td><td>${i.risk_score??"—"}</td><td class="mono sub">${esc((i.applied||[]).join(", "))}</td></tr>`}).join("")}</table>`;
  const fx=s.fixes||[];$("#hfix").innerHTML=fx.length?`<table>${fx.map(f=>`<tr><td>it${f.iteration}</td><td>${badge(f.status)}</td><td>${esc(f.summary)}<div class="sub mono">${(f.files||[]).map(esc).join("<br>")}</div><div class="sub">${esc(f.reason)}</div></td><td class="mono">${esc((f.commit||"").slice(0,10))}<div class="sub">${esc(f.approved_by||"")}</div></td></tr>`).join("")}</table>`:`<div class="empty">No fixes applied yet.</div>`;
  try{const ev=await api(`/heal/${encodeURIComponent(repo)}/events?since=${since}`);if(ev.events.length){if(since===0)$("#hlog").innerHTML="";since=ev.next;
   $("#hlog").innerHTML+=ev.events.map(e=>`<div>${esc(new Date((e.t||0)*1000).toLocaleTimeString())} ${esc(e.node)} <b>${esc(e.status)}</b> ${esc(e.message||"")}</div>`).join("");$("#hlog").scrollTop=1e9}}catch(e){}
  const sig=JSON.stringify([s.status,s.iterations.length,fx.length,s.journal.length]);if(sig!==lastSig){lastSig=sig;$("#hrep").src=$("#hrep").src;
   const cur=s.iterations[s.iterations.length-1];const rid=cur&&cur.run_dir?cur.run_dir.split(/[\\/]/).pop():null;
   if(rid&&!running&&s.status==="awaiting_approval"){$("#happ").innerHTML=`<section class="card"><h2>Pending approvals: iteration ${cur.n}</h2><div class="sub">Decide here, then press <b>Start / resume heal</b>; the agent validates, applies to the clone, verifies, and continues.</div><div id="hab"></div></section>`;
    approvalsPanel(rid,$("#hab"),{heal:true})}else if(running)$("#happ").innerHTML=""}
  if(running&&!timers.length){timers.push(setInterval(poll,3000))}if(!running&&!elsewhere&&timers.length){clearTimers()}}
 poll()}
/* ------------------------------------------------------------------ chaos engineering */
async function chaosView(id){const m=$("#main");if(id){m.innerHTML=`<section class="card"><div class="row" style="justify-content:space-between"><h2>Chaos scorecard ${esc(id)}</h2><a href="#/chaos">← all chaos runs</a></div>
 <iframe src="/chaos/${encodeURIComponent(id)}/report.html" title="Chaos scorecard"></iframe></section>`;return}
 let list=[],exps=[],clones=[];try{[list,exps,clones]=await Promise.all([api("/chaos"),api("/chaos/experiments"),api("/clones")])}catch(e){m.innerHTML=fail(e);return}
 m.innerHTML=`<section class="card"><h2>Chaos engineering</h2><div class="sub">Inject faults into Guardian itself (registry/OSV outages, tool crashes, corrupted lockfiles, a lying or prompt-injected LLM, hostile repo text…) on a throwaway copy, and check the steady state: the report is always written, complete, honest and leak-free.</div>
 <form id="cf" class="row" style="margin-top:10px"><label style="flex:1;min-width:260px">Local repository path<input type="text" id="ct" list="ccl" value="output/fixtures/guardian-fixture"></label>
 <datalist id="ccl">${clones.map(c=>`<option value="${esc(c.path)}">`).join("")}</datalist><label>Chaos monkey runs <input type="number" id="cm" value="0" min="0" max="20" style="width:70px"></label>
 <label>Seed <input type="number" id="cs" style="width:90px"></label><label><input type="checkbox" id="co"> allow network</label><button class="pri">Run experiments</button></form><div id="cmsg"></div>
 <details style="margin-top:8px"><summary>${exps.length} experiments</summary><table>${exps.map(e=>`<tr><td class="mono">${esc(e.id)}</td><td>${esc(e.category)}</td><td>${esc(e.name)}</td></tr>`).join("")}</table></details></section>
 <section class="card"><h2>Scorecards</h2>${list.length?`<table><tr><th>Run</th><th>Target</th><th>Resilience</th><th></th></tr>${list.map(c=>`<tr class="click" onclick="${c.status==="done"?`location.hash='#/chaos/${esc(c.id)}'`:""}">
 <td class="mono">${esc(c.id)}</td><td class="sub">${esc(c.target||"")}</td><td>${c.status==="done"?`<b>${esc(c.resilience_score)}%</b> <span class="sub">${esc(c.passed)}/${esc(c.experiments)}</span>`:badge(c.status)}</td><td>${c.status==="done"?"open →":""}</td></tr>`).join("")}</table>`:`<div class="empty">No chaos runs yet.</div>`}</section>`;
 $("#cf").onsubmit=async ev=>{ev.preventDefault();try{const r=await api("/chaos",{method:"POST",body:{target:$("#ct").value.trim(),monkey:+$("#cm").value||0,seed:$("#cs").value?+$("#cs").value:null,online:$("#co").checked}});
  $("#cmsg").innerHTML=`<div class="msg">Running… <span id="cprog"></span></div>`;const t=setInterval(async()=>{const j=await api(`/chaos/jobs/${r.job}`).catch(()=>null);if(!j)return;
   $("#cprog").textContent=`${j.results.length} experiment(s) done: `+j.results.map(x=>(x.passed?"✓ ":"✗ ")+x.id).join(", ");
   if(j.status!=="running"){clearInterval(t);if(j.report)location.hash=`#/chaos/${j.report}`;else $("#cmsg").innerHTML=fail(j.status)}},2000);timers.push(t)}catch(e){$("#cmsg").innerHTML=fail(e)}}}
route();
</script></body></html>"""
