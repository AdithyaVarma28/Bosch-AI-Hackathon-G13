"""Self-contained interactive report page (graph explorer + what-if chaos simulator + findings + evidence)."""

HTML = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Guardian report: __TITLE__</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.28.1/cytoscape.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/dagre/0.8.5/dagre.min.js"></script>
<style>
:root{--bg:#f5f6f8;--card:#fff;--fg:#151a23;--mut:#5d6677;--line:#e2e5ea;--soft:#f0f2f5;--acc:#2563eb;
--p0:#d92d20;--p1:#e8710a;--p2:#e0a100;--p3:#98a2b3;--ok:#067647;--shadow:0 1px 2px rgba(16,24,40,.06),0 1px 3px rgba(16,24,40,.08)}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#0d1117;--card:#151b23;--fg:#e6edf3;--mut:#8d96a3;--line:#262d37;--soft:#1b222c;--acc:#4f8cff;--shadow:none}}
:root[data-theme="dark"]{--bg:#0d1117;--card:#151b23;--fg:#e6edf3;--mut:#8d96a3;--line:#262d37;--soft:#1b222c;--acc:#4f8cff;--shadow:none}
*{box-sizing:border-box}body{margin:0;font:14px/1.45 Inter,system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--fg)}
header{padding:16px 24px;border-bottom:1px solid var(--line);background:var(--card);display:flex;gap:16px;align-items:center;flex-wrap:wrap}
h1{margin:0;font-size:19px;font-weight:650}h2{font-size:15px;margin:0 0 12px;font-weight:650}h3{font-size:13px;margin:14px 0 6px;color:var(--mut);text-transform:uppercase;letter-spacing:.04em}
.sub{color:var(--mut)}main{padding:16px 24px;display:grid;gap:16px;max-width:1600px;margin:0 auto}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px;box-shadow:var(--shadow);min-width:0}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px}.kpi{background:var(--soft);border-radius:10px;padding:10px 12px}.kpi b{display:block;font-size:21px}
button,.chip,select,input[type=search]{font:inherit;font-size:12.5px;border:1px solid var(--line);background:var(--card);color:var(--fg);border-radius:8px;padding:5px 10px}
button{cursor:pointer}button:hover{border-color:var(--acc)}button.on,.chip.on{background:var(--acc);border-color:var(--acc);color:#fff}
.chip{border-radius:999px;cursor:pointer;display:inline-flex;align-items:center;gap:6px}.dot{width:9px;height:9px;border-radius:50%;display:inline-block}
.bar{display:flex;gap:6px;flex-wrap:wrap;align-items:center;margin-bottom:8px}.bar .sep{width:1px;height:22px;background:var(--line);margin:0 4px}
.tabs button{border-radius:8px}
.gwrap{display:grid;grid-template-columns:minmax(0,1fr) 360px;gap:12px}#cy{height:680px;border:1px solid var(--line);border-radius:10px;background:
radial-gradient(circle at 1px 1px,var(--line) 1px,transparent 0) 0 0/22px 22px,var(--soft);position:relative}
#side{border:1px solid var(--line);border-radius:10px;height:680px;display:flex;flex-direction:column;overflow:hidden}
#side nav{display:flex;border-bottom:1px solid var(--line)}#side nav button{flex:1;border:0;border-radius:0;padding:9px;background:transparent}
#side nav button.on{background:var(--soft);color:var(--fg);box-shadow:inset 0 -2px 0 var(--acc)}#sidebody{padding:12px 14px;overflow:auto;flex:1}
.badge{font-weight:700;border-radius:6px;padding:1px 7px;color:#fff;font-size:11.5px;display:inline-block}
.P0{background:var(--p0)}.P1{background:var(--p1)}.P2{background:var(--p2);color:#111}.P3{background:var(--p3)}.Unprioritized{background:#888}.none{background:var(--ok)}
.kv{display:grid;grid-template-columns:110px 1fr;gap:3px 10px;font-size:12.5px}.kv div:nth-child(odd){color:var(--mut)}.kv div{word-break:break-all}
.list{margin:4px 0;padding-left:16px;font-size:12.5px}.list li{margin:2px 0}.link{color:var(--acc);cursor:pointer}
.impact{display:grid;grid-template-columns:repeat(3,1fr);gap:6px;margin:8px 0}.impact div{background:var(--soft);border-radius:8px;padding:6px 8px;font-size:12px}.impact b{display:block;font-size:18px}
#tip{position:fixed;pointer-events:none;background:var(--card);border:1px solid var(--line);border-radius:8px;padding:6px 9px;font-size:12px;box-shadow:var(--shadow);display:none;z-index:9;max-width:320px}
table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid var(--line);padding:7px 8px;text-align:left;vertical-align:top}th{color:var(--mut);font-weight:600;font-size:12px}
.sig{font-size:11px;border:1px solid var(--line);border-radius:4px;padding:0 5px;margin-left:4px;color:var(--mut)}tr.f{cursor:pointer}tr.f:hover{background:var(--soft)}
pre{white-space:pre-wrap;background:var(--soft);padding:8px;border-radius:6px;font-size:12px;max-height:260px;overflow:auto}
.claim{margin:6px 0;padding:6px 8px;border-left:3px solid var(--acc);background:var(--soft);border-radius:0 6px 6px 0}.t{font-size:10.5px;font-weight:700;text-transform:uppercase;margin-right:6px}
.ev{color:var(--acc);cursor:pointer;text-decoration:underline;font-size:12px;margin-right:6px}.warn{color:var(--p1)}
.legend{display:grid;grid-template-columns:auto 1fr;gap:6px 10px;font-size:12.5px;align-items:center}.sw{width:22px;height:14px;border-radius:4px;border:2px solid transparent}
.overlay{position:absolute;left:10px;bottom:10px;display:flex;gap:6px;z-index:2}.overlay button{background:var(--card)}
.count{position:absolute;right:10px;top:10px;z-index:2;font-size:12px;color:var(--mut);background:var(--card);border:1px solid var(--line);border-radius:6px;padding:2px 8px}
header{position:sticky;top:0;z-index:20}.topnav{display:flex;gap:4px;margin-left:auto;background:var(--soft);padding:4px;border-radius:10px}
.topnav button{border:0;background:transparent;padding:7px 14px;font-size:13.5px;font-weight:600;color:var(--mut)}.topnav button.on{background:var(--card);color:var(--fg);box-shadow:var(--shadow)}
.topnav .n{font-weight:500;font-size:11.5px;color:var(--mut);margin-left:4px}
.page{display:none;gap:16px}.page.on{display:grid}
.sbgrid{display:grid;grid-template-columns:minmax(0,1fr) 380px;gap:12px}.sbtable{max-height:640px;overflow:auto;border:1px solid var(--line);border-radius:10px}
.sbtable table th{position:sticky;top:0;background:var(--card);cursor:pointer;user-select:none;z-index:1}.sbtable tr.c{cursor:pointer}.sbtable tr.c:hover,.sbtable tr.sel{background:var(--soft)}
.mono{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:12px;word-break:break-all}.tag{font-size:11px;border-radius:4px;padding:0 6px;border:1px solid var(--line);white-space:nowrap}
#sbside{border:1px solid var(--line);border-radius:10px;padding:12px 14px;max-height:640px;overflow:auto}
@media (max-width:1000px){.sbgrid{grid-template-columns:1fr}.topnav{margin-left:0;width:100%}.topnav button{flex:1}}
@media (max-width:1000px){.gwrap{grid-template-columns:1fr}#side{height:auto;max-height:520px}#cy{height:520px}main,header{padding:12px 16px}}
</style></head><body>
<header><div><h1>Guardian: <span id="repo"></span></h1><div class="sub" id="meta"></div></div>
<nav class="topnav" id="topnav"><button data-p="report" class="on">Report<span class="n" id="n-report"></span></button>
<button data-p="graph">Dependency graph<span class="n" id="n-graph"></span></button><button data-p="sbom">SBOM<span class="n" id="n-sbom"></span></button>
<button data-p="remediation" id="nav-rem" hidden>Remediation<span class="n" id="n-rem"></span></button></nav></header>
<main>
<div class="page on" data-page="report">
<section class="card"><h2>What is in the application</h2><div id="dossier"></div><div class="kpis" id="kpis" style="margin-top:12px"></div></section>
</div>

<div class="page" data-page="remediation">
<section class="card"><h2>From detection to verified remediation</h2><div class="kpis" id="remkpis"></div>
<p class="sub" id="remnote"></p></section>
<section class="card" style="padding:0;overflow:hidden"><iframe id="remframe" title="Remediation" style="width:100%;height:82vh;border:0"></iframe></section>
</div>

<div class="page" data-page="sbom">
<section class="card"><h2>Software Bill of Materials <span class="sub" id="sbfmt"></span></h2>
 <div class="kpis" id="sbkpis"></div>
 <div class="bar" style="margin-top:12px"><input type="search" id="sbq" placeholder="Filter by name, purl, license…" style="min-width:240px">
  <select id="sbeco"><option value="">All ecosystems</option></select>
  <select id="sbscope"><option value="">All scopes</option><option>prod</option><option>dev</option><option>optional</option><option>build</option><option>unknown</option></select>
  <select id="sbrel"><option value="">Direct + transitive</option><option value="direct">Direct only</option><option value="transitive">Transitive only</option></select>
  <button id="sbvuln">With findings only</button><span class="sep"></span>
  <button id="sbdl">Download CycloneDX JSON</button><button id="sbcsv">Download CSV</button></div>
 <div class="sbgrid"><div class="sbtable"><table><thead><tr id="sbhead"></tr></thead><tbody id="sbrows"></tbody></table></div>
  <aside id="sbside"><p class="sub">Select a component to see its CycloneDX entry, origin, hashes, dependencies and findings.</p></aside></div>
 <details style="margin-top:12px"><summary class="sub">How this SBOM was built (cross-check, tools, notes)</summary><div id="sbnotes"></div></details>
</section>
<section class="card"><div class="bar" style="justify-content:space-between"><h2 style="margin:0">CycloneDX JSON <span class="sub" id="sbsize"></span></h2>
 <span><button id="sbcopy">Copy</button> <button id="sbdl2">Download</button></span></div>
 <pre id="sbjson" class="mono" style="max-height:560px;margin:0"></pre></section></div>

<div class="page" data-page="graph">
<section class="card"><h2>Dependency graph explorer</h2>
 <div class="bar tabs" id="views"></div>
 <div class="bar">
  <input type="search" id="q" placeholder="Search package, file, route…" style="min-width:220px">
  <span class="sep"></span><span id="ecos"></span>
  <span class="sep"></span><select id="scope"><option value="all">All scopes</option><option value="prod">Runtime only</option><option value="dev">Dev/test only</option></select>
  <button id="risky">Risky only</button>
  <span id="depthbox"><span class="sep"></span><label class="sub">Depth <input type="range" id="depth" min="1" max="8" value="8" style="vertical-align:middle"> <span id="depthv"></span></label></span>
 </div>
 <div class="gwrap">
  <div style="position:relative;min-width:0"><div id="cy"></div><div class="count" id="cnt"></div><div class="overlay"><button id="fit">Fit</button><button id="reset">Clear</button><button id="png">PNG</button></div></div>
  <aside id="side"><nav><button data-t="details" class="on">Details</button><button data-t="whatif">What-if (chaos)</button><button data-t="legend">Legend</button></nav><div id="sidebody"></div></aside>
 </div>
</section>
<section class="card"><h2>Execution paths (route &rarr; code &rarr; sink)</h2><table><thead><tr><th>Route</th><th>Input</th><th>Call chain</th><th>Sink</th><th>Where</th></tr></thead><tbody id="paths"></tbody></table></section>
<section class="card"><h2>Declared vs resolved vs imported</h2><table><thead><tr><th>Package</th><th>Declared</th><th>Resolved</th><th>Imported</th><th>Status</th></tr></thead><tbody id="disc"></tbody></table></section>
</div>

<div class="page on" data-page="report">
<section class="card"><h2>What appears risky</h2><div class="bar" id="bands"></div><table><thead><tr><th>Band</th><th>Finding</th><th>Class</th><th>Locator</th><th id="d2h" hidden>Remediation</th></tr></thead><tbody id="ftable"></tbody></table>
<div class="sub" id="thr" style="margin-top:8px"></div></section>
<section class="card" id="fdetail" hidden></section>
<section class="card"><h2>What changed</h2><table><thead><tr><th>Commit</th><th>Date</th><th>Message</th><th>Added</th><th>Removed</th><th>Changed</th></tr></thead><tbody id="hist"></tbody></table></section>
<section class="card"><h2>Coverage: what Guardian could and could not see</h2><div id="cov"></div></section>
</div>
</main><div id="tip"></div>
<script>
const R=__REPORT__, V=__VIZ__;
const esc=s=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const $=id=>document.getElementById(id);
const css=v=>getComputedStyle(document.documentElement).getPropertyValue(v).trim();
$("repo").textContent=R.repo.name;
$("meta").textContent=`commit ${(R.repo.commit||"n/a").slice(0,12)} · run ${R.run_id} · ${R.generated_at} · LLM: ${R.coverage.llm}`;
const D=R.dossier||{};
function claimHtml(c){return `<div class="claim"><span class="t">${esc(c.type)}</span>${esc(c.text)} <span class="sub">[${esc(c.verifier_status)}${c.confidence?", "+esc(c.confidence):""}]</span><br>${(c.evidence_ids||[]).map(e=>`<span class="ev" data-ev="${esc(e)}">${esc(e)}</span>`).join("")}</div>`}
$("dossier").innerHTML=`<p><b>${esc(D.app_type)}</b> · exposure <b>${esc(D.exposure)}</b> · by ${esc(D.generated_by)}</p><p>${esc(D.summary)}</p>`+
 (D.claims||[]).map(claimHtml).join("")+`<details><summary class="sub">Limits</summary><ul>${(D.limits||[]).map(l=>`<li>${esc(l)}</li>`).join("")}</ul></details>`;
const S=R.summary, SBR=(R.sbom.report||{});
$("kpis").innerHTML=[["Components",S.components],["Direct",S.direct],["Transitive",S.transitive],["Vulnerabilities",S.vulnerabilities],
 ["Supply-chain signals",S.supply_chain_signals],["Container/CI",S.container_ci],["Secrets",S.secrets],["SBOM confidence",SBR.confidence||"?"]]
 .map(([k,v])=>`<div class="kpi"><span class="sub">${k}</span><b>${esc(v)}</b></div>`).join("");
document.addEventListener("click",e=>{const id=e.target.dataset&&e.target.dataset.ev;if(!id)return;const ev=R.evidence[id];
 const box=e.target.closest(".claim")||e.target.parentElement;let p=box.querySelector("pre[data-for='"+id+"']");if(p){p.remove();return}
 p=document.createElement("pre");p.dataset.for=id;p.textContent=ev?`${ev.kind.toUpperCase()} · ${ev.source} · ${ev.locator}\nsha256 ${ev.sha256}\n\n${ev.excerpt}`:"evidence not embedded in report";box.appendChild(p)});

/* ------------------------------------------------------------------ graph explorer */
const FIND=Object.fromEntries(R.findings.map(f=>[f.id,f]));
const NODES=Object.fromEntries(V.nodes.map(n=>[n.id,n]));
const ECO_COL={npm:"#cb3837",pypi:"#3776ab",maven:"#c71a36",golang:"#00add8",cargo:"#b7410e",gem:"#9b111e",composer:"#8892bf",nuget:"#6c4bd0",other:"#7a8494"};
const TYPE_COL={project:"#111827",source_module:"#0f766e",function:"#14b8a6",model:"#a16207",route:"#7c3aed",input:"#ea580c",db_table:"#a16207",secret:"#be123c",
 external_service:"#db2777",sensitive_call:"#dc2626",dockerfile:"#0891b2",image:"#0e7490",workflow:"#475467",action:"#667085",compose_service:"#0284c7"};
const SHAPE={project:"round-hexagon",artifact:"round-rectangle",package:"round-rectangle",source_module:"round-tag",function:"ellipse",model:"barrel",route:"round-pentagon",
 input:"round-triangle",db_table:"barrel",secret:"round-diamond",external_service:"rhomboid",sensitive_call:"round-octagon",dockerfile:"cut-rectangle",image:"cut-rectangle",
 workflow:"round-rectangle",action:"round-octagon",compose_service:"round-rectangle"};
const RISK_COL={P0:"#d92d20",P1:"#e8710a",P2:"#f2c037",P3:"#d0d5dd",Unprioritized:"#d0d5dd"};
const REL_COL={DEPENDS_ON:"#8d96a3",DIRECT:"#4b5563",DECLARES:"#6b7280",IMPORTS:"#2563eb",USES:"#2563eb",CALLS:"#14b8a6",HANDLED_BY:"#7c3aed",INPUT_TO:"#ea580c",
 READS_ENV:"#be123c",WRITES_DB:"#a16207",READS_DB:"#a16207",RAW_SQL:"#a16207",CONTACTS:"#db2777",SENSITIVE_CALL:"#dc2626",BUILT_BY:"#0891b2",BASED_ON:"#0e7490",
 CI:"#475467",USES_ACTION:"#667085",RUNS_SERVICE:"#0284c7",MAPS_TO:"#a16207",DEFINES:"#94a3b8",BREAKS_BUILD:"#d92d20",HAS_ARTIFACT:"#8d96a3"};
const VIEWS={
 tree:{label:"Dependency tree",types:["project","artifact"],rels:["DEPENDS_ON","DIRECT"],layout:"dagre",depth:true,
  hint:"Project → direct dependencies → transitive dependencies (resolved layer)."},
 usage:{label:"Code → packages",types:["source_module","package"],rels:["IMPORTS"],layout:"dagre",
  hint:"Which source files statically import which packages (usage layer)."},
 paths:{label:"Execution paths",types:["route","input","function","db_table","secret","external_service","sensitive_call","model"],
  rels:["HANDLED_BY","INPUT_TO","CALLS","READS_ENV","WRITES_DB","READS_DB","RAW_SQL","CONTACTS","SENSITIVE_CALL","MAPS_TO"],layout:"dagre",fromRoutes:true,
  hint:"HTTP routes → handlers → called functions → secrets, tables, services and risky calls."},
 infra:{label:"Build & CI",types:["project","dockerfile","image","workflow","action","compose_service"],rels:["BUILT_BY","BASED_ON","CI","USES_ACTION","RUNS_SERVICE"],layout:"dagre",
  hint:"Container images, compose services and CI workflows / actions."},
 all:{label:"Everything",types:null,rels:null,layout:"cose",hint:"All layers in one graph. Use search or a node click to focus."},
 blast:{label:"Blast radius",types:null,rels:null,layout:"dagre",hidden:true,hint:"Nodes reached by the simulated failure."}
};
const st={view:"tree",ecos:new Set(V.ecosystems),scope:"all",risky:false,depth:8,blast:null,sel:null,tab:"details"};
const maxDepth=Math.max(1,...V.nodes.filter(n=>n.type==="artifact"&&n.depth!=null).map(n=>n.depth+1));
$("depth").max=Math.max(1,maxDepth);st.depth=V.nodes.filter(n=>n.type==="artifact").length>250?2:maxDepth;$("depth").value=st.depth;
$("views").innerHTML=Object.entries(VIEWS).filter(([k,v])=>!v.hidden).map(([k,v])=>`<button data-v="${k}" class="${k===st.view?"on":""}">${v.label}</button>`).join("")+
 `<span class="sub" id="vhint" style="margin-left:6px"></span>`;
$("ecos").innerHTML=V.ecosystems.map(e=>`<span class="chip on" data-e="${e}"><span class="dot" style="background:${ECO_COL[e]||"#888"}"></span>${e}</span>`).join(" ");

function label(n){if(n.type==="artifact"){const nm=String(n.label).split("@");return nm.slice(0,-1).join("@")+"\n"+(n.version||"?")}
 if(n.type==="function")return String(n.label).split(".").pop();return String(n.label).length>38?"…"+String(n.label).slice(-36):String(n.label)}
function keep(n){if(n.ecosystem&&["artifact","package"].includes(n.type)&&!st.ecos.has(n.ecosystem))return false;
 if(st.scope!=="all"&&n.type==="artifact"){if(st.scope==="prod"&&n.scope!=="prod")return false;if(st.scope==="dev"&&n.scope==="prod")return false}
 return true}
function viewElements(){
 const v=VIEWS[st.view];let ids=new Set(),edges=[];
 if(st.view==="blast"&&st.blast){ids=new Set(st.blast.nodes);
  /* orient every edge in the direction the failure spreads: package -> dependents -> code -> routes / secrets */
  const REV={DEPENDS_ON:1,IMPORTS:1,USES:1,CALLS:1,HANDLED_BY:1,HAS_ARTIFACT:1},FWD={DEFINES:1,READS_ENV:1,WRITES_DB:1,READS_DB:1,RAW_SQL:1,CONTACTS:1,SENSITIVE_CALL:1};
  V.edges.forEach(e=>{if(!ids.has(e.s)||!ids.has(e.t))return;if(REV[e.rel])edges.push({s:e.t,t:e.s,rel:e.rel,impact:1});else if(FWD[e.rel])edges.push({s:e.s,t:e.t,rel:e.rel,impact:1})});
  const proj=V.nodes.find(n=>n.type==="project");if(st.blast.direct.length){ids.add(proj.id);st.blast.direct.forEach(d=>edges.push({s:d,t:proj.id,rel:"BREAKS_BUILD",impact:1}))}}
 else{
  V.nodes.forEach(n=>{if((!v.types||v.types.includes(n.type))&&keep(n))ids.add(n.id)});
  if(st.view==="tree"){ids.forEach(i=>{const n=NODES[i];if(n.type==="artifact"&&(n.depth==null?st.depth<maxDepth:n.depth>=st.depth))ids.delete(i)})}
  V.edges.forEach(e=>{if(ids.has(e.s)&&ids.has(e.t)&&(!v.rels||v.rels.includes(e.rel)))edges.push(e)});
  if(st.view==="tree"){const proj=V.nodes.find(n=>n.type==="project");V.nodes.forEach(n=>{if(n.type==="artifact"&&n.direct&&ids.has(n.id))edges.push({s:proj.id,t:n.id,rel:"DIRECT"})})}
  if(st.view==="usage"){const used=new Set();edges.forEach(e=>{used.add(e.s);used.add(e.t)});ids.forEach(i=>{if(!used.has(i))ids.delete(i)})}
  if(v.fromRoutes){const adj={};edges.forEach(e=>{(adj[e.s]=adj[e.s]||[]).push(e.t);if(e.rel==="INPUT_TO")(adj[e.t]=adj[e.t]||[]).push(e.s)});
   const seen=new Set(),stack=[...ids].filter(i=>NODES[i].type==="route");while(stack.length){const x=stack.pop();if(seen.has(x))continue;seen.add(x);(adj[x]||[]).forEach(y=>stack.push(y))}
   ids=seen;edges=edges.filter(e=>ids.has(e.s)&&ids.has(e.t))}
  if(st.risky){const hot=new Set([...ids].filter(i=>NODES[i].risk&&NODES[i].risk!=="P3"));const keepIds=new Set(hot);
   const radj={};edges.forEach(e=>{(radj[e.t]=radj[e.t]||[]).push(e.s)});const stack=[...hot];while(stack.length){const x=stack.pop();(radj[x]||[]).forEach(y=>{if(!keepIds.has(y)){keepIds.add(y);stack.push(y)}})}
   ids=keepIds;edges=edges.filter(e=>ids.has(e.s)&&ids.has(e.t))}
 }
 const els=[];ids.forEach(i=>{const n=NODES[i];if(!n)return;const lb=label(n);const lines=lb.split("\n");const w=Math.max(...lines.map(l=>l.length));
  const big=n.type==="project";els.push({data:{id:i,lb,type:n.type,risk:n.risk||"",eco:n.ecosystem||"",direct:n.direct?1:0,
   w:big?150:["function","input","secret","sensitive_call"].includes(n.type)?Math.min(150,20+w*6.3):Math.min(230,26+w*6.6),
   h:big?54:lines.length>1?40:30,col:n.risk?RISK_COL[n.risk]:(TYPE_COL[n.type]||css("--card")),
   bcol:ECO_COL[n.ecosystem]||TYPE_COL[n.type]||"#9aa3b2",tcol:n.risk==="P0"||n.risk==="P1"?"#fff":(n.risk?"#111":(["artifact","package"].includes(n.type)?css("--fg"):"#fff")),
   shape:SHAPE[n.type]||"ellipse",fill:n.risk||!["artifact","package"].includes(n.type)?1:0}})});
 const seenE=new Set();edges.forEach((e,k)=>{const key=e.s+"|"+e.t+"|"+e.rel;if(seenE.has(key))return;seenE.add(key);
  els.push({data:{id:"e"+k,source:e.s,target:e.t,rel:e.rel,col:REL_COL[e.rel]||"#9aa3b2",ls:e.rel==="DECLARES"?"dashed":["IMPORTS","USES"].includes(e.rel)?"dotted":"solid"}})});
 return els}
let cy=null;
function styleSheet(){return[
 {selector:"node",style:{shape:"data(shape)",width:"data(w)",height:"data(h)","background-color":"data(col)","background-opacity":1,"border-width":2,"border-color":"data(bcol)",
  label:"data(lb)","text-wrap":"wrap","text-valign":"center","text-halign":"center","font-size":10.5,"font-weight":500,color:"data(tcol)","text-max-width":220,"min-zoomed-font-size":6}},
 {selector:"node[fill = 0]",style:{"background-color":css("--card")}},
 {selector:"node[direct = 1]",style:{"border-width":3.5}},
 {selector:"node[type = 'project']",style:{"font-size":13,"font-weight":700,color:"#fff","background-color":"#111827","border-color":"#111827"}},
 {selector:"node[type = 'function'],node[type = 'input'],node[type = 'secret'],node[type = 'sensitive_call']",style:{"text-valign":"bottom","text-margin-y":4,color:css("--fg"),height:22,"font-size":9.5}},
 {selector:"edge",style:{width:1.4,"line-color":"data(col)","target-arrow-color":"data(col)","target-arrow-shape":"triangle","arrow-scale":.75,
  "curve-style":"bezier","line-style":"data(ls)",opacity:.85}},
 {selector:"edge.taxi",style:{"curve-style":"taxi","taxi-direction":"rightward","taxi-turn":"50%"}},
 {selector:".dim",style:{opacity:.12}},
 {selector:"node.hl",style:{"border-width":4,"border-color":css("--acc"),"z-index":10}},
 {selector:"edge.hl",style:{width:3,opacity:1,"z-index":9}},
 {selector:"node.boom",style:{"overlay-color":"#d92d20","overlay-opacity":.22,"overlay-padding":8,"border-color":"#ff4d4f","border-width":4,"border-style":"solid"}},
 {selector:"node.origin",style:{"overlay-color":"#d92d20","overlay-opacity":.45,"overlay-padding":12,"border-width":6,"border-style":"double"}},
 {selector:"edge[rel = 'BREAKS_BUILD']",style:{"line-style":"dashed"}},
 {selector:"edge.boom",style:{"line-color":"#d92d20","target-arrow-color":"#d92d20",width:2.6,opacity:1}},
 {selector:":selected",style:{"border-color":css("--acc"),"border-width":4}}]}
function draw(){
 if(!window.cytoscape){$("cy").innerHTML='<p class="sub" style="padding:14px">The graph library could not load (offline). The full graph is in graph.json.</p>';return}
 const v=VIEWS[st.view];$("vhint").textContent=v.hint;$("depthbox").style.display=v.depth?"":"none";$("depthv").textContent=st.depth>=maxDepth?"all":st.depth;
 const els=viewElements();
 if(cy)cy.destroy();
 cy=cytoscape({container:$("cy"),elements:els,style:styleSheet(),wheelSensitivity:.25,minZoom:.05,maxZoom:3});
 const n=cy.nodes().length;$("cnt").textContent=`${n} nodes · ${cy.edges().length} edges`;
 let layout={name:"cose",animate:false,nodeRepulsion:12000,idealEdgeLength:90,nodeOverlap:20,gravity:.25,numIter:1200,padding:30};
 const useDagre=v.layout==="dagre"||n>220;   /* force-directed layouts stall on big graphs: use layered layout */
 if(useDagre&&window.dagre&&dagreLayout(st.view==="tree"?120:95)){if(n<=400)cy.edges().addClass("taxi")}
 else if(v.layout==="cose"){layout.numIter=Math.max(300,Math.min(1200,Math.round(120000/Math.max(1,n))));try{cy.layout(layout).run()}catch(e){cy.layout({name:"concentric",padding:24}).run()}}
 else{try{cy.layout(v.layout==="dagre"?{name:"breadthfirst",directed:true,spacingFactor:1.1,padding:24}:layout).run()}catch(e){cy.layout({name:"grid"}).run()}}
 if(n>0)cy.fit(undefined,30);
 cy.on("tap","node",e=>select(e.target.id()));cy.on("tap",e=>{if(e.target===cy)clearSel()});
 cy.on("mouseover","node",e=>{const d=NODES[e.target.id()];const t=$("tip");t.style.display="block";
  t.innerHTML=`<b>${esc(d.label)}</b><br><span class="sub">${esc(d.type)}${d.ecosystem?" · "+d.ecosystem:""}${d.scope?" · "+d.scope:""}</span>${d.risk?`<br><span class="badge ${d.risk}">${d.risk}</span> ${(d.findings||[]).length} finding(s)`:""}`});
 cy.on("mousemove",e=>{const t=$("tip");t.style.left=(e.originalEvent.clientX+14)+"px";t.style.top=(e.originalEvent.clientY+14)+"px"});
 cy.on("mouseout","node",()=>{$("tip").style.display="none"});
 if(st.blast)markBlast();
 if(st.sel&&cy.getElementById(st.sel).length)select(st.sel,false);
}
function dagreLayout(ranksep){/* layered left-to-right layout computed with dagre, applied as preset positions */
 try{const g=new dagre.graphlib.Graph({multigraph:true});g.setGraph({rankdir:"LR",nodesep:14,ranksep,edgesep:8,ranker:"network-simplex",marginx:20,marginy:20});
  g.setDefaultEdgeLabel(()=>({}));cy.nodes().forEach(n=>g.setNode(n.id(),{width:n.data("w"),height:n.data("h")}));
  cy.edges().forEach(e=>{if(e.source().id()!==e.target().id())g.setEdge(e.source().id(),e.target().id(),{},e.id())});
  dagre.layout(g);cy.nodes().positions(n=>{const p=g.node(n.id());return{x:p.x,y:p.y}});return true}catch(e){console.warn("dagre layout failed",e);return false}}
function clearSel(){st.sel=null;if(cy)cy.elements().removeClass("dim hl");if(st.tab==="details")side()}
function select(id,center=true){st.sel=id;if(!cy)return;const node=cy.getElementById(id);if(!node.length){side();return}
 cy.elements().removeClass("hl").addClass("dim");
 const up=node.predecessors(),down=node.successors().filter(x=>st.view!=="tree"||true);
 const keep=node.union(up).union(st.view==="tree"?down.slice(0,400):node.neighborhood());keep.removeClass("dim").addClass("hl");
 if(center)cy.animate({center:{eles:node},zoom:Math.max(cy.zoom(),.9)},{duration:300});
 st.tab="details";tabs();side()}
function pathsToRoot(id){const back={};V.edges.forEach(e=>{if(e.rel==="DEPENDS_ON")(back[e.t]=back[e.t]||[]).push(e.s)});
 const out=[];const walk=(x,p,depth)=>{if(out.length>=5||depth>12)return;const n=NODES[x];if(n&&n.direct){out.push([x,...p]);return}(back[x]||[]).forEach(y=>{if(!p.includes(y))walk(y,[x,...p],depth+1)})};
 walk(id,[],0);return out.map(p=>p.length&&p[0]===p[1]?p.slice(1):p)}
function nodeDetails(id){const n=NODES[id];if(!n)return'<p class="sub">Click a node to see details.</p>';
 const kv=[["Type",n.type],["Ecosystem",n.ecosystem],["Version",n.version],["Scope",n.scope],["Relation",n.type==="artifact"?(n.direct?"direct":"transitive"):null],
  ["Depth",n.depth],["Fan-in",n.fan_in],["Fan-out",n.fan_out],["Registry",n.registry],["Resolved",n.resolved_url],["Source repo",n.source_repo],
  ["Seen by",(n.seen_by||[]).join(", ")],["Install script",n.has_install_script?"yes":null],["Language",n.language],["Framework",n.framework],
  ["Tag",n.tag],["Digest",n.digest],["Pinned to SHA",n.pinned_to_sha===undefined?null:String(n.pinned_to_sha)],["Category",n.category]].filter(([k,v])=>v!==undefined&&v!==null&&v!=="");
 let h=`<div style="display:flex;gap:8px;align-items:center;margin-bottom:8px"><span class="badge ${n.risk||"none"}">${n.risk||"no finding"}</span><b style="word-break:break-all">${esc(n.label)}</b></div>`;
 h+=`<div class="kv">${kv.map(([k,v])=>`<div>${k}</div><div>${esc(v)}</div>`).join("")}</div>`;
 if((n.findings||[]).length)h+=`<h3>Findings (${n.findings.length})</h3><ul class="list">${n.findings.map(f=>FIND[f]?`<li><span class="badge ${FIND[f].band}">${FIND[f].band}</span> <span class="link" data-f="${f}">${esc(FIND[f].title)}</span></li>`:"").join("")}</ul>`;
 if(n.type==="artifact"){const ps=pathsToRoot(id);if(ps.length&&ps[0].length>1)h+=`<h3>How it gets in</h3><ul class="list">${ps.map(p=>`<li>${p.map(x=>esc((NODES[x]||{}).label||x)).join(" → ")}</li>`).join("")}</ul>`;
  const b=V.blast[id];if(b)h+=`<h3>Used by code</h3>${b.files.length?`<ul class="list">${b.files.slice(0,12).map(f=>`<li>${esc(f.replace("file:",""))}</li>`).join("")}</ul>`:'<p class="sub">No static import found.</p>'}`;
  h+=`<p><button id="simbtn">Simulate compromise of this package</button></p>`}
 const ins=V.edges.filter(e=>e.t===id&&e.rel!=="CONTAINS").slice(0,15),outs=V.edges.filter(e=>e.s===id&&e.rel!=="CONTAINS").slice(0,15);
 if(ins.length+outs.length)h+=`<h3>Relationships</h3><ul class="list">${ins.map(e=>`<li>← ${e.rel} <span class="link" data-n="${esc(e.s)}">${esc((NODES[e.s]||{}).label||e.s)}</span>${e.loc?` <span class="sub">${esc(e.loc)}</span>`:""}</li>`).join("")}${outs.map(e=>`<li>→ ${e.rel} <span class="link" data-n="${esc(e.t)}">${esc((NODES[e.t]||{}).label||e.t)}</span>${e.loc?` <span class="sub">${esc(e.loc)}</span>`:""}</li>`).join("")}</ul>`;
 return h}
function legend(){const row=(sw,t)=>`<div>${sw}</div><div>${t}</div>`;let h='<div class="legend">';
 h+=Object.entries(RISK_COL).slice(0,4).map(([k,c])=>row(`<span class="sw" style="background:${c}"></span>`,`Worst finding ${k}`)).join("");
 h+=row(`<span class="sw" style="background:var(--card);border-color:#9aa3b2"></span>`,"Package with no finding (border = ecosystem)");
 h+=row(`<span class="sw" style="background:var(--card);border-color:#4b5563;border-width:3px"></span>`,"Thick border = direct dependency");
 h+=V.ecosystems.map(e=>row(`<span class="dot" style="background:${ECO_COL[e]}"></span>`,e)).join("");
 h+=Object.entries({source_module:"Source file",function:"Function",route:"HTTP route",secret:"Env var / secret",db_table:"DB table",external_service:"External service",sensitive_call:"Risky call",image:"Container image",action:"CI action"})
  .map(([k,t])=>row(`<span class="sw" style="background:${TYPE_COL[k]}"></span>`,t)).join("");
 h+='</div><h3>Edges</h3><div class="legend">'+[["DEPENDS_ON","solid grey: depends on"],["IMPORTS","dotted blue: imports / uses"],["CALLS","teal: calls"],["READS_ENV","red: reads secret"],["WRITES_DB","brown: database"],["CONTACTS","pink: network service"]]
  .map(([r,t])=>row(`<span class="sw" style="height:3px;background:${REL_COL[r]}"></span>`,t)).join("")+"</div>";
 return h}

/* ------------------------------------------------------------------ what-if (supply-chain chaos) */
function impactOf(purls,label){const nodes=new Set(),direct=new Set();let files=new Set(),funcs=new Set(),routes=new Set(),exposed=new Set(),deps=new Set();
 purls.forEach(p=>{nodes.add(p);const b=V.blast[p];if(!b)return;b.dependents.forEach(x=>{nodes.add(x);deps.add(x)});b.introducers.forEach(x=>{nodes.add(x);direct.add(x)});
  if(b.package)nodes.add(b.package);b.files.forEach(x=>{nodes.add(x);files.add(x)});b.functions.forEach(x=>{nodes.add(x);funcs.add(x)});b.routes.forEach(x=>{nodes.add(x);routes.add(x)});b.exposed.forEach(x=>{nodes.add(x);exposed.add(x)})});
 const install=purls.some(p=>(NODES[p]||{}).has_install_script);const prod=purls.some(p=>(NODES[p]||{}).scope==="prod")||[...direct].some(d=>(NODES[d]||{}).scope==="prod");
 return{label,origin:purls,nodes:[...nodes],direct:[...direct],deps:[...deps],files:[...files],funcs:[...funcs],routes:[...routes],exposed:[...exposed],install,prod}}
function markBlast(){if(!cy||!st.blast)return;const set=new Set(st.blast.nodes);cy.nodes().forEach(n=>{if(set.has(n.id()))n.addClass("boom")});
 cy.edges().forEach(e=>{if(set.has(e.source().id())&&set.has(e.target().id()))e.addClass("boom")});st.blast.origin.forEach(o=>cy.getElementById(o).addClass("origin"))}
function whatif(){const arts=V.nodes.filter(n=>n.type==="artifact").sort((a,b)=>(a.risk?["P0","P1","P2","P3"].indexOf(a.risk):9)-(b.risk?["P0","P1","P2","P3"].indexOf(b.risk):9)||String(a.label).localeCompare(b.label));
 let h=`<p class="sub">Chaos experiments on the <b>supply chain</b>: inject a failure and see how far it spreads through dependencies, code, routes and secrets. Static estimate: reachability is not proven.</p>
 <h3>Scenario</h3><select id="scn" style="width:100%"><option value="compromise">Package compromised (malicious release / maintainer takeover)</option><option value="outage">Registry outage or package removed (left-pad style)</option></select>
 <div id="scnpick" style="margin-top:8px"></div><p><button id="runsim" class="on">Run experiment</button> <button id="clearsim">Clear</button></p><div id="simout"></div>`;
 $("sidebody").innerHTML=h;
 const pick=()=>{const s=$("scn").value;$("scnpick").innerHTML=s==="compromise"?`<select id="pk" style="width:100%">${arts.map(n=>`<option value="${esc(n.id)}" ${n.id===st.sel?"selected":""}>${n.risk?"["+n.risk+"] ":""}${esc(n.label)}${n.direct?" (direct)":""}</option>`).join("")}</select>`
  :`<select id="rg" style="width:100%">${Object.entries(V.registries).map(([r,ps])=>`<option value="${esc(r)}">${esc(r)} — ${ps.length} package(s)</option>`).join("")}</select>`};
 pick();$("scn").onchange=pick;
 $("runsim").onclick=()=>{const s=$("scn").value;st.blast=s==="compromise"?impactOf([$("pk").value],"Compromise of "+((NODES[$("pk").value]||{}).label||"")):impactOf(V.registries[$("rg").value]||[],"Outage of "+$("rg").value);
  report();st.view="blast";syncViews();draw()};
 $("clearsim").onclick=()=>{st.blast=null;$("simout").innerHTML="";if(st.view==="blast")st.view="tree";syncViews();draw()};
 if(st.blast)report()}
function report(){const b=st.blast;if(!b)return;const lab=x=>esc((NODES[x]||{}).label||x);
 const sev=b.routes.length&&b.exposed.length?"High":b.routes.length||b.exposed.length||b.install?"Medium":b.files.length?"Low":"Contained";
 $("simout").innerHTML=`<h3>${esc(b.label)}</h3><p>Estimated impact: <span class="badge ${sev==="High"?"P0":sev==="Medium"?"P1":sev==="Low"?"P2":"none"}">${sev}</span>${b.prod?"":" <span class='sig'>dev/test only</span>"}</p>
 <div class="impact"><div><b>${b.origin.length}</b>failed pkgs</div><div><b>${b.direct.length}</b>direct deps hit</div><div><b>${b.deps.length}</b>dependent pkgs</div>
 <div><b>${b.files.length}</b>source files</div><div><b>${b.routes.length}</b>exposed routes</div><div><b>${b.exposed.length}</b>secrets / data / services</div></div>
 ${b.install?'<p class="warn">Install-time code execution possible (package declares an install script).</p>':""}
 ${b.routes.length?`<h3>Routes reachable</h3><ul class="list">${b.routes.map(r=>`<li>${lab(r)}</li>`).join("")}</ul>`:""}
 ${b.exposed.length?`<h3>Secrets, tables & services in the same code</h3><ul class="list">${b.exposed.map(r=>`<li>${lab(r)} <span class="sub">${esc((NODES[r]||{}).type)}</span></li>`).join("")}</ul>`:""}
 ${b.direct.length?`<h3>Direct dependencies that break</h3><ul class="list">${b.direct.slice(0,25).map(r=>`<li>${lab(r)}</li>`).join("")}</ul>`:""}
 ${b.files.length?`<h3>Code that imports it</h3><ul class="list">${b.files.slice(0,25).map(r=>`<li>${lab(r)}</li>`).join("")}</ul>`:""}`}

/* ------------------------------------------------------------------ side panel + controls */
function tabs(){[...$("side").querySelectorAll("nav button")].forEach(b=>b.classList.toggle("on",b.dataset.t===st.tab))}
function side(){tabs();if(st.tab==="legend")$("sidebody").innerHTML=legend();else if(st.tab==="whatif")whatif();else{$("sidebody").innerHTML=st.sel?nodeDetails(st.sel):
 `<p class="sub">${esc(VIEWS[st.view].hint)}</p><p class="sub">Click a node to see its versions, findings, how it gets into the build and which code uses it. Use <b>What-if (chaos)</b> to simulate a compromised package or a registry outage.</p>`+
 `<h3>Most connected packages</h3><ul class="list">${V.nodes.filter(n=>n.type==="artifact").sort((a,b)=>(b.fan_in||0)-(a.fan_in||0)).slice(0,8).map(n=>`<li><span class="link" data-n="${esc(n.id)}">${esc(n.label)}</span> <span class="sub">fan-in ${n.fan_in||0}</span></li>`).join("")}</ul>`+
 `<h3>Riskiest packages</h3><ul class="list">${V.nodes.filter(n=>n.type==="artifact"&&n.risk).sort((a,b)=>a.risk.localeCompare(b.risk)).slice(0,10).map(n=>`<li><span class="badge ${n.risk}">${n.risk}</span> <span class="link" data-n="${esc(n.id)}">${esc(n.label)}</span></li>`).join("")}</ul>`}
 const sb=$("simbtn");if(sb)sb.onclick=()=>{st.tab="whatif";side();$("scn").value="compromise";$("runsim").click()}}
$("side").querySelector("nav").onclick=e=>{if(!e.target.dataset.t)return;st.tab=e.target.dataset.t;side()};
$("sidebody").addEventListener("click",e=>{const n=e.target.dataset.n,f=e.target.dataset.f;if(n){if(cy&&!cy.getElementById(n).length){st.view=NODES[n]&&NODES[n].type==="artifact"?"tree":"all";syncViews();st.sel=n;draw()}select(n)}if(f)openFinding(f)});
function syncViews(){[...$("views").querySelectorAll("button")].forEach(b=>b.classList.toggle("on",b.dataset.v===st.view))}
$("views").onclick=e=>{const v=e.target.dataset.v;if(!v)return;st.view=v;syncViews();draw();side()};
$("ecos").onclick=e=>{const c=e.target.closest(".chip");if(!c)return;const k=c.dataset.e;st.ecos.has(k)?st.ecos.delete(k):st.ecos.add(k);c.classList.toggle("on");draw()};
$("scope").onchange=e=>{st.scope=e.target.value;draw()};$("risky").onclick=e=>{st.risky=!st.risky;e.target.classList.toggle("on",st.risky);draw()};
$("depth").oninput=e=>{st.depth=+e.target.value;draw()};
$("fit").onclick=()=>cy&&cy.fit(undefined,30);$("reset").onclick=()=>{clearSel();st.blast=null;if(cy)cy.elements().removeClass("boom origin")};
$("png").onclick=()=>{if(!cy)return;const a=document.createElement("a");a.href=cy.png({full:true,scale:2,bg:css("--card")||"#fff"});a.download=`guardian-${R.repo.name}-${st.view}.png`;a.click()};
$("q").addEventListener("keydown",e=>{if(e.key!=="Enter")return;const q=e.target.value.toLowerCase().trim();if(!q)return;
 let hit=cy&&cy.nodes().filter(n=>String(NODES[n.id()].label).toLowerCase().includes(q))[0];
 if(!hit){const n=V.nodes.find(n=>String(n.label).toLowerCase().includes(q));if(!n)return;st.view=n.type==="artifact"?"tree":"all";st.depth=maxDepth;$("depth").value=maxDepth;syncViews();draw();hit=cy.getElementById(n.id)}
 select(hit.id())});

/* ------------------------------------------------------------------ findings + other sections */
let bandFilter="all";const bands=["all","P0","P1","P2","P3","Unprioritized"];
$("bands").innerHTML=bands.map(b=>`<button data-b="${b}" class="${b==="all"?"on":""}">${b} ${b==="all"?R.findings.length:(S.bands[b]||0)}</button>`).join("");
$("bands").onclick=e=>{if(!e.target.dataset.b)return;bandFilter=e.target.dataset.b;[...$("bands").children].forEach(x=>x.classList.toggle("on",x===e.target));drawF()};
const CL={C:"Confirmed",S:"Strong signal",W:"Weak signal"};
const REM=R.remediation||null, BYF=(REM&&REM.by_finding)||{};
function d2cell(id){const x=BYF[id];if(!x)return REM?'<td class="sub">—</td>':"";
 return `<td><b>${x.score}</b> <span class="sub">${esc((x.bucket||"").replace("_"," "))}</span>${x.verdict?`<br><span class="sig">${esc(x.verdict)}</span>`:x.plan_status?`<br><span class="sub">${esc(x.plan_status.replace("_"," "))}</span>`:""}</td>`}
function drawF(){$("ftable").innerHTML=R.findings.filter(f=>bandFilter==="all"||f.band===bandFilter).map(f=>
 `<tr class="f" data-id="${f.id}"><td><span class="badge ${esc(f.band)}">${esc(f.band)}</span></td><td>${esc(f.title)}<span class="sig">${CL[f.classification]}</span></td><td>${esc(f.attack_class||f.cls)}</td><td class="sub">${esc(f.locator)}</td>${d2cell(f.id)}</tr>`).join("")}
if(REM){$("d2h").hidden=false;$("nav-rem").hidden=false;$("n-rem").textContent=(REM.plans||[]).length;
 const v=REM.verdicts||{};$("remkpis").innerHTML=[["Plans",(REM.plans||[]).length],...Object.entries(REM.plan_status||{}).map(([k,n])=>[k.replace("_"," "),n]),
  ...Object.entries(v)].map(([k,n])=>`<div class="kpi"><span class="sub">${esc(k)}</span><b>${esc(n)}</b></div>`).join("");
 $("remnote").textContent="Day 2 stages S10-S16 ran in the same pipeline after detection. Plans wait at the human approval gate: guardian approve <run_dir> <plan> --hash <hash> --reviewer <name>, then guardian remediate <run_dir>."}
drawF();$("thr").textContent=R.coverage.thresholds;
$("ftable").onclick=e=>{const tr=e.target.closest("tr");if(tr)openFinding(tr.dataset.id)};
function openFinding(id){const f=FIND[id];if(!f)return;const x=f.explanation||{};const s=f.signals||{};
 const el=$("fdetail");el.hidden=false;el.innerHTML=`<h2><span class="badge ${esc(f.band)}">${esc(f.band)}</span> ${esc(f.title)}</h2>
 <p class="sub">${esc(f.band_reason)} · ${CL[f.classification]} · detector ${esc(f.detector)} · ${esc(f.locator)}</p>
 ${NODES[f.subject]?`<p><button data-show="${esc(f.subject)}">Show in graph</button></p>`:""}
 ${s.path?`<p><b>Dependency path:</b> ${s.path.map(esc).join(" &rarr; ")}</p>`:""}
 ${s.fixed_versions&&s.fixed_versions.length?`<p><b>Fixed in:</b> ${s.fixed_versions.map(esc).join(", ")}</p>`:""}
 ${s.imported_by&&s.imported_by.length?`<p><b>Referenced in code:</b> ${s.imported_by.map(esc).join(", ")}</p>`:""}
 ${s.exposed_routes&&s.exposed_routes.length?`<p><b>Reachable from routes (static):</b> ${s.exposed_routes.map(esc).join(", ")}</p>`:""}
 <h3>Explanation <span class="sub">(${esc(x.generated_by||"none")})</span></h3>${(x.claims||[]).map(claimHtml).join("")}
 ${x.counterfactual?`<p><b>What would change it:</b> ${esc(x.counterfactual)}</p>`:""}<p class="sub">${esc(x.notes||"")}</p>
 ${BYF[id]?`<h3>Remediation (Day 2)</h3><p>Risk score <b>${BYF[id].score}</b> (${esc(BYF[id].bucket.replace("_"," "))}, confidence ${esc(BYF[id].confidence)}) · <span class="sub">${esc(BYF[id].breakdown||"")}</span></p>
 ${BYF[id].plan_key?`<p>Plan <span class="mono">${esc(BYF[id].plan_key)}</span> · ${esc(BYF[id].plan_status||"")}${BYF[id].verdict?" · verdict <b>"+esc(BYF[id].verdict)+"</b>":""}<br>${esc(BYF[id].recommended||"")}</p>`:""}
 ${BYF[id].investigation?`<p>Investigation: <b>${esc(BYF[id].investigation)}</b></p>`:""}<p><button data-rem="1">Open in Remediation</button></p>`:""}
 <h3>Raw evidence</h3><div class="claim">${(f.raw_evidence_ids||[]).map(e=>`<span class="ev" data-ev="${esc(e)}">${esc(e)}</span>`).join("")}</div>
 <details><summary class="sub">All signals</summary><pre>${esc(JSON.stringify(s,null,2))}</pre></details>`;
 const b=el.querySelector("[data-show]");if(b)b.onclick=()=>showInGraph(b.dataset.show);
 const rb=el.querySelector("[data-rem]");if(rb)rb.onclick=()=>showPage("remediation");
 if(page!=="report")showPage("report");
 el.scrollIntoView({behavior:"smooth"})}
function showInGraph(n){if(!NODES[n])return;showPage("graph");st.view=NODES[n].type==="artifact"?"tree":"all";st.depth=maxDepth;$("depth").value=maxDepth;syncViews();st.sel=n;draw();
 $("cy").scrollIntoView({behavior:"smooth",block:"center"});select(n)}
$("hist").innerHTML=(R.history||[]).map(h=>`<tr><td><code>${esc(h.commit.slice(0,7))}</code>${h.baseline?' <span class="sig">baseline</span>':""}</td><td class="sub">${esc(h.date)}</td><td>${esc(h.message)}</td><td>${esc((h.added||[]).join(", "))}</td><td>${esc((h.removed||[]).join(", "))}</td><td>${esc((h.changed||[]).map(c=>`${c.name} ${c.from}→${c.to}`).join(", "))}</td></tr>`).join("")||'<tr><td colspan="6" class="sub">No git history available</td></tr>';
$("paths").innerHTML=(R.graph.execution_paths||[]).map(p=>`<tr><td>${esc(p.route)}</td><td>${esc((p.inputs||[]).join(", "))}</td><td>${p.chain.map(esc).join(" &rarr; ")}</td><td><b>${esc(p.sink)}</b> <span class="sub">${esc(p.sink_type)}/${esc(p.rel)}</span></td><td class="sub">${esc(p.locator)}</td></tr>`).join("")||'<tr><td colspan="5" class="sub">No routes found</td></tr>';
$("disc").innerHTML=(R.graph.discrepancies||[]).map(d=>`<tr><td>${esc(d.name)} <span class="sub">${esc(d.ecosystem)}</span></td><td>${d.declared?"yes":"–"}</td><td>${d.resolved?"yes":"–"}</td><td>${d.imported?"yes":"–"}</td><td>${esc(d.status)}</td></tr>`).join("");
const C=R.coverage;$("cov").innerHTML=`<p><b>Pipeline nodes:</b> ${Object.entries(C.node_status).map(([k,v])=>`<span class="chip">${esc(k)}: ${esc(v)}</span>`).join(" ")}</p>
 ${C.degraded.length?`<p class="warn"><b>Degraded:</b> ${C.degraded.map(esc).join(", ")}</p>`:""}
 <p><b>SBOM tools:</b> ${Object.entries(C.sbom_tools||{}).map(([k,v])=>`${esc(k)} = ${esc(v)}`).join("; ")||"n/a"}</p>
 ${C.code?`<p><b>Code index:</b> ${C.code.files_parsed}/${C.code.files_total} files parsed, ${C.code.files_failed} failed, ${C.code.internal_calls_resolved} internal calls resolved, ${C.code.external_imports_unmapped||0} unmapped imports, ${C.code.dynamic_imports} dynamic imports (known unknowns)</p>`:""}
 <details><summary>Notes (${C.notes.length})</summary><ul>${C.notes.map(n=>`<li>${esc(n)}</li>`).join("")}</ul></details>
 <details><summary>Not covered on Day 1</summary><ul>${C.unsupported.map(n=>`<li>${esc(n)}</li>`).join("")}</ul></details>`;
/* ------------------------------------------------------------------ SBOM viewer (CycloneDX) */
const SB=__SBOM__||{components:[],dependencies:[]};
const RC=Object.fromEntries((R.sbom.components||[]).map(c=>[c.purl,c]));
const dependsOn={},requiredBy={};
(SB.dependencies||[]).forEach(d=>{dependsOn[d.ref]=d.dependsOn||[];(d.dependsOn||[]).forEach(t=>{(requiredBy[t]=requiredBy[t]||[]).push(d.ref)})});
const prop=(c,k)=>((c.properties||[]).find(p=>p.name===k)||{}).value;
const ROWS=(SB.components||[]).map(c=>{const r=RC[c.purl]||{},n=NODES[c.purl]||{},o=r.origin||{};const lic=(c.licenses||[]).map(l=>(l.license||{}).id||(l.license||{}).name||l.expression).filter(Boolean).join(", ");
 return{purl:c.purl,name:c.name,version:c.version||"",eco:(c.purl||"").split(":")[1].split("/")[0],scope:prop(c,"guardian:scope")||r.scope||"unknown",
  direct:prop(c,"guardian:direct")==="true",license:lic||(o.license||""),registry:o.registry||(o.resolved_url?"git/url":""),source:prop(c,"guardian:source")||r.source||"",
  seen:(r.seen_by||[]).join(", "),risk:n.risk||"",nf:(n.findings||[]).length,vulns:n.vulns||0,deps:(dependsOn[c.purl]||[]).length,
  req:(requiredBy[c.purl]||[]).filter(x=>!String(x).startsWith("project:")).length,hashes:(c.hashes||[]).length+(o.integrity?1:0),comp:c,meta:r.metadata||{},origin:o}});
const sbs={q:"",eco:"",scope:"",rel:"",vuln:false,sort:"risk",dir:1,sel:null};
const COLS=[["name","Component"],["version","Version"],["eco","Ecosystem"],["scope","Scope"],["direct","Relation"],["risk","Findings"],["license","License"],["registry","Origin"],["deps","Deps"],["req","Required by"]];
const md=SB.metadata||{};
$("sbfmt").textContent=`${SB.bomFormat||"CycloneDX"} ${SB.specVersion||""} · ${(SB.serialNumber||"").slice(0,22)}… · ${md.timestamp||""}`;
const pct=(a,b)=>b?Math.round(100*a/b)+"%":"–";
$("sbkpis").innerHTML=[["Components",ROWS.length],["Direct",ROWS.filter(r=>r.direct).length],["Transitive",ROWS.filter(r=>!r.direct).length],
 ["Ecosystems",new Set(ROWS.map(r=>r.eco)).size],["With findings",ROWS.filter(r=>r.nf).length],["Known vulns",ROWS.reduce((a,r)=>a+r.vulns,0)],
 ["License known",pct(ROWS.filter(r=>r.license).length,ROWS.length)],["Hash / integrity",pct(ROWS.filter(r=>r.hashes).length,ROWS.length)],
 ["Version pinned",pct(ROWS.filter(r=>r.version).length,ROWS.length)],["SBOM confidence",(R.sbom.report||{}).confidence||"?"]]
 .map(([k,v])=>`<div class="kpi"><span class="sub">${k}</span><b>${esc(v)}</b></div>`).join("");
[...new Set(ROWS.map(r=>r.eco))].sort().forEach(e=>$("sbeco").insertAdjacentHTML("beforeend",`<option>${esc(e)}</option>`));
const rank=r=>r.risk?["P0","P1","P2","P3","Unprioritized"].indexOf(r.risk):9;
function sbFiltered(){const q=sbs.q.toLowerCase();return ROWS.filter(r=>(!q||(r.name+" "+r.purl+" "+r.license+" "+r.version).toLowerCase().includes(q))&&(!sbs.eco||r.eco===sbs.eco)&&
 (!sbs.scope||r.scope===sbs.scope)&&(!sbs.rel||(sbs.rel==="direct")===r.direct)&&(!sbs.vuln||r.nf))
 .sort((a,b)=>{const k=sbs.sort;const va=k==="risk"?rank(a)*1000-a.nf:a[k],vb=k==="risk"?rank(b)*1000-b.nf:b[k];return (va>vb?1:va<vb?-1:String(a.name).localeCompare(b.name))*sbs.dir})}
function sbDraw(){const rows=sbFiltered();
 $("sbhead").innerHTML=COLS.map(([k,t])=>`<th data-k="${k}">${t}${sbs.sort===k?(sbs.dir>0?" ▲":" ▼"):""}</th>`).join("");
 $("sbrows").innerHTML=rows.map(r=>`<tr class="c${sbs.sel===r.purl?" sel":""}" data-p="${esc(r.purl)}"><td><b>${esc(r.name)}</b></td><td class="mono">${esc(r.version)||'<span class="warn">unresolved</span>'}</td>
  <td><span class="dot" style="background:${ECO_COL[r.eco]||"#888"}"></span> ${esc(r.eco)}</td><td>${esc(r.scope)}</td><td>${r.direct?"direct":'<span class="sub">transitive</span>'}</td>
  <td>${r.risk?`<span class="badge ${r.risk}">${r.risk}</span> ${r.nf}`:'<span class="sub">–</span>'}</td><td>${esc(r.license)||'<span class="sub">–</span>'}</td>
  <td class="sub">${esc(r.registry)}</td><td>${r.deps}</td><td>${r.req}</td></tr>`).join("")||'<tr><td colspan="10" class="sub">No components match.</td></tr>';
 $("n-sbom").textContent=ROWS.length}
function sbDetail(purl){sbs.sel=purl;const r=ROWS.find(x=>x.purl===purl);if(!r)return;const name=p=>{const x=ROWS.find(y=>y.purl===p);return x?`${x.name}@${x.version}`:p};
 const m=r.meta||{},o=r.origin||{};
 $("sbside").innerHTML=`<div style="display:flex;gap:8px;align-items:center"><span class="badge ${r.risk||"none"}">${r.risk||"no finding"}</span><b>${esc(r.name)}</b> <span class="mono">${esc(r.version)}</span></div>
 <p class="mono" style="margin:8px 0">${esc(r.purl)}</p>
 <div class="kv"><div>Ecosystem</div><div>${esc(r.eco)}</div><div>Scope</div><div>${esc(r.scope)} · ${r.direct?"direct":"transitive"}</div><div>License</div><div>${esc(r.license)||"unknown"}</div>
 <div>Origin</div><div>${esc(o.registry||"")} ${o.resolved_url?`<br><span class="mono">${esc(o.resolved_url)}</span>`:""}</div><div>Integrity</div><div class="mono">${esc(o.integrity||((r.comp.hashes||[])[0]||{}).content||"none")}</div>
 <div>Install script</div><div>${o.has_install_script?'<span class="warn">yes</span>':"no"}</div><div>Source repo</div><div>${esc(m.source_repo||o.source_repo||"")}</div>
 <div>First release</div><div>${esc(m.first_release||"")}</div><div>This version</div><div>${esc(m.version_uploaded||"")}</div><div>Releases</div><div>${esc(m.release_count??"")}</div>
 <div>Found by</div><div>${esc(r.source)}${r.seen?" · "+esc(r.seen):""}</div></div>
 <p><button id="sbg">Show in dependency graph</button></p>
 ${(NODES[r.purl]||{}).findings?`<h3>Findings</h3><ul class="list">${NODES[r.purl].findings.map(f=>FIND[f]?`<li><span class="badge ${FIND[f].band}">${FIND[f].band}</span> <span class="link" data-f="${f}">${esc(FIND[f].title)}</span></li>`:"").join("")}</ul>`:""}
 <h3>Depends on (${r.deps})</h3>${r.deps?`<ul class="list">${dependsOn[r.purl].map(p=>`<li><span class="link" data-sb="${esc(p)}">${esc(name(p))}</span></li>`).join("")}</ul>`:'<p class="sub">No recorded dependencies.</p>'}
 <h3>Required by (${r.req})</h3>${r.req?`<ul class="list">${requiredBy[r.purl].filter(x=>!x.startsWith("project:")).map(p=>`<li><span class="link" data-sb="${esc(p)}">${esc(name(p))}</span></li>`).join("")}</ul>`:'<p class="sub">Only the project itself (direct) or unknown.</p>'}
 <details><summary class="sub">CycloneDX component entry</summary><pre>${esc(JSON.stringify(r.comp,null,2))}</pre></details>`;
 $("sbg").onclick=()=>showInGraph(r.purl);sbDraw()}
$("sbhead").onclick=e=>{const k=e.target.dataset.k;if(!k)return;sbs.dir=sbs.sort===k?-sbs.dir:1;sbs.sort=k;sbDraw()};
$("sbrows").onclick=e=>{const tr=e.target.closest("tr[data-p]");if(tr)sbDetail(tr.dataset.p)};
$("sbside").addEventListener("click",e=>{if(e.target.dataset.sb)sbDetail(e.target.dataset.sb);if(e.target.dataset.f)openFinding(e.target.dataset.f)});
$("sbq").oninput=e=>{sbs.q=e.target.value;sbDraw()};$("sbeco").onchange=e=>{sbs.eco=e.target.value;sbDraw()};$("sbscope").onchange=e=>{sbs.scope=e.target.value;sbDraw()};
$("sbrel").onchange=e=>{sbs.rel=e.target.value;sbDraw()};$("sbvuln").onclick=e=>{sbs.vuln=!sbs.vuln;e.target.classList.toggle("on",sbs.vuln);sbDraw()};
const dl=(name,type,text)=>{const a=document.createElement("a");a.href=URL.createObjectURL(new Blob([text],{type}));a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(a.href),1000)};
$("sbdl").onclick=()=>dl(`${R.repo.name}.cdx.json`,"application/json",JSON.stringify(SB,null,2));
$("sbcsv").onclick=()=>{const cols=["name","version","eco","scope","direct","license","registry","risk","nf","purl"];
 dl(`${R.repo.name}-sbom.csv`,"text/csv",[cols.join(",")].concat(sbFiltered().map(r=>cols.map(k=>`"${String(r[k]??"").replace(/"/g,'""')}"`).join(","))).join("\n"))};
const SR=R.sbom.report||{};
$("sbnotes").innerHTML=`<div class="kv" style="margin-top:8px"><div>Resolution</div><div>${esc(SR.resolution)}</div><div>Confidence</div><div>${esc(SR.confidence)}</div>
 <div>Tools</div><div>${Object.entries(SR.tools||{}).map(([k,v])=>`${esc(k)}: ${esc(v)}`).join("<br>")||"–"}</div><div>Tool agreement</div><div>${SR.jaccard==null?"n/a (fewer than two sources)":`Jaccard ${SR.jaccard}`}</div></div>
 ${Object.entries(SR.only_in||{}).filter(([k,v])=>v.length).map(([k,v])=>`<p><b>Only in ${esc(k)}:</b> ${v.slice(0,20).map(esc).join(", ")}</p>`).join("")}
 <ul class="list">${(SR.notes||[]).map(n=>`<li>${esc(n)}</li>`).join("")}</ul>`;
sbDraw();
const SBTXT=JSON.stringify(SB,null,2);
$("sbjson").innerHTML=esc(SBTXT).replace(/(&quot;[^&]*?&quot;)(\s*:)/g,'<span style="color:var(--acc)">$1</span>$2').replace(/: (&quot;.*?&quot;)/g,': <span style="color:#16a34a">$1</span>');
$("sbsize").textContent=`${(SBTXT.length/1024).toFixed(1)} KB · ${(SB.components||[]).length} components · ${(SB.dependencies||[]).length} dependency entries`;
$("sbcopy").onclick=e=>{navigator.clipboard&&navigator.clipboard.writeText(SBTXT).then(()=>{e.target.textContent="Copied";setTimeout(()=>e.target.textContent="Copy",1200)})};
$("sbdl2").onclick=()=>dl(`${R.repo.name}.cdx.json`,"application/json",SBTXT);

/* ------------------------------------------------------------------ pages */
let page="report",graphReady=false;
function showPage(p){page=p;document.querySelectorAll(".page").forEach(x=>x.classList.toggle("on",x.dataset.page===p));
 [...$("topnav").querySelectorAll("button")].forEach(b=>b.classList.toggle("on",b.dataset.p===p));
 if(location.hash!=="#"+p)history.replaceState(null,"","#"+p);
 if(p==="remediation"&&!$("remframe").getAttribute("src"))$("remframe").setAttribute("src","day2/remediation.html");
 if(p==="graph"){if(!graphReady){graphReady=true;syncViews();draw();side()}else if(cy){cy.resize();cy.fit(undefined,30)}}
 window.scrollTo({top:0})}
$("topnav").onclick=e=>{const b=e.target.closest("button");if(b)showPage(b.dataset.p)};
$("n-report").textContent=R.findings.length;$("n-graph").textContent=V.nodes.length;
showPage(["graph","sbom","report"].concat(REM?["remediation"]:[]).includes(location.hash.slice(1))?location.hash.slice(1):"report");
</script></body></html>"""
