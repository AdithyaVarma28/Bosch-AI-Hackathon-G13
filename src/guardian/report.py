"""S9 Report: report.json (schema 1.0) + a self-contained interactive report.html."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .context import RunContext
from .scoring import THRESHOLDS_NOTE
from .store import now_iso

UNSUPPORTED = [
    "Malicious code inside a published package's contents (package tarballs are not unpacked or analysed on Day 1)",
    "Runtime reachability of vulnerable functions (static references only)",
    "Compromised maintainer accounts / registry account takeover",
    "Native/binary artifact analysis",
    "Ecosystems other than npm and PyPI (Maven, Go, Cargo, ...) are inventoried only",
    "Container image layer contents unless Syft/Trivy can run",
]


def _sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def build_report(ctx: RunContext, node_status: dict[str, str], plan: dict, errors: list[str]) -> Path:
    store = ctx.store
    findings = store.list_findings()
    order = {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "Unprioritized": 4}
    findings.sort(key=lambda f: (order.get(f.band or "", 9), {"C": 0, "S": 1, "W": 2}[f.classification], f.title))
    exps = {e.finding_id: e for e in store.get_explanations()}
    graph = ctx.graph
    f = ctx.facts
    cited: set[str] = set()
    fjson = []
    for x in findings:
        d = x.model_dump(mode="json")
        d["id"] = x.id
        e = exps.get(x.id)
        d["explanation"] = e.model_dump(mode="json") if e else None
        cited.update(x.raw_evidence_ids)
        if e:
            for c in e.claims:
                cited.update(c.evidence_ids)
        fjson.append(d)
    if ctx.dossier:
        for c in ctx.dossier.claims:
            cited.update(c.evidence_ids)
    evidence = {e.id: e.model_dump(mode="json") for e in store.all_evidence() if e.id in cited}

    bands: dict[str, int] = {}
    for x in findings:
        bands[x.band or "?"] = bands.get(x.band or "?", 0) + 1
    report = {
        "schema_version": "1.0",
        "generated_at": now_iso(),
        "run_id": store.run_id,
        "repo": ctx.repo.model_dump(mode="json"),
        "dossier": ctx.dossier.model_dump(mode="json") if ctx.dossier else None,
        "summary": {"components": len(ctx.components), "direct": sum(c.direct for c in ctx.components),
                    "transitive": sum(not c.direct for c in ctx.components), "findings": len(findings), "bands": bands,
                    "vulnerabilities": sum(x.cls == "vuln" for x in findings),
                    "supply_chain_signals": sum(x.cls in ("anomaly", "discrepancy") for x in findings),
                    "container_ci": sum(x.cls in ("container", "ci") for x in findings),
                    "secrets": sum(x.cls == "secret" for x in findings)},
        "inventory": {
            "ecosystems": f.ecosystems if f else [], "languages": f.languages if f else {},
            "manifests": [m.model_dump(mode="json") for m in (f.manifests if f else [])],
            "lockfiles": [h.model_dump(mode="json") for h in (f.lockfiles if f else [])],
            "package_indexes": [i.model_dump(mode="json") for i in (f.package_indexes if f else [])],
            "dockerfiles": [d.model_dump(mode="json", exclude={"instructions"}) for d in (f.dockerfiles if f else [])],
            "ci_workflows": [w.model_dump(mode="json") for w in (f.ci_workflows if f else [])],
            "compose_services": [s.model_dump(mode="json") for s in (f.config.compose_services if f else [])],
            "env_var_names": [e.model_dump(mode="json") for e in (f.config.env_files if f else [])],
        },
        "sbom": {"path": "sbom.cdx.json", "report": ctx.sbom_report.model_dump(mode="json") if ctx.sbom_report else None,
                 "components": [{**c.model_dump(mode="json", include={"purl", "name", "version", "ecosystem", "scope", "direct", "source", "seen_by"}),
                                 "origin": c.origin.model_dump(mode="json"),
                                 "metadata": (ctx.metadata.get(c.purl).model_dump(mode="json", include={"first_release", "version_uploaded", "release_count", "source_repo", "status"})
                                              if ctx.metadata.get(c.purl) else None)}
                                for c in ctx.components]},
        "graph": {"path": "graph.json", "counts": graph.counts() if graph else {},
                  "validation": graph.validation if graph else {},
                  "discrepancies": graph.discrepancies() if graph else [],
                  "execution_paths": graph.execution_paths() if graph else []},
        "history": [h.model_dump(mode="json", by_alias=True) for h in (f.dependency_history if f else [])],
        "findings": fjson,
        "evidence": evidence,
        "coverage": {
            "node_status": node_status,
            "degraded": sorted(k for k, v in node_status.items() if v == "degraded"),
            "skipped": {k: (plan.get("reasons") or {}).get(k, "") for k, v in node_status.items() if v == "skipped"},
            "failed": sorted(k for k, v in node_status.items() if v == "failed"),
            "code": ctx.code_index.coverage.model_dump() if ctx.code_index else None,
            "sbom_tools": ctx.sbom_report.tools if ctx.sbom_report else {},
            "notes": (ctx.sbom_report.notes if ctx.sbom_report else []) + (f.errors[:20] if f else []) +
                     (ctx.code_index.errors[:20] if ctx.code_index else []),
            "pipeline_errors": [e for e in errors if not e.startswith("Traceback")][:20],
            "llm": ctx.llm.name if ctx.llm else "not configured (set GROQ_API_KEY to enable the LLM agents)",
            "unsupported": UNSUPPORTED,
            "thresholds": THRESHOLDS_NOTE,
        },
        "remediation": None, "validation": None, "vex": None,   # Day 2
    }
    arts = {}
    for name in ("facts.json", "sbom.cdx.json", "code_index.json", "graph.json"):
        p = store.run_dir / name
        if p.exists():
            arts[name] = _sha(p)
    report["integrity"] = {"artifact_sha256": arts}
    out = store.run_dir / "report.json"
    out.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    graph_json = graph.to_json() if graph else {"nodes": [], "edges": []}
    (store.run_dir / "report.html").write_text(render_html(report, graph_json), encoding="utf-8")
    return out


def verify_integrity(report: dict, run_dir: Path) -> bool:
    for name, digest in (report.get("integrity") or {}).get("artifact_sha256", {}).items():
        p = Path(run_dir) / name
        if not p.exists() or _sha(p) != digest:
            return False
    return True


def _js(obj) -> str:
    return json.dumps(obj, default=str).replace("</", "<\\/")


def render_html(report: dict, graph: dict) -> str:
    return HTML.replace("__REPORT__", _js(report)).replace("__GRAPH__", _js(graph)).replace(
        "__TITLE__", (report.get("repo") or {}).get("name", "report").replace("<", ""))


HTML = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Guardian report: __TITLE__</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.28.1/cytoscape.min.js"></script>
<style>
:root{--bg:#f7f8fa;--card:#fff;--fg:#1d2330;--mut:#5d6677;--line:#e3e6eb;--acc:#1f6feb;--p0:#b42318;--p1:#c4320a;--p2:#b54708;--p3:#475467;--ok:#067647}
@media (prefers-color-scheme:dark){:root{--bg:#0f1218;--card:#171b23;--fg:#e6e9ef;--mut:#9aa3b2;--line:#2a303b;--acc:#58a6ff}}
*{box-sizing:border-box}body{margin:0;font:14px/1.45 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--fg)}
header{padding:16px 24px;border-bottom:1px solid var(--line);background:var(--card)}h1{margin:0;font-size:20px}h2{font-size:16px;margin:0 0 10px}
.sub{color:var(--mut)}main{padding:16px 24px;display:grid;gap:16px}.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px;overflow:auto}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px}.kpi b{display:block;font-size:22px}
nav button,.chip{border:1px solid var(--line);background:var(--card);color:var(--fg);border-radius:999px;padding:4px 10px;margin:0 4px 4px 0;cursor:pointer;font-size:12px}
nav button.on{background:var(--acc);color:#fff;border-color:var(--acc)}table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}
th{color:var(--mut);font-weight:600;font-size:12px}.band{font-weight:700;border-radius:6px;padding:1px 6px;color:#fff;font-size:12px}
.P0{background:var(--p0)}.P1{background:var(--p1)}.P2{background:var(--p2)}.P3{background:var(--p3)}.Unprioritized{background:#888}
.sig{font-size:11px;border:1px solid var(--line);border-radius:4px;padding:0 5px;margin-left:4px}tr.f{cursor:pointer}tr.f:hover{background:rgba(31,111,235,.06)}
#cy{height:560px;border:1px solid var(--line);border-radius:8px}.split{display:grid;grid-template-columns:2fr 1fr;gap:12px}
pre{white-space:pre-wrap;background:rgba(127,127,127,.08);padding:8px;border-radius:6px;font-size:12px;max-height:260px;overflow:auto}
.claim{margin:6px 0;padding:6px 8px;border-left:3px solid var(--acc);background:rgba(127,127,127,.06)}.t{font-size:11px;font-weight:700;text-transform:uppercase;margin-right:6px}
.ev{color:var(--acc);cursor:pointer;text-decoration:underline;font-size:12px;margin-right:6px}.warn{color:var(--p1)}
@media (max-width:900px){.split{grid-template-columns:1fr}main{padding:12px 16px}}
</style></head><body>
<header><h1>Guardian supply-chain report: <span id="repo"></span></h1><div class="sub" id="meta"></div></header>
<main>
<section class="card"><h2>What is in the application</h2><div id="dossier"></div><div class="kpis" id="kpis" style="margin-top:12px"></div></section>
<section class="card"><h2>Dependency graph</h2>
<nav id="layers"></nav><div class="split"><div id="cy"></div><div id="detail" class="card" style="max-height:560px"><span class="sub">Click a node to see its evidence.</span></div></div></section>
<section class="card"><h2>What appears risky</h2><nav id="bands"></nav><table><thead><tr><th>Band</th><th>Finding</th><th>Class</th><th>Locator</th></tr></thead><tbody id="ftable"></tbody></table>
<div class="sub" id="thr" style="margin-top:8px"></div></section>
<section class="card" id="fdetail" hidden></section>
<section class="card"><h2>What changed</h2><table><thead><tr><th>Commit</th><th>Date</th><th>Message</th><th>Added</th><th>Removed</th><th>Changed</th></tr></thead><tbody id="hist"></tbody></table></section>
<section class="card"><h2>Execution paths (route &rarr; code &rarr; sink)</h2><table><thead><tr><th>Route</th><th>Input</th><th>Call chain</th><th>Sink</th><th>Where</th></tr></thead><tbody id="paths"></tbody></table></section>
<section class="card"><h2>Declared vs resolved vs imported</h2><table><thead><tr><th>Package</th><th>Declared</th><th>Resolved</th><th>Imported</th><th>Status</th></tr></thead><tbody id="disc"></tbody></table></section>
<section class="card"><h2>Coverage: what Guardian could and could not see</h2><div id="cov"></div></section>
</main>
<script>
const R=__REPORT__, G=__GRAPH__;
const esc=s=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const $=id=>document.getElementById(id);
$("repo").textContent=R.repo.name;
$("meta").textContent=`commit ${(R.repo.commit||"n/a").slice(0,12)} · run ${R.run_id} · generated ${R.generated_at} · LLM: ${R.coverage.llm}`;
const D=R.dossier||{};
$("dossier").innerHTML=`<p><b>${esc(D.app_type)}</b> · exposure <b>${esc(D.exposure)}</b> · by ${esc(D.generated_by)}</p><p>${esc(D.summary)}</p>`+
 (D.claims||[]).map(c=>claimHtml(c)).join("")+`<details><summary class="sub">Limits</summary><ul>${(D.limits||[]).map(l=>`<li>${esc(l)}</li>`).join("")}</ul></details>`;
const S=R.summary;const sb=(R.sbom.report||{});
$("kpis").innerHTML=[["Components",S.components],["Direct",S.direct],["Transitive",S.transitive],["Vulnerabilities",S.vulnerabilities],
 ["Supply-chain signals",S.supply_chain_signals],["Container/CI",S.container_ci],["Secrets",S.secrets],["SBOM confidence",sb.confidence||"?"]]
 .map(([k,v])=>`<div class="kpi card"><span class="sub">${k}</span><b>${esc(v)}</b></div>`).join("");
function claimHtml(c){return `<div class="claim"><span class="t">${esc(c.type)}</span>${esc(c.text)} <span class="sub">[${esc(c.verifier_status)}${c.confidence?", "+esc(c.confidence):""}]</span><br>${(c.evidence_ids||[]).map(e=>`<span class="ev" data-ev="${esc(e)}">${esc(e)}</span>`).join("")}</div>`}
document.addEventListener("click",e=>{const id=e.target.dataset&&e.target.dataset.ev;if(!id)return;const ev=R.evidence[id];
 const box=e.target.closest(".claim")||e.target.parentElement;let p=box.querySelector("pre[data-for='"+id+"']");if(p){p.remove();return}
 p=document.createElement("pre");p.dataset.for=id;p.textContent=ev?`${ev.kind.toUpperCase()} · ${ev.source} · ${ev.locator}\nsha256 ${ev.sha256}\n\n${ev.excerpt}`:"evidence not embedded in report";box.appendChild(p)});
// findings
let bandFilter="all";const bands=["all","P0","P1","P2","P3","Unprioritized"];
$("bands").innerHTML=bands.map(b=>`<button data-b="${b}" class="${b==="all"?"on":""}">${b} ${b==="all"?R.findings.length:(S.bands[b]||0)}</button>`).join("");
$("bands").onclick=e=>{if(!e.target.dataset.b)return;bandFilter=e.target.dataset.b;[...$("bands").children].forEach(x=>x.classList.toggle("on",x===e.target));drawF()};
const CL={C:"Confirmed",S:"Strong signal",W:"Weak signal"};
function drawF(){$("ftable").innerHTML=R.findings.filter(f=>bandFilter==="all"||f.band===bandFilter).map((f,i)=>
 `<tr class="f" data-i="${R.findings.indexOf(f)}"><td><span class="band ${esc(f.band)}">${esc(f.band)}</span></td><td>${esc(f.title)}<span class="sig">${CL[f.classification]}</span></td><td>${esc(f.attack_class||f.cls)}</td><td class="sub">${esc(f.locator)}</td></tr>`).join("")}
drawF();$("thr").textContent=R.coverage.thresholds;
$("ftable").onclick=e=>{const tr=e.target.closest("tr");if(!tr)return;const f=R.findings[+tr.dataset.i];const x=f.explanation||{};const s=f.signals||{};
 const el=$("fdetail");el.hidden=false;el.innerHTML=`<h2><span class="band ${esc(f.band)}">${esc(f.band)}</span> ${esc(f.title)}</h2>
 <p class="sub">${esc(f.band_reason)} · ${CL[f.classification]} · detector ${esc(f.detector)} · ${esc(f.locator)}</p>
 ${s.path?`<p><b>Dependency path:</b> ${s.path.map(esc).join(" &rarr; ")}</p>`:""}
 ${s.fixed_versions&&s.fixed_versions.length?`<p><b>Fixed in:</b> ${s.fixed_versions.map(esc).join(", ")}</p>`:""}
 ${s.imported_by&&s.imported_by.length?`<p><b>Referenced in code:</b> ${s.imported_by.map(esc).join(", ")}</p>`:""}
 ${s.exposed_routes&&s.exposed_routes.length?`<p><b>Reachable from routes (static):</b> ${s.exposed_routes.map(esc).join(", ")}</p>`:""}
 <h3>Explanation <span class="sub">(${esc(x.generated_by||"none")})</span></h3>${(x.claims||[]).map(claimHtml).join("")}
 ${x.counterfactual?`<p><b>What would change it:</b> ${esc(x.counterfactual)}</p>`:""}<p class="sub">${esc(x.notes||"")}</p>
 <h3>Raw evidence</h3><div class="claim">${(f.raw_evidence_ids||[]).map(e=>`<span class="ev" data-ev="${esc(e)}">${esc(e)}</span>`).join("")}</div>
 <details><summary class="sub">All signals</summary><pre>${esc(JSON.stringify(s,null,2))}</pre></details>`;el.scrollIntoView({behavior:"smooth"})};
// history
$("hist").innerHTML=(R.history||[]).map(h=>`<tr><td><code>${esc(h.commit.slice(0,7))}</code>${h.baseline?' <span class="sig">baseline</span>':""}</td><td class="sub">${esc(h.date)}</td><td>${esc(h.message)}</td><td>${esc((h.added||[]).join(", "))}</td><td>${esc((h.removed||[]).join(", "))}</td><td>${esc((h.changed||[]).map(c=>`${c.name} ${c.from}→${c.to}`).join(", "))}</td></tr>`).join("")||'<tr><td colspan="6" class="sub">No git history available</td></tr>';
$("paths").innerHTML=(R.graph.execution_paths||[]).map(p=>`<tr><td>${esc(p.route)}</td><td>${esc((p.inputs||[]).join(", "))}</td><td>${p.chain.map(esc).join(" &rarr; ")}</td><td><b>${esc(p.sink)}</b> <span class="sub">${esc(p.sink_type)}/${esc(p.rel)}</span></td><td class="sub">${esc(p.locator)}</td></tr>`).join("")||'<tr><td colspan="5" class="sub">No routes found</td></tr>';
$("disc").innerHTML=(R.graph.discrepancies||[]).map(d=>`<tr><td>${esc(d.name)} <span class="sub">${esc(d.ecosystem)}</span></td><td>${d.declared?"yes":"–"}</td><td>${d.resolved?"yes":"–"}</td><td>${d.imported?"yes":"–"}</td><td>${esc(d.status)}</td></tr>`).join("");
const C=R.coverage;$("cov").innerHTML=`<p><b>Pipeline nodes:</b> ${Object.entries(C.node_status).map(([k,v])=>`<span class="chip">${esc(k)}: ${esc(v)}</span>`).join("")}</p>
 ${C.degraded.length?`<p class="warn"><b>Degraded:</b> ${C.degraded.map(esc).join(", ")}</p>`:""}
 <p><b>SBOM tools:</b> ${Object.entries(C.sbom_tools||{}).map(([k,v])=>`${esc(k)} = ${esc(v)}`).join("; ")||"n/a"}</p>
 ${C.code?`<p><b>Code index:</b> ${C.code.files_parsed}/${C.code.files_total} files parsed, ${C.code.files_failed} failed, ${C.code.internal_calls_resolved} internal calls resolved, ${C.code.internal_calls_unresolved} unresolved, ${C.code.dynamic_imports} dynamic imports (known unknowns)</p>`:""}
 <details><summary>Notes (${C.notes.length})</summary><ul>${C.notes.map(n=>`<li>${esc(n)}</li>`).join("")}</ul></details>
 <details><summary>Not covered on Day 1</summary><ul>${C.unsupported.map(n=>`<li>${esc(n)}</li>`).join("")}</ul></details>`;
// graph
const LAYERS={all:null,declared:["project","package"],resolved:["package","artifact"],usage:["source_module","package","function","route","input","db_table","secret","external_service","sensitive_call","model"],context:["project","dockerfile","image","workflow","action","compose_service"]};
const RELS={declared:["DECLARES"],resolved:["HAS_ARTIFACT","DEPENDS_ON"],usage:["IMPORTS","USES","CALLS","DEFINES","HANDLED_BY","INPUT_TO","READS_ENV","WRITES_DB","READS_DB","RAW_SQL","CONTACTS","SENSITIVE_CALL","MAPS_TO"],context:["BUILT_BY","BASED_ON","CI","USES_ACTION","RUNS_SERVICE"]};
const COLORS={project:"#111827",package:"#7c3aed",artifact:"#2563eb",source_module:"#059669",function:"#10b981",route:"#dc2626",input:"#f97316",db_table:"#a16207",secret:"#be123c",external_service:"#db2777",sensitive_call:"#ea580c",dockerfile:"#0891b2",image:"#0e7490",workflow:"#4b5563",action:"#6b7280",compose_service:"#0284c7",model:"#a16207"};
const STYLE={DEPENDS_ON:"solid",DECLARES:"dashed",IMPORTS:"dotted",USES:"dotted",CALLS:"solid"};
const flagged=new Set(R.findings.filter(f=>["P0","P1"].includes(f.band)).map(f=>f.subject));
const nodeIds=new Set(G.nodes.map(n=>n.id));
const els=[...G.nodes.map(n=>({data:{...n,id:n.id,label:n.label||n.id,color:COLORS[n.type]||"#999",hot:flagged.has(n.id)?1:0}})),
 ...G.edges.filter(e=>nodeIds.has(e.source)&&nodeIds.has(e.target)).map((e,i)=>({data:{...e,id:"e"+i,source:e.source,target:e.target,rel:e.rel,ls:STYLE[e.rel]||"solid"}}))];
let cy=null;
if(window.cytoscape){cy=cytoscape({container:$("cy"),elements:els,wheelSensitivity:.2,style:[
 {selector:"node",style:{"background-color":"data(color)",label:"data(label)","font-size":8,color:getComputedStyle(document.body).color,"text-valign":"bottom","text-wrap":"ellipsis","text-max-width":90,width:14,height:14}},
 {selector:"node[hot = 1]",style:{"border-width":3,"border-color":"#dc2626",width:20,height:20}},
 {selector:"edge",style:{width:1,"line-color":"#9aa3b2","target-arrow-color":"#9aa3b2","target-arrow-shape":"triangle","arrow-scale":.6,"curve-style":"bezier","line-style":"data(ls)",label:"data(rel)","font-size":6,color:"#9aa3b2"}},
 {selector:".faded",style:{display:"none"}}],layout:{name:"cose",animate:false,nodeRepulsion:9000,idealEdgeLength:70}});
 cy.on("tap","node",e=>{const d=e.target.data();const keys=Object.keys(d).filter(k=>!["color","hot","label","id"].includes(k));
  const ins=e.target.connectedEdges().map(x=>`${x.data("source")===d.id?"→":"←"} ${x.data("rel")} ${x.data("source")===d.id?x.data("target"):x.data("source")}${x.data("locator")?" @ "+x.data("locator"):""}`);
  $("detail").innerHTML=`<b>${esc(d.label)}</b><p class="sub">${esc(d.type)} · ${esc(d.id)}</p><pre>${esc(keys.map(k=>k+": "+JSON.stringify(d[k])).join("\n"))}</pre><b>Edges</b><pre>${esc(ins.join("\n"))}</pre>`;});
} else {$("cy").innerHTML='<p class="sub" style="padding:12px">Graph library could not load (offline). The full graph is in graph.json.</p>'}
$("layers").innerHTML=Object.keys(LAYERS).map(l=>`<button data-l="${l}" class="${l==="all"?"on":""}">${l}</button>`).join("")+'<span class="sub">solid = DEPENDS_ON/CALLS · dashed = DECLARES · dotted = IMPORTS/USES · red ring = P0/P1 finding</span>';
$("layers").onclick=e=>{const l=e.target.dataset.l;if(!l||!cy)return;[...$("layers").querySelectorAll("button")].forEach(x=>x.classList.toggle("on",x===e.target));
 cy.elements().removeClass("faded");if(LAYERS[l]){cy.nodes().filter(n=>!LAYERS[l].includes(n.data("type"))).addClass("faded");cy.edges().filter(x=>!RELS[l].includes(x.data("rel"))).addClass("faded")}
 cy.layout({name:"cose",animate:false,eles:cy.elements(":visible")}).run()};
</script></body></html>"""
