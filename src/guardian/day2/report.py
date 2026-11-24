"""Day 2 report: day2/report.json, day2/remediation.html (self-contained), day2/vex.cdx.json, and the Day 1
report.json `remediation` / `validation` / `vex` fields (placeholders since Day 1) filled with pointers + summary."""
from __future__ import annotations

import json
import uuid
from pathlib import Path

from ..store import now_iso
from .models import VerificationReport
from .policy import posture

SCHEMA = "day2-1.0"


def _summary(reports: list[VerificationReport], plans) -> dict:
    v: dict[str, int] = {}
    for r in reports:
        v[r.verdict] = v.get(r.verdict, 0) + 1
    st: dict[str, int] = {}
    for p in plans:
        st[p.status] = st.get(p.status, 0) + 1
    return {"verdicts": v, "plan_status": st, "plans": len(plans)}


def vex(dc, reports: list[VerificationReport]) -> dict:
    """CycloneDX 1.5 VEX: resolved (verified fixes), exploitable/will_not_fix (accepted risk), in_triage (awaiting)."""
    fmap = {f.id: f for f in dc.ctx.store.list_findings()}
    vulns = []
    seen = set()
    for r in reports:
        for fid in r.finding_ids:
            f = fmap.get(fid)
            if not f or f.cls != "vuln" or fid in seen:
                continue
            seen.add(fid)
            if r.verdict == "Verified":
                state, resp, detail = "resolved", ["update"], f"fixed by {r.chosen.summary if r.chosen else 'approved change'}; verified by rescan"
            elif r.verdict == "Risk accepted":
                state, resp, detail = "exploitable", ["will_not_fix"], "; ".join(a.get("reason", "") for a in r.accepted_risk)[:300]
            else:
                state, resp, detail = "in_triage", [], f"Guardian verdict: {r.verdict}"
            vulns.append({"bom-ref": f"vex:{fid}", "id": f.signals.get("advisory_id"),
                          "source": {"name": "OSV", "url": f"https://osv.dev/vulnerability/{f.signals.get('advisory_id')}"},
                          "affects": [{"ref": f.subject}],
                          "analysis": {"state": state, **({"response": resp} if resp else {}), "detail": detail}})
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
            "metadata": {"timestamp": now_iso(), "tools": {"components": [{"type": "application", "name": "guardian-day2"}]}},
            "vulnerabilities": vulns}


def write_report(dc) -> Path:
    d2, ctx = dc.d2, dc.ctx
    plans = d2.plans()
    all_revs = d2.plans(latest_only=False)
    reports = [VerificationReport.model_validate(d2.get(k)) for k in d2.keys("report:")]
    validations = {k: d2.get(k) for k in d2.keys("validation:")}
    corrections = {k.split(":", 1)[1]: d2.get(k) for k in d2.keys("corrections:")}
    approvals = [a.model_dump() for a in d2.approvals()]
    pol = d2.get("policy") or {}
    findings = ctx.store.list_findings()
    used_ev: set[str] = set()
    for a in dc.advisories.values():
        for ans in (a.relevance, a.feature_usage, a.affects_installed, a.recommended, a.mitigation_answer):
            if ans:
                used_ev |= {e for e in ans.evidence_ids if e}
        used_ev |= {e for m in a.mitigations for e in m.evidence_ids} | {c.get('evidence_id') for c in a.tool_calls if c.get('evidence_id')}
    for inv in dc.investigations.values():
        used_ev |= {t.get('evidence_id') for t in inv.tool_calls if t.get('evidence_id')}
        used_ev |= {e for c in inv.checks for e in c.evidence_ids} | {e for c in inv.claims for e in c.evidence_ids}
    for p in plans:
        used_ev |= {e for c in p.candidates for e in c.evidence_ids} | {e for c in p.rationale for e in c.evidence_ids}
    for r in reports:
        used_ev |= {e for t in r.timeline for e in t.evidence_ids}
        used_ev |= {e for p in r.policy for e in p.evidence_ids}
        if r.verifier:
            used_ev |= {e for c in r.verifier.checks for e in c.evidence_ids} | {e for c in r.verifier.claims for e in c.evidence_ids}
        for v in r.tournament:
            used_ev |= {s.evidence_id for s in v.steps if s.evidence_id}
            if v.rescan and v.rescan.evidence_id:
                used_ev.add(v.rescan.evidence_id)
        for o in r.original:
            used_ev |= set(o.get("evidence_ids") or [])
    evidence = {e.id: e.model_dump() for e in ctx.store.all_evidence() if e.id in used_ev}
    report = {
        "schema_version": SCHEMA, "generated_at": now_iso(), "run_id": ctx.store.run_id, "repo": ctx.repo.model_dump(mode="json"),
        "settings": {"sandbox": ctx.settings.sandbox, "offline": ctx.settings.offline,
                     "advisories": "snapshot" if ctx.settings.advisory_db else "osv",
                     "registry": "snapshot" if ctx.settings.registry_snapshot else "live/cache",
                     "llm": ctx.llm.name if ctx.llm else "not configured (rule-based)",
                     "max_queue": ctx.settings.max_queue, "max_finalists": ctx.settings.max_finalists,
                     "max_corrections": ctx.settings.max_corrections},
        "summary": _summary(reports, plans),
        "policy": {**pol, "posture": posture(dc.policy, findings, dc.investigations)},
        "priority": [s.model_dump() for s in dc.scores],
        "investigations": {k: v.model_dump() for k, v in dc.investigations.items()},
        "advisories": {k: v.model_dump() for k, v in dc.advisories.items()},
        "plans": [p.model_dump() for p in plans],
        "plan_revisions": [{"plan_key": p.plan_key, "revision": p.revision, "plan_hash": p.plan_hash, "parent_hash": p.parent_hash,
                            "status": p.status, "finalists": p.finalists} for p in all_revs],
        "approvals": approvals,
        "validations": validations,
        "corrections": corrections,
        "verification": [r.model_dump() for r in reports],
        "timeline": [t.model_dump() for t in d2.timeline()],
        "evidence": evidence,
    }
    out = d2.dir / "report.json"
    out.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    vx = vex(dc, reports)
    (d2.dir / "vex.cdx.json").write_text(json.dumps(vx, indent=2), encoding="utf-8")
    (d2.dir / "remediation.html").write_text(render_html(report), encoding="utf-8")
    # fill the Day 1 placeholders (pointers + summary; the Day 1 artifact hashes are untouched)
    d1 = ctx.store.run_dir / "report.json"
    try:
        r1 = json.loads(d1.read_text(encoding="utf-8"))
        r1["remediation"] = {"path": "day2/report.json", "html": "day2/remediation.html", **report["summary"],
                             "plans": [{"plan_key": p.plan_key, "title": p.title, "status": p.status, "plan_hash": p.plan_hash,
                                        "recommended": (p.candidate(p.recommended).summary if p.recommended and p.candidate(p.recommended) else None)}
                                       for p in plans]}
        r1["validation"] = [{"plan_key": r.plan_key, "verdict": r.verdict, "confidence": r.confidence} for r in reports]
        r1["vex"] = {"path": "day2/vex.cdx.json", "statements": len(vx["vulnerabilities"])}
        r1["remediation"]["by_finding"] = by_finding(dc, plans, reports)
        d1.write_text(json.dumps(r1, indent=2, default=str), encoding="utf-8")
        rerender_day1_html(ctx.store.run_dir, r1)
    except (OSError, ValueError):
        pass
    return out


def by_finding(dc, plans, reports) -> dict:
    """Per Day 1 finding: S10 score/bucket, S11 verdict, plan, status and verdict (shown in the Day 1 findings table)."""
    plan_of = {fid: p for p in plans for fid in p.finding_ids}
    rep_of = {r.plan_key: r for r in reports}
    out = {}
    for s in dc.scores:
        p = plan_of.get(s.finding_id)
        r = rep_of.get(p.plan_key) if p else None
        rec = p.candidate(p.recommended) if p and p.recommended else None
        inv = dc.investigations.get(s.finding_id)
        adv = dc.advisories.get(s.finding_id)
        out[s.finding_id] = {"score": s.total, "bucket": s.bucket, "confidence": s.confidence, "breakdown": s.breakdown(),
                             "plan_key": p.plan_key if p else None, "plan_status": p.status if p else None,
                             "recommended": rec.summary if rec else None, "verdict": r.verdict if r else None,
                             "investigation": f"{inv.verdict.replace('_', ' ')} ({inv.verdict_reason})" if inv else None,
                             "advisory": {"relevance": adv.relevance.value, "feature_usage": adv.feature_usage.value,
                                          "affects_installed": adv.affects_installed.value, "recommended": adv.recommended.value,
                                          "mitigations": [m.text[:200] for m in adv.mitigations][:2],
                                          "missing": adv.missing_evidence[:4], "by": adv.generated_by} if adv else None}
    return out


def rerender_day1_html(run_dir: Path, r1: dict) -> None:
    """report.html is ONE page for detection and remediation: re-render it with the Day 2 fields filled."""
    from ..report import render_html as render_day1
    run_dir = Path(run_dir)
    viz_p, sbom_p = run_dir / "viz.json", run_dir / "sbom.cdx.json"
    if not viz_p.exists():
        return
    viz = json.loads(viz_p.read_text(encoding="utf-8"))
    sbom = json.loads(sbom_p.read_text(encoding="utf-8")) if sbom_p.exists() else None
    (run_dir / "report.html").write_text(render_day1(r1, viz, sbom), encoding="utf-8")


def _js(obj) -> str:
    return json.dumps(obj, default=str).replace("</", "<\\/")


def render_html(report: dict) -> str:
    name = (report.get("repo") or {}).get("name", "repo").replace("<", "").replace("&", "")
    return HTML.replace("__TITLE__", name).replace("__DATA__", _js(report))


HTML = r"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Guardian Day 2 — __TITLE__</title>
<style>
:root{--bg:#f6f7f9;--card:#fff;--ink:#17202a;--sub:#5b6673;--line:#e2e6ea;--accent:#0b6e99;--ok:#1a7f37;--warn:#b26b00;--bad:#c62828;
--p0:#c62828;--p1:#e4572e;--p2:#d9a400;--p3:#5b8def;--fact:#e8f3ec;--inf:#fff5e0;--unk:#eef0f3;--mono:ui-monospace,SFMono-Regular,Consolas,monospace}
@media (prefers-color-scheme:dark){:root{--bg:#0f1418;--card:#171d23;--ink:#e6ebef;--sub:#97a3ae;--line:#2a333c;--accent:#4fb3e0;
--fact:#16301f;--inf:#3a2d10;--unk:#232a31}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
header{padding:18px 24px;border-bottom:1px solid var(--line);background:var(--card);position:sticky;top:0;z-index:2}
h1{margin:0;font-size:20px}h2{font-size:16px;margin:0 0 10px}h3{font-size:14px;margin:14px 0 6px}
.sub{color:var(--sub);font-size:12px}main{max-width:1200px;margin:0 auto;padding:16px}
nav{display:flex;gap:6px;flex-wrap:wrap;margin-top:10px}nav button{border:1px solid var(--line);background:var(--bg);color:var(--ink);border-radius:6px;padding:5px 10px;cursor:pointer}
nav button.on{background:var(--accent);color:#fff;border-color:var(--accent)}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px;margin-bottom:14px;overflow-x:auto}
table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}th{font-size:12px;color:var(--sub)}
.badge{display:inline-block;padding:1px 7px;border-radius:10px;font-size:11px;font-weight:600;color:#fff;background:#888}
.P0{background:var(--p0)}.P1{background:var(--p1)}.P2{background:var(--p2);color:#222}.P3{background:var(--p3)}
.v-Verified{background:var(--ok)}.v-Partially{background:var(--warn)}.v-Not,.v-Escalated,.v-Rejected{background:var(--bad)}.v-Awaiting,.v-Risk{background:#6b7785}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}.kpi{border:1px solid var(--line);border-radius:8px;padding:10px}
.kpi b{font-size:22px;display:block}.mono{font-family:var(--mono);font-size:12px}pre{white-space:pre-wrap;word-break:break-word;background:var(--bg);padding:10px;border-radius:6px;max-height:420px;overflow:auto}
.claim{padding:6px 10px;border-radius:6px;margin:4px 0}.claim.fact{background:var(--fact)}.claim.inference{background:var(--inf)}.claim.unknown{background:var(--unk)}
.claim small{color:var(--sub)}.pass{color:var(--ok);font-weight:600}.fail{color:var(--bad);font-weight:600}.unk{color:var(--sub)}
.bar{height:10px;border-radius:5px;background:var(--line);overflow:hidden;display:flex}.bar span{display:block;height:100%}
details summary{cursor:pointer;color:var(--accent)}.grid2{display:grid;grid-template-columns:1fr 1fr;gap:12px}
@media (max-width:760px){.grid2{grid-template-columns:1fr}main{padding:10px}header{padding:12px 16px}}
.tag{font-size:11px;border:1px solid var(--line);border-radius:4px;padding:0 5px;margin-left:4px;color:var(--sub)}
.tl{border-left:2px solid var(--line);padding-left:12px}.tl div{margin:6px 0}
</style></head><body>
<header><h1>Guardian Day 2: Brain &amp; Shield — <span id="repo"></span> <a href="../report.html" target="_top" style="font-size:12px;font-weight:400">detection report</a></h1><div class="sub" id="meta"></div>
<nav id="nav"></nav></header><main id="main"></main>
<script>
const R=__DATA__;const $=id=>document.getElementById(id);
const esc=s=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const vb=v=>`<span class="badge v-${esc((v||"").split(" ")[0])}">${esc(v)}</span>`;
const band=b=>`<span class="badge ${esc(b)}">${esc(b||"?")}</span>`;
const ok=x=>x===true?'<span class="pass">pass</span>':x===false?'<span class="fail">fail</span>':'<span class="unk">n/a</span>';
const ev=ids=>(ids||[]).map(i=>R.evidence[i]?`<details><summary class="mono">${esc(i)} · ${esc(R.evidence[i].source)} · ${esc(R.evidence[i].locator)}</summary><pre>${esc(R.evidence[i].excerpt)}</pre></details>`:`<span class="mono sub">${esc(i)}</span>`).join("");
const claims=cs=>(cs||[]).filter(c=>c.verifier_status!=="rejected").map(c=>`<div class="claim ${esc(c.type)}"><b>${esc(c.type)}</b> ${esc(c.text)} <small>(${esc(c.confidence)}, ${esc(c.verifier_status)})</small>${ev(c.evidence_ids)}</div>`).join("");
$("repo").textContent=R.repo.name;
$("meta").textContent=`run ${R.run_id} · ${R.generated_at} · sandbox ${R.settings.sandbox} · advisories ${R.settings.advisories} · ${R.settings.llm} · policy ${String((R.policy||{}).sha256||"").slice(0,12)}`;
const tabs={overview:"Overview",queue:"1 Prioritize",investigate:"2 Investigate",advisories:"Advisory analysis",plans:"3 Remediate",approve:"Approve",validate:"4 Validate",verify:"5 Verify & report",audit:"Audit trail"};
let cur="overview";
function nav(){$("nav").innerHTML=Object.entries(tabs).map(([k,v])=>`<button data-t="${k}" class="${k===cur?"on":""}">${v}</button>`).join("");
 $("nav").onclick=e=>{if(e.target.dataset.t){cur=e.target.dataset.t;nav();render()}}}
const plansBy=Object.fromEntries(R.plans.map(p=>[p.plan_key,p]));
function overview(){const s=R.summary;const fix=R.priority.filter(x=>x.bucket==="fix_now").length;
 let h=`<section class="card"><h2>From detection to verified remediation</h2><div class="kpis">
 <div class="kpi"><b>${R.priority.length}</b>findings scored</div><div class="kpi"><b>${fix}</b>in Fix now</div>
 <div class="kpi"><b>${Object.keys(R.investigations).length}</b>non-CVE signals investigated</div><div class="kpi"><b>${s.plans}</b>remediation plans</div>
 ${Object.entries(s.verdicts).map(([k,v])=>`<div class="kpi"><b>${v}</b>${vb(k)}</div>`).join("")}</div></section>`;
 h+=`<section class="card"><h2>Plans</h2><table><tr><th>Plan</th><th>Status</th><th>Verdict</th><th>Recommended</th></tr>`+
 R.plans.map(p=>{const r=R.verification.find(x=>x.plan_key===p.plan_key);const rec=p.candidates.find(c=>c.id===p.recommended);
 return `<tr><td>${esc(p.title)}<div class="sub mono">${esc(p.plan_key)} · rev ${p.revision} · ${esc(p.plan_hash.slice(0,12))}</div></td><td>${esc(p.status)}</td><td>${r?vb(r.verdict)+" <span class='sub'>"+esc(r.confidence)+"</span>":"—"}</td><td>${esc(rec?rec.summary:"—")}</td></tr>`}).join("")+`</table></section>`;
 h+=`<section class="card"><h2>Release gate (policy posture, whole repository)</h2><table><tr><th>Rule</th><th>Severity</th><th>Open violations</th><th>Examples</th></tr>`+
 ((R.policy||{}).posture||[]).map(p=>`<tr><td>${esc(p.rule_id)}<div class="sub">${esc(p.description)}</div></td><td>${esc(p.severity)}</td><td>${p.passed?'<span class="pass">0</span>':'<span class="fail">'+p.violations+'</span>'}</td><td class="sub">${esc((p.examples||[]).join("; "))}</td></tr>`).join("")+
 `</table><p class="sub">Policy sources: ${esc(((R.policy||{}).sources||[]).join(", "))}. ${esc(((R.policy||{}).notes||[]).join(" "))}</p></section>`;return h}
function queue(){return `<section class="card"><h2>Prioritized risks</h2><p class="sub">Score 0–100 = severity + exploitability + reachability + exposure + production use + criticality (+ policy). Confidence is data quality, not risk.</p><table><tr><th>Bucket</th><th>Band</th><th>Score</th><th>Finding</th><th>Confidence</th></tr>`+
 R.priority.map(s=>`<tr><td>${esc(s.bucket.replace("_"," "))}${s.needs_human?'<span class="tag">needs human look</span>':""}</td><td>${band(s.band)}</td><td><b>${s.total}</b></td><td>${esc(s.title)}<details><summary>breakdown</summary><table>${s.factors.map(f=>`<tr><td>${esc(f.name)}</td><td>${f.points>=0?"+":""}${f.points}</td><td class="sub">${esc(f.detail)}</td></tr>`).join("")}</table><div class="sub">${esc(s.bucket_reason)}${s.policy_violations.length?" · policy: "+esc(s.policy_violations.join(", ")):""}</div></details></td><td>${esc(s.confidence)}<div class="sub">${esc(s.confidence_reasons.join("; "))}</div></td></tr>`).join("")+`</table></section>`}
function investigate(){const xs=Object.values(R.investigations);if(!xs.length)return `<section class="card">No non-CVE signals needed investigation.</section>`;
 return xs.map(i=>`<section class="card"><h2>${esc(i.subject)} <span class="tag">${esc(i.signal)}</span> ${vb(i.verdict.replace("_"," "))}</h2><div class="sub">${esc(i.verdict_reason)} · label by <b>${esc(i.verdict_by||"rules")}</b> · rule baseline: ${esc(i.rule_verdict||i.verdict)} · ${esc(i.generated_by)}</div>
 ${(i.guardrail_notes||[]).map(n=>`<div class="claim unknown"><b>guardrail</b> ${esc(n)}</div>`).join("")}
 ${(i.tool_calls||[]).length?`<details><summary>agent tool calls (${i.tool_calls.length})</summary>${i.tool_calls.map(t=>`<div class="mono">${esc(t.tool)}(${esc(JSON.stringify(t.args))}) — ${esc(t.why||"")}</div>${ev([t.evidence_id])}`).join("")}</details>`:""}
 <h3>Checks</h3><table><tr><th>Check</th><th>Result</th><th>Detail</th></tr>${i.checks.map(c=>`<tr><td>${esc(c.name)}${c.strong?'<span class="tag">strong</span>':""}</td><td>${c.status==="pass"?ok(true):c.status==="fail"?ok(false):'<span class="unk">unknown</span>'}</td><td>${esc(c.detail)}${ev(c.evidence_ids)}</td></tr>`).join("")}</table>
 ${i.diffs.length?`<h3>Version / lockfile comparison</h3><pre class="mono">${esc(JSON.stringify(i.diffs,null,1))}</pre>`:""}
 <h3>Verified evidence vs AI/rule inference</h3>${claims(i.claims)}</section>`).join("")}
function cands(p){return `<table><tr><th>#</th><th>Candidate</th><th>Compat.</th><th>Risk ↓</th><th>Score</th><th>Status</th></tr>`+
 [...p.candidates].sort((a,b)=>(a.rank||99)-(b.rank||99)).map(c=>`<tr><td>${c.rank||""}</td><td><span class="tag">${esc(c.action)}</span> ${esc(c.summary)}<span class="sub mono"> ${esc(c.id)} · ${esc(c.source)}</span>
 ${c.simulation?`<details><summary>simulation</summary><div class="sub">target resolved: ${ok(c.simulation.target_resolved)} · method ${esc(c.simulation.method)}</div>${c.simulation.resolved_changes.map(x=>`<div class="mono">${esc(x.name)} ${esc(x.from)} → ${esc(x.to)} (${esc(x.bump)})</div>`).join("")}${(c.simulation.new_advisories||[]).map(a=>`<div class="fail">new advisory ${esc(a.id)} on ${esc(a.purl)}</div>`).join("")}${[...c.simulation.api_risk,...c.simulation.notes].map(n=>`<div class="sub">${esc(n)}</div>`).join("")}</details>`:""}
 ${c.compatibility_notes.length?`<div class="sub">${esc(c.compatibility_notes.join(" · "))}</div>`:""}${c.rollback?`<div class="sub">rollback: ${esc(c.rollback)}</div>`:""}
 ${c.diff?`<details><summary>diff (${esc((c.diff_sha256||"").slice(0,12))})</summary><pre class="mono">${esc(c.diff)}</pre></details>`:""}</td>
 <td>${esc(c.compatibility)}</td><td>${c.risk_reduction}</td><td>${Math.round(c.score)}</td><td>${p.finalists.includes(c.id)?'<b>finalist</b>':c.rejected_reason?'<span class="fail">rejected</span><div class="sub">'+esc(c.rejected_reason)+'</div>':c.action==="escalate"?"fallback":""}</td></tr>`).join("")+`</table>`}
function plans(){return R.plans.map(p=>`<section class="card"><h2>${esc(p.title)}</h2><div class="sub mono">${esc(p.plan_key)} · revision ${p.revision} · plan hash ${esc(p.plan_hash)}${p.parent_hash?" · parent "+esc(p.parent_hash.slice(0,12)):""} · status ${esc(p.status)}</div>
 <h3>Tournament round 1 (simulated, ranked)</h3>${cands(p)}<h3>Rationale</h3>${claims(p.rationale)}<div class="sub">by ${esc(p.rationale_by)}</div></section>`).join("")||`<section class="card">No plans: nothing in the Fix-now bucket.</section>`}
function approve(){const run=R.run_id;return `<section class="card"><h2>Human approval gate</h2><p class="sub">A reviewer approves the exact plan hash. Any change creates a new revision that needs a fresh approval. Approvals are append-only.</p>
 <table><tr><th>Plan</th><th>Hash</th><th>Status</th><th>Decide (CLI)</th></tr>${R.plans.map(p=>`<tr><td>${esc(p.title)}</td><td class="mono">${esc(p.plan_hash.slice(0,16))}</td><td>${esc(p.status)}</td><td><pre class="mono">guardian approve &lt;run_dir&gt; "${esc(p.plan_key)}" --hash ${esc(p.plan_hash.slice(0,16))} --reviewer &lt;name&gt;</pre></td></tr>`).join("")}</table>
 <h3>Decisions</h3><table><tr><th>When</th><th>Plan</th><th>Kind</th><th>Decision</th><th>Reviewer</th><th>Hash</th><th>Reason</th></tr>${R.approvals.map(a=>`<tr><td class="sub">${esc(a.timestamp)}</td><td class="mono">${esc(a.plan_key)}</td><td>${esc(a.kind)}</td><td>${esc(a.decision)}</td><td>${esc(a.reviewer)}</td><td class="mono">${esc(a.plan_hash.slice(0,12))}</td><td>${esc(a.reason)}${a.expires?" (expires "+esc(a.expires)+")":""}</td></tr>`).join("")||"<tr><td colspan=7 class='sub'>none yet</td></tr>"}</table>
 <h3>All revisions</h3><table><tr><th>Plan</th><th>Rev</th><th>Hash</th><th>Parent</th><th>Status</th></tr>${R.plan_revisions.map(r=>`<tr><td class="mono">${esc(r.plan_key)}</td><td>${r.revision}</td><td class="mono">${esc(r.plan_hash.slice(0,12))}</td><td class="mono">${esc((r.parent_hash||"").slice(0,12))}</td><td>${esc(r.status)}</td></tr>`).join("")}</table></section>`}
function vrow(v){const r=v.rescan;return `<tr><td class="mono">${esc(v.candidate_id)}${v.winner?' <span class="badge v-Verified">winner</span>':""}<div class="sub">${esc(v.branch)}</div></td><td>${esc(v.sandbox)}</td><td>${esc(v.status)}<div class="sub">${esc(v.reason)}</div></td>
 <td>${v.tests_before.ran?`${v.tests_before.passed}/${v.tests_before.failed}`:"—"} → ${v.tests_after.ran?`${v.tests_after.passed}/${v.tests_after.failed}${v.tests_after.smoke_only?" (smoke)":""}`:"—"}${v.regressions.length?`<div class="fail">regressed: ${esc(v.regressions.join(", "))}</div>`:""}</td>
 <td>${r?ok(r.target_resolved)+` · ${r.findings_new.length} new · score ${r.score_before}→${r.score_after}`:"—"}</td><td>${v.tournament_score??""}</td></tr>
 <tr><td colspan=6>${v.steps.map(s=>`<details><summary>${s.ok?"✓":"✗"} ${esc(s.name)} (${s.seconds}s)</summary><div class="mono sub">${esc((s.command||[]).join(" ").slice(0,300))}</div>${ev([s.evidence_id])}</details>`).join("")}</td></tr>`}
function validate(){const ks=Object.keys(R.validations);if(!ks.length)return `<section class="card">Nothing validated yet: approve a plan, then run <span class="mono">guardian remediate &lt;run_dir&gt; --resume</span>.</section>`;
 return ks.map(k=>`<section class="card"><h2>${esc(k.split(":").slice(1,-1).join(":"))} <span class="sub">rev ${esc(k.split(":").pop())}</span></h2><h3>Tournament round 2 (build, test, rescan)</h3>
 <table><tr><th>Candidate</th><th>Sandbox</th><th>Result</th><th>Tests before → after (pass/fail)</th><th>Rescan</th><th>Score</th></tr>${R.validations[k].map(vrow).join("")}</table>
 ${(R.corrections[k.split(":").slice(1,-1).join(":")]||[]).map(c=>`<div class="claim inference"><b>self-correction round ${c.round}</b>: ${esc(c.failure_class)} → ${esc(c.outcome)} · ${esc(c.detail)} <small>${esc(c.proposed_by)}${c.new_plan_hash?" · new plan "+esc(c.new_plan_hash.slice(0,12))+" needs approval":""}</small>${ev(c.log_evidence_ids)}</div>`).join("")}</section>`).join("")}
function bars(b){const t=Object.values(b).reduce((a,x)=>a+x,0)||1;return `<div class="bar">${["P0","P1","P2","P3"].map(k=>`<span class="${k}" style="width:${100*(b[k]||0)/t}%" title="${k}: ${b[k]||0}"></span>`).join("")}</div><div class="sub">${["P0","P1","P2","P3"].map(k=>`${k} ${b[k]||0}`).join(" · ")}</div>`}
function verify(){if(!R.verification.length)return `<section class="card">No verification reports yet.</section>`;
 return R.verification.map(r=>{const rs=r.rescan;return `<section class="card"><h2>${vb(r.verdict)} ${esc(r.title)}</h2><div class="sub">confidence <b>${esc(r.confidence)}</b> · deterministic verdict ${esc(r.deterministic_verdict)} · ${esc(r.confidence_reasons.join("; "))}</div>
 <div class="grid2"><div><h3>1 Original finding &amp; evidence</h3>${r.original.map(o=>`<div>${band(o.band)} ${esc(o.title)}${o.historical?'<span class="tag">historical</span>':""}<div class="sub">${esc(o.band_reason||"")}</div>${ev(o.evidence_ids)}</div>`).join("")}</div>
 <div><h3>2 Recommended &amp; approved action</h3>${r.chosen?`<div><span class="tag">${esc(r.chosen.action)}</span> ${esc(r.chosen.summary)}</div><div class="sub">rollback: ${esc(r.chosen.rollback)}</div>`:"<div class='sub'>none applied</div>"}${r.approved?`<div class="sub">approved by <b>${esc(r.approved.reviewer)}</b> at ${esc(r.approved.timestamp)} · hash ${esc(r.approved.plan_hash.slice(0,12))}</div>`:""}
 <details><summary>alternatives considered (${r.alternatives.length})</summary>${r.alternatives.map(a=>`<div class="sub">[${esc(a.action)}] ${esc(a.summary)} ${a.rejected_reason?"— "+esc(a.rejected_reason):""}</div>`).join("")}</details></div></div>
 <h3>3 Build and test results</h3><table><tr><th>Candidate</th><th>Sandbox</th><th>Result</th><th>Tests</th><th>Rescan</th><th>Score</th></tr>${r.tournament.map(vrow).join("")}</table>
 <h3>4 Before and after</h3>${rs?`<div class="grid2"><div><b>Before</b>${bars(rs.bands_before)}<div class="sub">risk score sum ${rs.score_before}</div></div><div><b>After</b>${bars(rs.bands_after)}<div class="sub">risk score sum ${rs.score_after}</div></div></div>
 <table><tr><th>SBOM changed</th><th>Added</th><th>Removed</th></tr><tr><td class="mono">${rs.sbom_changed.map(c=>esc(`${c.name} ${c.from} → ${c.to}`)).join("<br>")||"—"}</td><td class="mono">${rs.sbom_added.map(esc).join("<br>")||"—"}</td><td class="mono">${rs.sbom_removed.map(esc).join("<br>")||"—"}</td></tr></table>
 <table><tr><th>Resolved</th><th>Still open</th><th>New</th></tr><tr><td>${rs.findings_resolved.map(x=>band(x.band)+" "+esc(x.title)).join("<br>")||"—"}</td><td>${rs.findings_open.map(x=>band(x.band)+" "+esc(x.title)).join("<br>")||"—"}${rs.vulnerable_versions_left.map(x=>`<div class="fail">${esc(x)}</div>`).join("")}</td><td>${rs.findings_new.map(x=>band(x.band)+" "+esc(x.title)).join("<br>")||"—"}</td></tr></table>`:"<div class='sub'>no rescan</div>"}
 <h3>Policy (sha ${esc((r.policy[0]||{}).policy_sha256?.slice(0,12)||"")})</h3><table><tr><th>Rule</th><th>Severity</th><th>Result</th><th>Detail</th></tr>${r.policy.map(p=>`<tr><td>${esc(p.rule_id)}${p.floor?'<span class="tag">floor</span>':""}</td><td>${esc(p.severity)}</td><td>${ok(p.passed)}</td><td>${esc(p.detail)}</td></tr>`).join("")}</table>
 ${r.verifier?`<h3>Independent verifier <span class="sub">${esc(r.verifier.generated_by)}</span></h3><table>${r.verifier.checks.map(c=>`<tr><td>${esc(c.check)}</td><td>${ok(c.ok)}</td><td>${esc(c.detail)}${ev(c.evidence_ids)}</td></tr>`).join("")}</table>${claims(r.verifier.claims)}${r.verifier.downgrade_to?`<div class="fail">downgrade to ${esc(r.verifier.downgrade_to)}: ${esc(r.verifier.reason)}</div>`:""}`:""}
 <h3>5 Remaining or accepted risk</h3>${r.remaining_risk.map(x=>`<div>${band(x.band)} ${esc(x.title)} <span class="sub">— ${esc(x.why)}</span></div>`).join("")||"<div class='sub'>none</div>"}${r.accepted_risk.map(a=>`<div>accepted by ${esc(a.reviewer)} until ${esc(a.expires)}: ${esc(a.reason)}</div>`).join("")}
 ${r.corrections.length?`<h3>Self-correction</h3>${r.corrections.map(c=>`<div class="claim inference">round ${c.round}: ${esc(c.failure_class)} → ${esc(c.outcome)} · ${esc(c.detail)}</div>`).join("")}`:""}
 <h3>6 Audit trail</h3><div class="tl">${r.timeline.map(t=>`<div><span class="sub mono">${esc(t.at)}</span> <b>${esc(t.stage)}</b> ${esc(t.event)} <span class="sub">${esc(t.actor)}</span><div class="sub">${esc(t.detail)}</div></div>`).join("")}</div></section>`}).join("")}
function audit(){return `<section class="card"><h2>Audit trail (append-only)</h2><div class="tl">${R.timeline.map(t=>`<div><span class="sub mono">${esc(t.at)}</span> <b>${esc(t.stage)}</b> ${esc(t.event)} <span class="sub">${esc(t.actor)}${t.plan_key?" · "+esc(t.plan_key):""}</span><div class="sub">${esc(t.detail)}</div>${ev(t.evidence_ids)}</div>`).join("")}</div></section>`}
function ansRow(label,a){if(!a)return "";return `<tr><td>${esc(label)}<div class="sub">${esc(a.question)}</div></td><td><b>${esc(a.value)}</b></td>
 <td><div class="claim ${esc(a.basis)}"><b>${esc(a.basis)}</b> ${esc(a.text)} <small>(${esc(a.verifier_status)}, ${esc(a.by)})</small>${ev(a.evidence_ids)}</div></td></tr>`}
function advisories(){const xs=Object.values(R.advisories||{});if(!xs.length)return `<section class="card">No confirmed advisories to analyse.</section>`;
 return xs.map(a=>`<section class="card"><h2>${esc(a.advisory_id)} · ${esc(a.package)}@${esc(a.version)} <span class="tag">${esc(a.generated_by)}</span></h2>
 <table><tr><th>Question</th><th>Answer</th><th>Evidence</th></tr>${ansRow("Relevance to this app",a.relevance)}${ansRow("Vulnerable feature",a.feature_usage)}
 ${ansRow("Workaround / mitigation",a.mitigation_answer)}${ansRow("Installed version + usage path",a.affects_installed)}${ansRow("Safest remediation",a.recommended)}
 <tr><td>Missing evidence<div class="sub">What evidence is still missing?</div></td><td colspan=2>${(a.missing_evidence||[]).map(m=>`<div class="claim unknown">${esc(m)}</div>`).join("")||"—"}</td></tr></table>
 ${(a.mitigations||[]).length?`<h3>Mitigations</h3>${a.mitigations.map(m=>`<div class="claim inference"><b>${esc(m.kind)}</b> ${esc(m.text)} <small>${esc(m.by)}</small>${ev(m.evidence_ids)}</div>`).join("")}`:""}
 ${(a.usage_paths||[]).length?`<h3>Usage paths</h3>${a.usage_paths.map(p=>`<div class="mono">${p.map(esc).join(" → ")}</div>`).join("")}`:""}
 ${(a.notes||[]).length?`<div class="sub">${esc(a.notes.join(" · "))}</div>`:""}${(a.tool_calls||[]).length?`<details><summary>${a.tool_calls.length} tool call(s)</summary><pre class="mono">${esc(JSON.stringify(a.tool_calls,null,1))}</pre></details>`:""}</section>`).join("")}
const V={overview,queue,investigate,advisories,plans,approve,validate,verify,audit};
function render(){$("main").innerHTML=V[cur]()}
if(new URLSearchParams(location.search).has("embed"))document.querySelector("header").style.display="none";   /* inside the Guardian app */
const fromHash=()=>{const t=location.hash.slice(1);if(tabs[t]){cur=t;nav();render()}};window.addEventListener("hashchange",fromHash);
if(tabs[location.hash.slice(1)])cur=location.hash.slice(1);nav();render();
</script></body></html>"""
