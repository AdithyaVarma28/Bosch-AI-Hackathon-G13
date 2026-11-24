"""heal.html: one page for the heal loop (iterations, applied/rolled-back fixes, agent decisions)."""
from __future__ import annotations

import json
from pathlib import Path


def render_heal_html(st) -> str:
    data = json.loads(st.model_dump_json())
    return HTML.replace("__DATA__", json.dumps(data, default=str).replace("</", "<\\/")).replace(
        "__TITLE__", st.repo.replace("<", "").replace("&", ""))


def write_heal_html(st, path: Path) -> None:
    Path(path).write_text(render_heal_html(st), encoding="utf-8")


HTML = r"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Guardian Heal — __TITLE__</title><style>
:root{--bg:#f6f7f9;--card:#fff;--ink:#17202a;--sub:#5b6673;--line:#e2e6ea;--ok:#1a7f37;--warn:#b26b00;--bad:#c62828;--accent:#0b6e99}
@media (prefers-color-scheme:dark){:root{--bg:#0f1418;--card:#171d23;--ink:#e6ebef;--sub:#97a3ae;--line:#2a333c;--accent:#4fb3e0}}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 system-ui,Segoe UI,Roboto,sans-serif}main{max-width:1100px;margin:0 auto;padding:16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px;margin-bottom:14px;overflow-x:auto}
h1{font-size:20px;margin:0}h2{font-size:16px;margin:0 0 10px}.sub{color:var(--sub);font-size:12px}table{border-collapse:collapse;width:100%}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}th{font-size:12px;color:var(--sub)}
.b{display:inline-block;padding:1px 8px;border-radius:10px;color:#fff;font-size:11px;font-weight:600}
.applied,.threshold_met{background:var(--ok)}.rolled_back,.diff_mismatch,.stopped{background:var(--bad)}.skipped,.awaiting_approval,.running{background:var(--warn)}
.mono{font-family:ui-monospace,Consolas,monospace;font-size:12px}.bar{display:flex;gap:6px;align-items:end;height:90px}
.bar div{background:var(--accent);width:40px;border-radius:4px 4px 0 0;position:relative}.bar span{position:absolute;top:-18px;width:100%;text-align:center;font-size:12px}
</style></head><body><main id="m"></main><script>
const S=__DATA__;const e=s=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const mx=Math.max(1,...S.iterations.map(i=>i.remaining||0));
document.getElementById("m").innerHTML=`<section class="card"><h1>Guardian heal agent — ${e(S.repo)} <span class="b ${e(S.status)}">${e(S.status.replace("_"," "))}</span></h1>
<div class="sub">${e(S.clone_path)} · branch <span class="mono">${e(S.branch)}</span> from ${e(S.base_commit.slice(0,10))} · started ${e(S.started_at)}</div>
<p>${e(S.stop_reason)}</p><div class="sub">threshold: ≤ ${e(S.config.max_remaining)} open finding(s) in ${e((S.config.bands||[]).join(", "))}${S.config.count_signals?" (CVEs + signals)":" (CVEs)"} · max ${e(S.config.max_iterations)} iterations · ${e(S.config.max_retries)} retries per plan · accepted verdicts: ${e((S.config.accept||[]).join(", "))}</div></section>
<section class="card"><h2>Remaining counted findings per iteration</h2><div class="bar">${S.iterations.map(i=>`<div style="height:${Math.max(4,80*(i.remaining||0)/mx)}px" title="iteration ${i.n}"><span>${i.remaining??"?"}</span></div>`).join("")}</div>
<div class="sub">${S.iterations.map(i=>"it "+i.n).join(" · ")}</div></section>
<section class="card"><h2>Iterations</h2><table><tr><th>#</th><th>Scan</th><th>HEAD</th><th>Remaining</th><th>Risk score</th><th>Applied</th></tr>
${S.iterations.map(i=>{const rid=i.run_dir?i.run_dir.split(/[\\/]/).pop():"";const href=location.protocol.startsWith("http")?`/runs/${rid}/report.html`:`../../${i.run_dir?i.run_dir.replace(/\\/g,"/").split("/").slice(-2).join("/"):""}/report.html`;
return `<tr><td>${i.n}</td><td class="mono">${i.run_dir?`<a href="${e(href)}">${e(rid)}</a>`:"—"}</td><td class="mono">${e((i.head||"").slice(0,10))}</td>
<td>${i.remaining??"—"}<div class="sub">${e((i.remaining_titles||[]).slice(0,4).join("; "))}</div></td><td>${i.risk_score??"—"}</td><td class="mono">${e(i.applied.join(", "))}</td></tr>`}).join("")}</table></section>
<section class="card"><h2>Fixes on the clone</h2><table><tr><th>It.</th><th>Status</th><th>Fix</th><th>Commit</th><th>Approved by / verdict</th><th>Verification</th></tr>
${S.fixes.map(f=>`<tr><td>${f.iteration}</td><td><span class="b ${e(f.status)}">${e(f.status.replace("_"," "))}</span></td><td>${e(f.summary)}<div class="sub mono">${e(f.plan_key)} · ${e(f.candidate_id)} · plan ${e(f.plan_hash.slice(0,12))}</div></td>
<td class="mono">${e((f.commit||"").slice(0,10))}${(f.files||[]).map(p=>`<div class="sub">${e(p)}</div>`).join("")}</td><td>${e(f.approved_by||"—")}<div class="sub">${e(f.verdict||"")}</div></td><td>${e(f.reason)}${f.resolved.length?`<details><summary class="sub">${f.resolved.length} finding(s) resolved</summary><div class="sub">${e(f.resolved.join("; "))}</div></details>`:""}</td></tr>`).join("")||"<tr><td colspan=6 class='sub'>none yet</td></tr>"}</table></section>
<section class="card"><h2>Agent decisions</h2><table><tr><th>When</th><th>It.</th><th>Action</th><th>Reason</th><th>Allowed</th><th>By</th></tr>
${S.journal.map(d=>`<tr><td class="sub">${e(d.at)}</td><td>${d.iteration}</td><td><b>${e(d.action)}</b></td><td>${e(d.reason)}</td><td class="sub">${e(d.allowed.join(", "))}</td><td class="sub">${e(d.decided_by)}</td></tr>`).join("")}</table></section>`;
</script></body></html>"""
