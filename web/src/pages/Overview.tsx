import { Link, useParams } from "react-router-dom";
import { Boxes, GitCompare, ShieldAlert } from "lucide-react";
import { useOverview } from "../api";
import { AIBadge, ConfidenceChip, EntityLink, PageHeader, Panel, QueryState, ReviewBadge, RiskChip, SeverityChip } from "../components/ui";

export default function Overview() {
  const { scanId = "" } = useParams();
  const q = useOverview(scanId);
  return <QueryState q={q} rows={8}>{() => {
    const d = q.data;
    const w = d.whats_in_it, c = d.what_changed, r = d.what_looks_risky;
    return (
      <div>
        <PageHeader crumbs={[{ label: "Overview" }]} title={d.repo.name}>
          <span className="mono text-sm text-slate-500">{d.repo.branch} · {d.repo.commit}</span>
        </PageHeader>
        {d.repo.purpose && <p className="mb-5 flex items-start gap-2 text-slate-700 dark:text-slate-300"><AIBadge by="rules" />{d.repo.purpose}</p>}
        <div className="grid gap-4 lg:grid-cols-3">
          <Panel title={<span className="flex items-center gap-1"><Boxes className="h-4 w-4" />What's in it</span>} action={<Link className="text-xs text-indigo-700 underline" to="map">Map →</Link>}>
            <dl className="grid grid-cols-2 gap-2 text-sm">
              <dt className="text-slate-500">Modules</dt><dd>{w.modules}</dd>
              <dt className="text-slate-500">Files / functions</dt><dd>{w.files} / {w.functions}</dd>
              <dt className="text-slate-500">Packages</dt><dd><Link className="underline" to="packages">{w.packages_direct} direct, {w.packages_transitive} transitive</Link></dd>
            </dl>
            <div className="mt-3 space-y-1 text-sm">
              <div><span className="text-xs uppercase text-slate-500">Routes </span>{w.routes.map((x: any) => <span key={x.id} className="mr-2"><EntityLink id={x.id} label={x.label} /></span>)}</div>
              <div><span className="text-xs uppercase text-slate-500">External services </span>{w.services.map((x: any) => <span key={x.id} className="mr-2"><EntityLink id={x.id} label={x.label} /></span>)}</div>
              <div><span className="text-xs uppercase text-slate-500">Tables </span>{w.tables.map((x: any) => <span key={x.id} className="mr-2"><EntityLink id={x.id} label={x.label} /></span>)}</div>
            </div>
          </Panel>
          <Panel title={<span className="flex items-center gap-1"><GitCompare className="h-4 w-4" />What changed</span>} action={<Link className="text-xs text-indigo-700 underline" to="changes">Changes →</Link>}>
            <p className="mb-2 text-xs text-slate-500">Since baseline {c.baseline?.short ?? c.baseline?.commit?.slice?.(0, 7)} ({c.summary?.commits ?? "?"} commits)</p>
            <ul className="space-y-1 text-sm">{(c.items ?? []).slice(0, 8).map((i: any, k: number) => <li key={k} className="truncate mono text-xs">{i.label}</li>)}</ul>
          </Panel>
          <Panel title={<span className="flex items-center gap-1"><ShieldAlert className="h-4 w-4" />What looks risky</span>} action={<Link className="text-xs text-indigo-700 underline" to="findings">Findings →</Link>}>
            <div className="mb-3 flex flex-wrap gap-2">{(["critical", "high", "medium", "low"] as const).map(k => <Link key={k} to={`findings?risk=${k}`} className="flex items-center gap-1"><RiskChip risk={k} /><b>{r.by_risk[k]}</b></Link>)}</div>
            {r.pending_reviews > 0 && <Link to="review" className="mb-2 block text-sm text-amber-700 underline">{r.pending_reviews} finding(s) awaiting human review</Link>}
            <ul className="space-y-1.5">{r.top.map((f: any) => <li key={f.finding_id} className="flex items-center gap-2 text-sm"><RiskChip risk={f.project_risk} /><EntityLink id={f.finding_id} label={`${f.finding_id} ${f.title.slice(0, 48)}`} /></li>)}</ul>
          </Panel>
        </div>
        <div className="mt-4 grid gap-4 lg:grid-cols-[2fr_1fr]">
          <Panel title="Top risky components">
            <table className="w-full text-sm"><thead className="text-left text-xs uppercase text-slate-500"><tr><th className="py-1">Component</th><th>Risk</th><th>Blast radius</th><th>Vulns</th><th>Anomalies</th></tr></thead>
              <tbody>{d.top_components.map((t: any) => <tr key={t.component} className="border-t border-slate-100 dark:border-slate-800"><td className="py-1.5"><EntityLink id={t.component} label={t.name} /></td><td><RiskChip risk={t.risk} /></td><td>{t.radius ?? "—"}</td><td>{t.vulns}</td><td>{t.anomalies}</td></tr>)}</tbody></table>
          </Panel>
          <Panel title="Coverage" action={<Link className="text-xs text-indigo-700 underline" to="coverage">Details →</Link>}>
            <p className="text-sm">Understood {d.coverage.calls_total ? Math.round(100 * d.coverage.calls_resolved / d.coverage.calls_total) : 100}% of internal calls · parsed {d.coverage.files_parsed}/{d.coverage.files} files · {d.coverage.known_unknowns} known unknown(s)</p>
          </Panel>
        </div>
      </div>
    );
  }}</QueryState>;
}

export { ConfidenceChip, ReviewBadge, SeverityChip };
