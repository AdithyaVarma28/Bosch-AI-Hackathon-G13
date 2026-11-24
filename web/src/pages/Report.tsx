// Print-friendly report: checkpoint answers, findings table, top findings with evidence, coverage, review decisions.
import { useParams } from "react-router-dom";
import { useFinding, useFindings, useOverview } from "../api";
import { PageHeader, Panel, QueryState, RiskChip } from "../components/ui";

function Top({ fid }: { fid: string }) {
  const { scanId = "" } = useParams();
  const q = useFinding(scanId, fid);
  if (!q.data) return null;
  const c = q.data.card;
  return <div className="mb-3 break-inside-avoid"><div className="flex items-center gap-2"><RiskChip risk={c.project_risk} /><b>{c.finding_id} {c.title}</b></div>
    <p className="text-sm">{c.explanation}</p><p className="text-xs text-slate-500">Evidence: {c.evidence.filter((e: any) => e.file).map((e: any) => `${e.file}:${e.lines ?? ""}`).slice(0, 4).join(", ")} · Recommendation: {c.recommendation}</p></div>;
}

export default function Report() {
  const { scanId = "" } = useParams();
  const o = useOverview(scanId);
  const f = useFindings(scanId);
  return (
    <div>
      <PageHeader crumbs={[{ label: "Overview", to: `/scans/${scanId}` }, { label: "Report" }]} title="Report">
        <button onClick={() => window.print()} className="rounded bg-indigo-600 px-2 py-1 text-sm text-white print:hidden">Print / PDF</button>
        {["json", "sarif", "cyclonedx"].map(fmt => <a key={fmt} className="rounded border border-slate-300 px-2 py-1 text-sm print:hidden dark:border-slate-600" href={`/api/scans/${scanId}/report?format=${fmt}`}>{fmt.toUpperCase()}</a>)}
      </PageHeader>
      <QueryState q={o}>{() => (
        <div className="space-y-4">
          <Panel title="Repository"><p className="text-sm"><b>{o.data.repo.name}</b> @ {o.data.repo.commit} · {o.data.repo.purpose}</p></Panel>
          <Panel title="Checkpoint answers"><ul className="list-disc space-y-1 pl-5 text-sm">
            <li><b>What is in the application?</b> {o.data.whats_in_it.modules} modules, {o.data.whats_in_it.files} files, {o.data.whats_in_it.packages_direct} direct and {o.data.whats_in_it.packages_transitive} transitive packages, {o.data.whats_in_it.routes.length} routes, {o.data.whats_in_it.services.length} external services.</li>
            <li><b>What changed?</b> {(o.data.what_changed.items ?? []).slice(0, 6).map((i: any) => i.label).join("; ")}</li>
            <li><b>What appears risky?</b> {Object.entries(o.data.what_looks_risky.by_risk).map(([k, v]) => `${v} ${k}`).join(", ")}; {o.data.what_looks_risky.pending_reviews} awaiting review.</li></ul></Panel>
          <QueryState q={f}>{() => <>
            <Panel title="Top 5 findings">{f.data!.slice(0, 5).map(r => <Top key={r.finding_id} fid={r.finding_id} />)}</Panel>
            <Panel title="All findings"><table className="w-full text-sm"><thead className="text-left text-xs uppercase text-slate-500"><tr><th>ID</th><th>Title</th><th>Risk</th><th>Confidence</th><th>Review</th></tr></thead>
              <tbody>{f.data!.map(r => <tr key={r.finding_id} className="border-t border-slate-100"><td className="py-1 mono text-xs">{r.finding_id}</td><td>{r.title}</td><td><RiskChip risk={r.project_risk} /></td><td>{r.confidence}</td><td>{r.review_status}</td></tr>)}</tbody></table></Panel></>}</QueryState>
          <Panel title="Coverage"><p className="text-sm">{o.data.coverage.calls_resolved}/{o.data.coverage.calls_total} internal calls resolved · {o.data.coverage.files_parsed}/{o.data.coverage.files} files parsed · {o.data.coverage.known_unknowns} known unknowns</p></Panel>
        </div>)}</QueryState>
    </div>
  );
}
