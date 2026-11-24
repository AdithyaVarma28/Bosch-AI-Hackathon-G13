// Supply chain: package indexes / VCS sources, CI workflows + actions, container images; each row links to its finding.
import { useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { EntityLink, PageHeader, Panel, QueryState, RiskChip } from "../components/ui";

export default function SupplyChain() {
  const { scanId = "" } = useParams();
  const q = useQuery({ queryKey: ["supply", scanId], queryFn: async () => (await fetch(`/api/scans/${scanId}/supply-chain`)).json() });
  const ok = (b: boolean) => <span className={b ? "text-emerald-700" : "text-red-700"}>{b ? "✓" : "✗"}</span>;
  return (
    <div>
      <PageHeader crumbs={[{ label: "Overview", to: `/scans/${scanId}` }, { label: "Supply chain" }]} title="Supply chain" />
      <QueryState q={q}>{() => (
        <div className="grid gap-4 lg:grid-cols-2">
          <Panel title="Sources">
            <ul className="space-y-1 text-sm">{q.data.indexes.length ? q.data.indexes.map((i: any) => <li key={i.url}>{i.type}: <code>{i.url}</code> <span className="text-xs text-slate-500">{i.source_file}:{i.line}</span></li>) : <li>PyPI (default index only)</li>}
              {q.data.vcs.map((v: any) => <li key={v.name}>{v.name}: {v.kind} <code className="text-xs">{v.spec}</code></li>)}</ul>
          </Panel>
          <Panel title="Containers">
            <table className="w-full text-sm"><thead className="text-left text-xs uppercase text-slate-500"><tr><th>Image</th><th>Digest pinned</th><th>Source</th><th>Finding</th></tr></thead>
              <tbody>{q.data.images.map((i: any) => <tr key={i.id} className="border-t border-slate-100 dark:border-slate-800"><td className="py-1"><code>{i.ref}</code></td><td>{ok(!!i.digest)}</td><td className="text-xs">{i.file}</td>
                <td>{i.findings.map((f: any) => <span key={f.finding_id} className="mr-1 inline-flex items-center gap-1"><RiskChip risk={f.project_risk} /><EntityLink id={f.finding_id} label={f.finding_id} /></span>)}</td></tr>)}</tbody></table>
            <p className="mt-2 text-xs text-slate-500">OS-level vulnerabilities from Grype: {q.data.container_vulns} {q.data.grype_note ? `(${q.data.grype_note})` : ""}</p>
          </Panel>
          <Panel title="CI/CD workflows" className="lg:col-span-2">
            {q.data.workflows.map((w: any) => (
              <div key={w.file} className="mb-3">
                <div className="flex flex-wrap items-center gap-2 text-sm"><b>{w.file}</b><span className="text-xs text-slate-500">triggers: {w.triggers.join(", ")} · permissions: {w.permissions ? JSON.stringify(w.permissions) : "not set"} · secrets: {w.secrets.join(", ") || "none"}</span>
                  {w.findings.map((f: any) => <span key={f.finding_id} className="inline-flex items-center gap-1"><RiskChip risk={f.project_risk} /><EntityLink id={f.finding_id} label={f.finding_id} /></span>)}</div>
                <table className="mt-1 w-full text-sm"><thead className="text-left text-xs uppercase text-slate-500"><tr><th>Action</th><th>Ref</th><th>Pinned by SHA</th></tr></thead>
                  <tbody>{w.actions.map((a: any) => <tr key={a.uses + a.ref} className="border-t border-slate-100 dark:border-slate-800"><td className="py-1"><code>{a.uses}</code></td><td>{a.ref}</td><td>{ok(a.pinned_to_sha)}</td></tr>)}</tbody></table>
              </div>))}
          </Panel>
        </div>)}</QueryState>
    </div>
  );
}
