// Packages (SBOM view): sortable, filterable table; filters in the URL; CycloneDX + CSV export.
import { useMemo } from "react";
import { useParams, useSearchParams } from "react-router-dom";
import { usePackages } from "../api";
import { EntityLink, PageHeader, QueryState, RiskChip } from "../components/ui";

const QUICK = [["vulns", "has vulns"], ["anomalies", "has anomalies"], ["direct", "direct"], ["transitive", "transitive"], ["unused", "unused"], ["dev", "dev"]];

export default function Packages() {
  const { scanId = "" } = useParams();
  const q = usePackages(scanId);
  const [sp, setSp] = useSearchParams();
  const sort = sp.get("sort") ?? "risk";
  const active = new Set((sp.get("f") ?? "").split(",").filter(Boolean));
  const order: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
  const rows = useMemo(() => {
    let r = [...(q.data ?? [])];
    if (active.has("vulns")) r = r.filter(p => p.vulns);
    if (active.has("anomalies")) r = r.filter(p => p.anomalies);
    if (active.has("direct")) r = r.filter(p => p.direct);
    if (active.has("transitive")) r = r.filter(p => !p.direct);
    if (active.has("unused")) r = r.filter(p => p.tags.includes("declared_unused"));
    if (active.has("dev")) r = r.filter(p => p.scope === "dev");
    r.sort((a, b) => sort === "name" ? a.name.localeCompare(b.name) : sort === "used" ? b.used_by - a.used_by : (order[b.risk] ?? 0) - (order[a.risk] ?? 0) || (b.max_cvss ?? 0) - (a.max_cvss ?? 0));
    return r;
  }, [q.data, sp]);
  const toggle = (k: string) => { const n = new URLSearchParams(sp); active.has(k) ? active.delete(k) : active.add(k); active.size ? n.set("f", [...active].join(",")) : n.delete("f"); setSp(n); };
  const csv = () => {
    const lines = ["name,version,direct,scope,used_by,radius,vulns,anomalies,risk", ...rows.map(p => [p.name, p.version, p.direct, p.scope, p.used_by, p.radius, p.vulns, p.anomalies, p.risk ?? ""].join(","))];
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([lines.join("\n")], { type: "text/csv" }));
    a.download = `${scanId}-packages.csv`;
    a.click();
  };
  return (
    <div>
      <PageHeader crumbs={[{ label: "Overview", to: `/scans/${scanId}` }, { label: "Packages" }]} title="Packages">
        <a className="rounded border border-slate-300 px-2 py-1 text-sm dark:border-slate-600" href={`/api/scans/${scanId}/report?format=cyclonedx`}>Download SBOM (CycloneDX)</a>
        <button onClick={csv} className="rounded border border-slate-300 px-2 py-1 text-sm dark:border-slate-600">Export CSV</button>
      </PageHeader>
      <div className="mb-3 flex flex-wrap gap-2">{QUICK.map(([k, l]) => <button key={k} onClick={() => toggle(k)} className={`rounded-full border px-2.5 py-0.5 text-xs ${active.has(k) ? "border-indigo-500 bg-indigo-50 text-indigo-700" : "border-slate-300 dark:border-slate-600"}`}>{l}</button>)}</div>
      <QueryState q={q} rows={10}>{() => (
        <div className="overflow-x-auto rounded-xl border border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900">
          <table className="w-full text-sm">
            <thead className="bg-slate-50 text-left text-xs uppercase text-slate-500 dark:bg-slate-800"><tr>
              {[["name", "Package"], ["", "Version"], ["", "Direct"], ["", "Scope"], ["", "Introduced via"], ["used", "Used by"], ["", "Blast radius"], ["", "Vulns (max CVSS)"], ["", "Anomalies"], ["risk", "Project risk"]].map(([k, l]) =>
                <th key={l} className="px-3 py-2">{k ? <button onClick={() => { const n = new URLSearchParams(sp); n.set("sort", k); setSp(n); }} className={sort === k ? "underline" : ""}>{l}</button> : l}</th>)}</tr></thead>
            <tbody>{rows.map(p => (
              <tr key={p.purl} className="border-t border-slate-100 dark:border-slate-800">
                <td className="px-3 py-1.5"><EntityLink id={p.purl} label={p.name} /></td><td className="mono text-xs">{p.version}</td>
                <td>{p.direct ? "direct" : "transitive"}</td><td>{p.scope}</td>
                <td className="text-xs">{p.direct ? (p.declared_at[0] ? `${p.declared_at[0].file}:${p.declared_at[0].line}` : "") : p.required_by.map((r: string) => r.split("/").pop()?.split("@")[0]).join(", ")}</td>
                <td>{p.used_by} file(s)</td><td>{p.radius}</td><td>{p.vulns ? `${p.vulns} (${p.max_cvss ?? "?"})` : "—"}</td><td>{p.anomalies || "—"}</td><td><RiskChip risk={p.risk} /></td>
              </tr>))}</tbody>
          </table>
        </div>)}</QueryState>
    </div>
  );
}
