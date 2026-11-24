// Unified findings inbox (vulnerabilities + anomalies). Filters live in the URL; j/k + Enter navigation.
import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { Bug, Radar } from "lucide-react";
import { FindingRow, useFindings } from "../api";
import { ConfidenceChip, EmptyState, PageHeader, Panel, QueryState, ReviewBadge, RiskChip, SeverityChip, cx } from "../components/ui";

const FILTERS: { key: keyof FindingRow; label: string; values: string[] }[] = [
  { key: "project_risk", label: "Risk", values: ["critical", "high", "medium", "low"] },
  { key: "type", label: "Type", values: ["vulnerability", "anomaly"] },
  { key: "confidence", label: "Confidence", values: ["high", "medium", "low"] },
  { key: "review_status", label: "Review", values: ["pending", "confirmed", "dismissed", "overridden", "not_required"] },
  { key: "scope", label: "Scope", values: ["runtime", "dev", "test_only", "container_os", "container", "ci"] },
];
const URLKEY: Record<string, string> = { project_risk: "risk", type: "type", confidence: "confidence", review_status: "review", scope: "scope" };

export default function Findings() {
  const { scanId = "" } = useParams();
  const q = useFindings(scanId);
  const [sp, setSp] = useSearchParams();
  const nav = useNavigate();
  const [sel, setSel] = useState(0);
  const rows = useMemo(() => (q.data ?? []).filter(r => FILTERS.every(f => {
    const v = sp.get(URLKEY[f.key as string]);
    return !v || v.split(",").includes(String(r[f.key]));
  })).filter(r => !sp.get("new") || r.commit), [q.data, sp]);
  useEffect(() => {
    const k = (e: KeyboardEvent) => {
      if ((e.target as HTMLElement)?.tagName === "INPUT") return;
      if (e.key === "j") setSel(s => Math.min(s + 1, rows.length - 1));
      if (e.key === "k") setSel(s => Math.max(s - 1, 0));
      if (e.key === "Enter" && rows[sel]) nav(`/scans/${scanId}/findings/${rows[sel].finding_id}`);
    };
    window.addEventListener("keydown", k);
    return () => window.removeEventListener("keydown", k);
  }, [rows, sel]);
  const toggle = (key: string, v: string) => {
    const n = new URLSearchParams(sp);
    const cur = new Set((n.get(key) ?? "").split(",").filter(Boolean));
    cur.has(v) ? cur.delete(v) : cur.add(v);
    cur.size ? n.set(key, [...cur].join(",")) : n.delete(key);
    setSp(n);
  };
  return (
    <div>
      <PageHeader crumbs={[{ label: "Overview", to: `/scans/${scanId}` }, { label: "Findings" }]} title="Findings">
        <span className="text-xs text-slate-500">j / k to move · Enter to open</span>
      </PageHeader>
      <div className="grid gap-4 lg:grid-cols-[200px_1fr]">
        <Panel title="Filters">
          {FILTERS.map(f => (
            <fieldset key={f.label} className="mb-3"><legend className="mb-1 text-xs font-semibold uppercase text-slate-500">{f.label}</legend>
              {f.values.map(v => <label key={v} className="flex items-center gap-2 text-sm capitalize"><input type="checkbox" checked={(sp.get(URLKEY[f.key as string]) ?? "").split(",").includes(v)} onChange={() => toggle(URLKEY[f.key as string], v)} />{v.replace("_", " ")}</label>)}
            </fieldset>))}
          <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={!!sp.get("new")} onChange={() => { const n = new URLSearchParams(sp); n.get("new") ? n.delete("new") : n.set("new", "1"); setSp(n); }} />New in last diff</label>
        </Panel>
        <QueryState q={q} rows={10}>{() => rows.length === 0 ? <EmptyState title="No findings match these filters." /> : (
          <div className="overflow-x-auto rounded-xl border border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900">
            <table className="w-full text-sm">
              <thead className="bg-slate-50 text-left text-xs uppercase text-slate-500 dark:bg-slate-800"><tr>
                <th className="px-3 py-2">ID</th><th>Type</th><th>Title / component</th><th>Project risk</th><th>Severity / suspicion</th><th>Confidence</th><th>Usage · reach / exposure</th><th>Review</th></tr></thead>
              <tbody>{rows.map((r, i) => (
                <tr key={r.finding_id} className={cx("border-t border-slate-100 align-top dark:border-slate-800", i === sel && "bg-indigo-50/60 dark:bg-slate-800/60")}>
                  <td className="whitespace-nowrap px-3 py-2 mono text-xs"><Link to={r.finding_id} className="text-indigo-700 hover:underline dark:text-indigo-300">{r.finding_id}</Link></td>
                  <td>{r.type === "vulnerability" ? <span className="inline-flex items-center gap-1 text-xs"><Bug className="h-3.5 w-3.5" />Vuln</span> : <span className="inline-flex items-center gap-1 text-xs"><Radar className="h-3.5 w-3.5" />Anomaly</span>}</td>
                  <td className="max-w-md py-2"><Link to={r.finding_id} className="font-medium hover:underline">{r.title}</Link><div className="text-xs text-slate-500">{r.component_name}{r.vuln_id ? ` · ${r.vuln_id}` : ""}{r.detectors ? ` · ${r.detectors.join(", ")}` : ""}</div></td>
                  <td><RiskChip risk={r.project_risk} /></td>
                  <td>{r.severity ? <SeverityChip cvss={r.severity.cvss} band={r.severity.band} /> : <span className="text-xs capitalize">suspicion {r.suspicion}</span>}</td>
                  <td><ConfidenceChip c={r.confidence} /></td>
                  <td className="text-xs text-slate-600 dark:text-slate-300">{r.type === "vulnerability" ? `${r.usage?.replaceAll("_", " ")} · ${r.reachability?.replaceAll("_", " ")}` : r.exposure?.replaceAll("_", " ")}</td>
                  <td><ReviewBadge status={r.review_status} /></td>
                </tr>))}</tbody>
            </table>
          </div>)}</QueryState>
      </div>
    </div>
  );
}
