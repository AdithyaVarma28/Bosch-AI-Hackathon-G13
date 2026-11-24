// Flows: every entry point's execution paths as a left-to-right diagram; vulnerable usage sites marked.
import { useMemo } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { useFlows } from "../api";
import GraphView from "../components/GraphView";
import { EntityLink, PageHeader, Panel, QueryState, usePeek } from "../components/ui";

export default function Flows() {
  const { scanId = "" } = useParams();
  const q = useFlows(scanId);
  const [sp, setSp] = useSearchParams();
  const entry = sp.get("entry");
  const peek = usePeek();
  const entries = useMemo(() => [...new Set((q.data ?? []).map(p => p.entry))], [q.data]);
  const shown = (q.data ?? []).filter(p => !entry || p.entry === entry);
  const graph = useMemo(() => {
    const nodes = new Map<string, any>(), edges: any[] = [];
    for (const p of shown) {
      const chain = [p.entry, ...p.steps];
      chain.forEach((n: string) => nodes.set(n, { id: n, type: n.startsWith("route:") || n.startsWith("cli:") ? "Route" : "Function", label: n.startsWith("fn:") ? n.split("::").pop() + "()" : n.split(":").slice(1).join(":"), risk: p.vuln_sites[n] ? "high" : null }));
      chain.slice(1).forEach((n: string, i: number) => edges.push({ source: chain[i], target: n, type: "CALLS", weight: 1 }));
      for (const s of p.sink_details) {
        nodes.set(s.id, { id: s.id, type: s.id.startsWith("svc:") ? "ExternalService" : s.id.startsWith("table:") ? "Table" : s.id.startsWith("env:") ? "EnvVar" : "Package", label: s.label });
        edges.push({ source: s.function, target: s.id, type: s.via, weight: 1 });
      }
    }
    return { level: "flow", nodes: [...nodes.values()], edges };
  }, [shown]);
  return (
    <div>
      <PageHeader crumbs={[{ label: "Overview", to: `/scans/${scanId}` }, { label: "Flows", to: entry ? `/scans/${scanId}/flows` : undefined }, ...(entry ? [{ label: entry.split(":").slice(1).join(":") }] : [])]} title={entry ? entry.split(":").slice(1).join(":") : "Execution flows"} />
      <QueryState q={q} rows={8}>{() => (
        <div className="grid gap-4 lg:grid-cols-[260px_1fr]">
          <Panel title="Entry points">
            <ul className="space-y-1 text-sm">{entries.map(e => {
              const ps = q.data!.filter(p => p.entry === e);
              const vuln = ps.some(p => Object.keys(p.vuln_sites).length);
              return <li key={e}><button onClick={() => { const n = new URLSearchParams(sp); n.set("entry", e); setSp(n); }} className={`w-full rounded px-2 py-1 text-left ${entry === e ? "bg-indigo-50 dark:bg-slate-800" : ""}`}>
                <span className="font-medium">{e.split(":").slice(1).join(":")}</span><span className="block text-xs text-slate-500">{ps.length} path(s), {new Set(ps.flatMap(p => p.sinks)).size} sink(s){vuln ? " · vulnerable site" : ""}</span></button></li>;
            })}</ul>
          </Panel>
          <div className="space-y-3">
            <GraphView data={graph} layout="breadthfirst" height={420} onSelect={id => peek.open(id)} />
            {shown.map(p => (
              <Panel key={p.id}><div className="flex flex-wrap items-center gap-1 text-sm"><EntityLink id={p.entry} label={p.entry_label} /><span className="text-xs text-slate-500">({p.input ?? "no input"})</span>
                {p.steps.map((s: string) => <span key={s} className="flex items-center gap-1">→ <EntityLink id={s} />{p.vuln_sites[s] && <Link to={`/scans/${scanId}/findings/${p.vuln_sites[s]}`} className="rounded bg-orange-100 px-1 text-xs text-orange-800">{p.vuln_sites[s]}</Link>}</span>)}
                <span className="text-slate-400">⇒</span>{[...new Set(p.sink_details.map((x: any) => x.label))].map((l: any) => <span key={l} className="rounded bg-slate-100 px-1 text-xs dark:bg-slate-800">{l}</span>)}</div></Panel>))}
          </div>
        </div>)}</QueryState>
    </div>
  );
}
