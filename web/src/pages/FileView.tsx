// File page: code with gutter markers (import, env, vuln usage, anomaly, route, DB write, network); #L12-L18 highlights.
import { useEffect } from "react";
import { Link, useLocation, useParams } from "react-router-dom";
import { useFile } from "../api";
import { AIBadge, EntityLink, PageHeader, Panel, QueryState, entityHref, cx } from "../components/ui";

const MARK: Record<string, [string, string]> = { import: ["bg-blue-500", "import"], env: ["bg-yellow-400", "env read"], vuln: ["bg-red-600", "vulnerable usage"],
  anomaly: ["bg-orange-500", "anomaly"], route: ["bg-green-600", "route"], db_write: ["bg-slate-900", "DB write"], network: ["bg-cyan-500", "network"], api: ["bg-violet-500", "package API"] };

export default function FileView() {
  const { scanId = "", "*": path = "" } = useParams();
  const q = useFile(scanId, path);
  const { hash } = useLocation();
  const m = hash.match(/#L(\d+)(?:-L(\d+))?/);
  const hl: [number, number] | null = m ? [Number(m[1]), Number(m[2] ?? m[1])] : null;
  useEffect(() => { if (hl && q.data) document.getElementById(`L${hl[0]}`)?.scrollIntoView({ block: "center" }); }, [q.data, hash]);
  const parts = path.split("/");
  return (
    <div>
      <PageHeader crumbs={[{ label: "Overview", to: `/scans/${scanId}` }, { label: "Files" }, ...parts.map(p => ({ label: p }))]} title={<span className="mono text-xl">{path}</span>} />
      <QueryState q={q} rows={12}>{() => {
        const byLine: Record<number, any[]> = {};
        for (const mk of q.data.markers) (byLine[mk.line] ??= []).push(mk);
        return (
          <div className="grid gap-4 lg:grid-cols-[1fr_300px]">
            <div className="overflow-hidden rounded-xl border border-slate-200 dark:border-slate-800">
              <pre className="overflow-x-auto bg-white py-2 text-xs leading-5 dark:bg-slate-900">{q.data.lines.map((t: string, i: number) => {
                const n = i + 1, marks = byLine[n] ?? [];
                return <div key={n} id={`L${n}`} className={cx("group flex px-2", hl && n >= hl[0] && n <= hl[1] && "bg-amber-100 dark:bg-amber-900/40")}>
                  <span className="flex w-8 shrink-0 items-center gap-0.5">{marks.slice(0, 3).map((mk, k) => <Link key={k} to={entityHref(scanId, mk.target)} title={`${MARK[mk.kind]?.[1]}: ${mk.label}`} className={cx("inline-block h-2.5 w-2.5 rounded-sm", MARK[mk.kind]?.[0] ?? "bg-slate-400")} />)}</span>
                  <a href={`#L${n}`} className="w-9 shrink-0 select-none pr-3 text-right text-slate-400">{n}</a><code>{t || " "}</code></div>;
              })}{q.data.lines.length === 0 && <div className="px-3 text-slate-500">Source not available for this scan.</div>}</pre>
            </div>
            <div className="space-y-3">
              {q.data.card && <Panel title="File card"><AIBadge by={q.data.card.discovered_by} confidence={q.data.card.confidence} /><p className="mt-1 text-sm">{q.data.card.purpose}</p></Panel>}
              <Panel title="Markers"><ul className="space-y-1 text-sm">{q.data.markers.map((mk: any, i: number) => <li key={i} className="flex items-center gap-2"><i className={cx("inline-block h-2.5 w-2.5 rounded-sm", MARK[mk.kind]?.[0])} /><a href={`#L${mk.line}`} className="text-xs text-slate-500">L{mk.line}</a><EntityLink id={mk.target} label={mk.label} /></li>)}</ul></Panel>
              <Panel title="Functions"><ul className="space-y-1 text-sm">{q.data.functions.map((f: any) => <li key={f.id}><EntityLink id={f.id} label={f.label} /> <a href={`#L${f.line}`} className="text-xs text-slate-500">L{f.line}</a></li>)}</ul></Panel>
            </div>
          </div>);
      }}</QueryState>
    </div>
  );
}
