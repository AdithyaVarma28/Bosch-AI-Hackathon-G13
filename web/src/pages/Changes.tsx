// Time travel: compare two stored snapshots (never re-scans), plus the commit timeline inside this scan.
import { Link, useParams, useSearchParams } from "react-router-dom";
import { useChanges, useCompare, useScan, useScans } from "../api";
import GraphView from "../components/GraphView";
import { EmptyState, EntityLink, PageHeader, Panel, QueryState, cx } from "../components/ui";

const CHANGE_COLOR: Record<string, string> = { added: "text-emerald-700", removed: "text-red-700", changed: "text-amber-700" };

export default function Changes() {
  const { scanId = "" } = useParams();
  const [sp, setSp] = useSearchParams();
  const scans = useScans();
  const me = useScan(scanId);
  const timeline = useChanges(scanId);
  const same = (scans.data ?? []).filter(s => s.repo === me.data?.repo && s.status === "done");
  const from = sp.get("from") ?? same.find(s => s.scan_id !== scanId)?.scan_id;
  const to = sp.get("to") ?? scanId;
  const cmp = useCompare(from, to);
  const set = (k: string, v: string) => { const n = new URLSearchParams(sp); n.set(k, v); setSp(n); };
  const groups: Record<string, any[]> = {};
  for (const i of cmp.data?.items ?? []) (groups[i.group] ??= []).push(i);
  const status: Record<string, string> = Object.fromEntries((cmp.data?.graph.nodes ?? []).map((n: any) => [n.id, n.status]));
  return (
    <div>
      <PageHeader crumbs={[{ label: "Overview", to: `/scans/${scanId}` }, { label: "Changes" }]} title="What changed" />
      <Panel title="Commit timeline (this scan's history)" className="mb-4">
        <QueryState q={timeline}>{() => (
          <ol className="flex gap-2 overflow-x-auto pb-1">{[...(timeline.data.commits ?? [])].reverse().map((c: any) => (
            <li key={c.commit} className={cx("min-w-48 rounded-lg border p-2 text-xs", c.type === "notable" ? "border-amber-300 bg-amber-50 dark:bg-amber-950" : "border-slate-200 dark:border-slate-700")}>
              <EntityLink id={`commit:${c.short}`} label={c.short} /> <span className="text-slate-400">{c.date?.slice(0, 10)}</span>
              <div className="font-medium">{c.title}</div>
              <ul className="mt-1 space-y-0.5 text-slate-600 dark:text-slate-300">{(c.items ?? []).slice(0, 4).map((x: string, i: number) => <li key={i} className="truncate">{x}</li>)}</ul>
            </li>))}</ol>)}</QueryState>
      </Panel>
      <div className="mb-3 flex flex-wrap items-center gap-2 text-sm">
        <span>Compare snapshot</span>
        <select value={from ?? ""} onChange={e => set("from", e.target.value)} className="rounded border border-slate-200 bg-transparent px-1 dark:border-slate-700">{same.map(s => <option key={s.scan_id} value={s.scan_id}>{s.commit?.slice(0, 7)} {s.label ?? s.scan_id}</option>)}</select>
        <span>→</span>
        <select value={to} onChange={e => set("to", e.target.value)} className="rounded border border-slate-200 bg-transparent px-1 dark:border-slate-700">{same.map(s => <option key={s.scan_id} value={s.scan_id}>{s.commit?.slice(0, 7)} {s.label ?? s.scan_id}</option>)}</select>
      </div>
      {!from ? <EmptyState title="Only one stored snapshot of this repository. Scan another commit to compare snapshots." action={<Link className="underline" to="/">Start a scan</Link>} /> :
        <QueryState q={cmp}>{() => (
          <div className="grid gap-4 lg:grid-cols-[1fr_1.2fr]">
            <Panel title={`${cmp.data.items.length} differences`}>
              {Object.entries(groups).map(([g, items]) => (
                <div key={g} className="mb-3"><h3 className="mb-1 text-xs font-semibold uppercase text-slate-500">{g}</h3>
                  <ul className="space-y-0.5 text-sm">{items.map((i, k) => <li key={k} className={cx("mono text-xs", CHANGE_COLOR[i.change])}>{i.id ? <Link className="hover:underline" to={i.id.match(/^[FA]-/) ? `/scans/${to}/findings/${i.id}` : `/scans/${to}/entity/${encodeURIComponent(i.id)}`}>{i.label}</Link> : i.label}</li>)}</ul></div>))}
            </Panel>
            <div><GraphView data={{ level: "repo", nodes: cmp.data.graph.nodes.map((n: any) => ({ id: n.id, type: "Module", label: n.label ?? n.id })), edges: cmp.data.graph.edges.map((e: any) => ({ ...e, type: "DEPENDS_ON", weight: 1 })) }}
              colorBy="status" statusOf={id => status[id]} height={420} /></div>
          </div>)}</QueryState>}
    </div>
  );
}
