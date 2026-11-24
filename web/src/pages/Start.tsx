import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Play } from "lucide-react";
import { useScans, useStartScan } from "../api";
import { EmptyState, Panel, QueryState, RiskChip, Spinner } from "../components/ui";

export default function Start() {
  const scans = useScans();
  const start = useStartScan();
  const nav = useNavigate();
  const [path, setPath] = useState("");
  const [offline, setOffline] = useState(false);
  const demo = (scans.data ?? []).find(s => s.scan_id === "demo-minishop-head");
  return (
    <div className="mx-auto max-w-5xl px-6 py-10">
      <h1 className="mb-1 flex items-center gap-2 text-3xl font-bold"><span className="grid h-9 w-9 place-items-center rounded bg-indigo-600 text-white">◆</span>Guardian</h1>
      <p className="mb-8 text-slate-500">Supply-chain intelligence for Python repositories: what is in it, what changed, what looks risky.</p>
      <div className="mb-8 grid gap-4 md:grid-cols-2">
        <Panel title="Scan a repository">
          <p className="mb-3 text-xs text-slate-500">Paste a public GitHub link and Guardian clones it, then scans it. Guardian analyses Python code, so a JavaScript or TypeScript repository will show little.</p>
          <form className="space-y-3" onSubmit={e => { e.preventDefault(); start.mutate({ path, offline }, { onSuccess: r => nav(`/scans/${r.scan_id}/progress`) }); }}>
            <input value={path} onChange={e => setPath(e.target.value)} required placeholder="GitHub link (https://github.com/owner/repo) or a local path"
              className="w-full rounded-md border border-slate-300 bg-transparent px-3 py-2 text-sm dark:border-slate-700" aria-label="GitHub repository link or local path" />
            <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={offline} onChange={e => setOffline(e.target.checked)} />Offline (no OSV, PyPI or LLM calls)</label>
            <button disabled={start.isPending} className="inline-flex items-center gap-2 rounded-md bg-indigo-600 px-3 py-2 text-sm font-medium text-white disabled:opacity-60">{start.isPending ? <Spinner /> : <Play className="h-4 w-4" />}Run live scan</button>
            {start.error && <p className="text-sm text-red-600">{String((start.error as Error).message)}</p>}
          </form>
        </Panel>
        <Panel title="Demo">
          <p className="mb-3 text-sm text-slate-600 dark:text-slate-300">A completed, stored mini-shop scan (baseline + HEAD). Opens instantly, with no network.</p>
          {demo ? <Link to={`/scans/${demo.scan_id}`} className="inline-flex rounded-md bg-slate-900 px-3 py-2 text-sm font-medium text-white dark:bg-slate-700">Open demo scan</Link>
            : <p className="text-sm text-slate-500">Not built yet: run <code className="rounded bg-slate-100 px-1 dark:bg-slate-800">guardian demo</code>.</p>}
        </Panel>
      </div>
      <Panel title="Past scans">
        <QueryState q={scans}>{() => (scans.data!.length === 0 ? <EmptyState title="No scans yet. Try the demo repository." /> :
          <table className="w-full text-sm">
            <thead className="text-left text-xs uppercase text-slate-500"><tr><th className="py-2">Repository</th><th>Commit</th><th>Date</th><th>Findings by risk</th><th>Status</th></tr></thead>
            <tbody>{scans.data!.map(s => (
              <tr key={s.scan_id} className="border-t border-slate-100 dark:border-slate-800">
                <td className="py-2"><Link className="font-medium text-indigo-700 hover:underline dark:text-indigo-300" to={`/scans/${s.scan_id}${s.status === "running" ? "/progress" : ""}`}>{s.repo}</Link> <span className="text-xs text-slate-400">{s.label ?? s.scan_id}</span></td>
                <td className="mono text-xs">{(s.commit ?? "").slice(0, 7)}</td>
                <td className="text-xs">{(s.created_at ?? "").slice(0, 16).replace("T", " ")}</td>
                <td className="space-x-1">{(["critical", "high", "medium", "low"] as const).map(r => s.findings[r] ? <span key={r} className="inline-flex items-center gap-0.5"><RiskChip risk={r} />{s.findings[r]}</span> : null)}</td>
                <td className="text-xs">{s.status}{s.pending_reviews ? ` · ${s.pending_reviews} to review` : ""}</td>
              </tr>))}</tbody>
          </table>)}</QueryState>
      </Panel>
    </div>
  );
}
