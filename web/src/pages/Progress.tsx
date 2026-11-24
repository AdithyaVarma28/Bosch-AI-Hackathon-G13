// Scan progress: stage stepper + live investigation activity feed (SSE). Actions and results only.
import { useEffect, useRef, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { CheckCircle2, Circle, Loader2, XCircle } from "lucide-react";
import { useQueryClient } from "@tanstack/react-query";
import { useScan } from "../api";
import { PageHeader, Panel, cx } from "../components/ui";

const STAGES = [["1", "Facts"], ["2", "Code index"], ["3", "Knowledge graph (3A–3D)"], ["4", "Vulnerabilities"], ["5", "Anomalies"]];

export default function Progress() {
  const { scanId = "" } = useParams();
  const scan = useScan(scanId);
  const qc = useQueryClient();
  const nav = useNavigate();
  const [events, setEvents] = useState<any[]>([]);
  const [done, setDone] = useState(false);
  const box = useRef<HTMLDivElement>(null);
  useEffect(() => {
    setEvents([]);
    const es = new EventSource(`/api/scans/${scanId}/progress/events`);
    es.onmessage = m => {
      const e = JSON.parse(m.data);
      if (e.type === "end") { es.close(); setDone(true); qc.invalidateQueries(); return; }
      setEvents(prev => [...prev, e]);
      if (e.type === "stage") qc.invalidateQueries({ queryKey: ["scan", scanId] });
    };
    es.onerror = () => es.close();
    return () => es.close();
  }, [scanId]);
  useEffect(() => { box.current?.scrollTo({ top: box.current.scrollHeight }); }, [events.length]);
  const stageState: Record<string, any> = {};
  for (const e of events) if (e.type === "stage" && /^[1-5]$/.test(String(e.stage))) stageState[e.stage] = { ...stageState[e.stage], ...e };
  const meta = scan.data?.stages ?? {};
  const failed = events.some(e => e.type === "done" && e.status === "failed");
  useEffect(() => { if (done && !failed && events.some(e => e.type === "done")) { const t = setTimeout(() => nav(`/scans/${scanId}`), 2500); return () => clearTimeout(t); } }, [done]);
  const feed = events.filter(e => e.type === "activity" || e.type === "log" || e.type === "error" || (e.type === "stage" && !/^[1-5]$/.test(String(e.stage))));
  return (
    <div>
      <PageHeader crumbs={[{ label: "Scans", to: "/" }, { label: scanId }]} title="Scan progress" />
      <div className="grid gap-4 lg:grid-cols-[280px_1fr]">
        <Panel title="Stages">
          <ol className="space-y-3">{STAGES.map(([k, name]) => {
            const st = stageState[k]?.status ?? meta[k]?.status ?? (scan.data?.status === "done" ? "done" : "pending");
            const Icon = st === "done" ? CheckCircle2 : st === "running" ? Loader2 : st === "failed" ? XCircle : Circle;
            return <li key={k} className="flex gap-2"><Icon className={cx("mt-0.5 h-4 w-4", st === "running" && "animate-spin text-indigo-600", st === "done" && "text-emerald-600", st === "failed" && "text-red-600")} />
              <div><div className="text-sm font-medium">Stage {k}: {name}</div><div className="text-xs text-slate-500">{stageState[k]?.summary ?? meta[k]?.summary ?? st}{meta[k]?.duration_s ? ` · ${meta[k].duration_s}s` : ""}</div>
                {st === "done" && k === "3" && <Link className="text-xs text-indigo-700 underline" to={`/scans/${scanId}/map`}>Open map</Link>}
                {st === "done" && (k === "4" || k === "5") && <Link className="text-xs text-indigo-700 underline" to={`/scans/${scanId}/findings`}>Open findings</Link>}</div></li>;
          })}</ol>
          {done && <p className="mt-4 text-sm">{failed ? "The scan failed; see the feed." : <>Done. <Link className="text-indigo-700 underline" to={`/scans/${scanId}`}>Go to overview</Link></>}</p>}
        </Panel>
        <Panel title="Live investigation activity">
          <div ref={box} className="max-h-[60vh] space-y-1.5 overflow-y-auto text-sm">
            {feed.length === 0 && <p className="text-slate-500">Waiting for activity…</p>}
            {feed.map((e, i) => (
              <div key={i} className={cx("rounded px-2 py-1", e.type === "error" ? "bg-red-50 text-red-800" : e.type === "activity" ? "bg-slate-50 dark:bg-slate-800/60" : "text-slate-500")}>
                {e.type === "activity" ? <><b>{e.action}</b>{e.vuln_id ? <span className="text-slate-500"> · {e.vuln_id} {e.package}</span> : e.stage5_subject ? <span className="text-slate-500"> · {e.stage5_subject}</span> : null} → {e.result}</>
                  : e.type === "stage" ? <>Stage {e.stage}: {e.status} {e.deep != null ? `(${e.deep} deep, ${e.light} light)` : e.matches != null ? `(${e.matches} matches)` : e.signals != null ? `(${e.signals} signals)` : ""}</>
                  : <span className="mono text-xs">{e.message}</span>}
              </div>))}
          </div>
        </Panel>
      </div>
    </div>
  );
}
