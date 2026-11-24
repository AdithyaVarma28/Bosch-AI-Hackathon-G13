// Review queue: findings paused by the workflow; list left, evidence right, the next item loads after a decision.
import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { useReviewQueue } from "../api";
import { EmptyState, PageHeader, QueryState, RiskChip, cx } from "../components/ui";
import Finding from "./Finding";

export default function Review() {
  const { scanId = "" } = useParams();
  const q = useReviewQueue(scanId);
  const [sel, setSel] = useState<string | null>(null);
  const items = q.data ?? [];
  useEffect(() => { if (items.length && (!sel || !items.some(i => i.finding_id === sel))) setSel(items[0].finding_id); }, [items]);
  return (
    <div>
      <PageHeader crumbs={[{ label: "Overview", to: `/scans/${scanId}` }, { label: "Review queue" }]} title="Review queue" />
      <QueryState q={q}>{() => items.length === 0 ? <EmptyState title="Nothing is waiting for a human decision." /> : (
        <div className="grid gap-4 xl:grid-cols-[280px_1fr]">
          <ul className="space-y-1">{items.map(i => (
            <li key={i.finding_id}><button onClick={() => setSel(i.finding_id)} className={cx("w-full rounded-lg border p-2 text-left text-sm", sel === i.finding_id ? "border-indigo-400 bg-indigo-50 dark:bg-slate-800" : "border-slate-200 dark:border-slate-700")}>
              <div className="flex items-center gap-2"><RiskChip risk={i.project_risk} /><b>{i.finding_id}</b></div>
              <div className="truncate">{i.title}</div><div className="text-xs text-slate-500">{(i.reasons ?? []).join("; ")}</div></button></li>))}</ul>
          <div className="min-w-0">{sel && <Finding key={sel} fid={sel} />}</div>
        </div>)}</QueryState>
    </div>
  );
}
