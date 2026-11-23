import { useEffect, useState } from "react"
import { useSearchParams } from "react-router-dom"
import { getEvidence } from "../api/client"
import { Evidence, Report } from "../api/types"
import { Card, EmptyState, StatusBadge } from "../components/ui/ui"
import { anomalyCounts, AnomalyItem, anomalyItems } from "../model/anomalies"
import { dash, shortCommit } from "../model/format"
import { RunGate } from "./common"

function EvidenceList({ runId, ids }: { runId: string; ids: string[] }) {
  const [items, setItems] = useState<(Evidence | null)[]>([])
  useEffect(() => {
    let live = true
    Promise.all(ids.map(async (id) => { try { return await getEvidence(runId, id) } catch { return null } })).then((r) => live && setItems(r))
    return () => { live = false }
  }, [runId, ids.join(",")])
  if (ids.length === 0) return <p className="text-body text-textMuted">No evidence recorded.</p>
  return (
    <ul className="space-y-2 text-body">
      {items.map((e, i) => e ? (
        <li key={e.id}><p className="font-medium">{dash(e.locator)}</p><pre className="whitespace-pre-wrap rounded bg-page p-2 text-label">{e.excerpt}</pre></li>
      ) : <li key={i} className="text-textMuted">Evidence could not be loaded.</li>)}
    </ul>
  )
}

function Detail({ item, runId, scanCommit }: { item: AnomalyItem; runId: string; scanCommit: string | null }) {
  const d = item.detail
  return (
    <Card title={item.title} subtitle={item.subtitle} action={<StatusBadge status={item.status} />}>
      <div className="space-y-4 text-body">
        <section>
          <h3 className="font-semibold mb-1">What changed</h3>
          <dl className="grid grid-cols-[80px_1fr] gap-y-1">
            <dt className="text-textMuted">File</dt><dd>{dash(d.file)}</dd>
            <dt className="text-textMuted">Commit</dt><dd>{shortCommit(d.commit)}</dd>
          </dl>
          {d.diff && (
            <div className="mt-2 rounded border border-border font-mono text-label">
              <p className="bg-accentSoft px-2 py-1"><span className="text-textMuted">Previous </span>{d.diff.previous}</p>
              <p className="px-2 py-1" style={{ backgroundColor: "#ecfdf3" }}><span className="text-textMuted">Current </span>{d.diff.current}</p>
            </div>
          )}
        </section>
        <section><h3 className="font-semibold mb-1">Detection rationale</h3><p className="text-textSecondary">{dash(d.rationale)}</p></section>
        {!d.diff && <section><h3 className="font-semibold mb-1">Supporting evidence</h3><EvidenceList runId={runId} ids={d.evidenceIds} /></section>}
        <p className="text-label text-textMuted border-t border-border pt-2">Baseline {shortCommit(d.baseline)} · Scan {shortCommit(scanCommit)}</p>
      </div>
    </Card>
  )
}

function Body({ report, runId }: { report: Report; runId: string }) {
  const [params, setParams] = useSearchParams()
  const [tab, setTab] = useState<"all" | "new">("all")
  const all = anomalyItems(report)
  const counts = anomalyCounts(all)
  const items = tab === "new" ? all.filter((i) => i.status === "New") : all
  const baseline = all[0]?.detail.baseline ?? null
  const sel = params.get("signal")
  const selected = items.find((i) => i.id === sel) ?? items[0] ?? null
  const select = (id: string) => setParams((p) => { const n = new URLSearchParams(p); n.set("signal", id); return n })

  return (
    <div className="space-y-4">
      <div className="flex gap-6 text-body text-textMuted">
        <span className="font-semibold text-textPrimary">{report.repo.name}</span>
        {baseline && <span>Comparing {shortCommit(baseline)} → {shortCommit(report.repo.commit)}</span>}
      </div>
      <div className="rounded border border-border px-4 py-3 text-body" style={{ backgroundColor: "#fffaeb", color: "#b54708" }}>
        <strong>Signals are not confirmed threats.</strong> Review each change in context before acting.
      </div>
      {all.length === 0 ? <Card><EmptyState title="No suspicious changes detected" /></Card> : (
        <div className="grid grid-cols-[1fr_1.4fr] gap-4">
          <Card title="Detected changes">
            <div className="flex gap-4 mb-3 text-body">
              <button className={tab === "all" ? "font-semibold" : "text-textMuted"} onClick={() => setTab("all")}>All signals {counts.all}</button>
              <button className={tab === "new" ? "font-semibold" : "text-textMuted"} onClick={() => setTab("new")}>New {counts.new}</button>
            </div>
            <ul className="space-y-1">
              {items.map((i) => (
                <li key={i.id}>
                  <button className={`w-full text-left rounded border p-2 ${i.id === selected?.id ? "border-link bg-[#f8fafd]" : "border-border"}`} onClick={() => select(i.id)}>
                    <p className="text-body font-medium">{i.title}</p>
                    <p className="text-label text-textMuted truncate">{i.subtitle}</p>
                    <div className="mt-1 flex gap-2 text-label"><span>{i.band}</span><StatusBadge status={i.status} /></div>
                  </button>
                </li>
              ))}
            </ul>
          </Card>
          {selected && <Detail item={selected} runId={runId} scanCommit={report.repo.commit} />}
        </div>
      )}
    </div>
  )
}

export default function AnomalyDetection() {
  return <RunGate title="Anomaly Detection" subtitle="Review changes that look unusual in your software supply chain.">{({ report, runId }) => <Body report={report} runId={runId} />}</RunGate>
}
