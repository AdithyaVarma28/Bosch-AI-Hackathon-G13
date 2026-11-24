import { useMemo, useState } from "react"
import { Link } from "react-router-dom"
import { Band, Report } from "../api/types"
import { Card, DataTable, EmptyState, Pagination } from "../components/ui/ui"
import { CLASS_LABEL, filterRisk, RiskFilter, riskModel } from "../model/risk"
import { paginate } from "../model/vulns"
import { RunGate } from "./common"

const sel = "border border-border rounded px-2 py-1.5"
const PAGE = 10

function Body({ report, runId }: { report: Report; runId: string }) {
  const m = useMemo(() => riskModel(report), [report])
  const [q, setQ] = useState<RiskFilter>({ band: "All", cls: "All", search: "" })
  const [page, setPage] = useState(1)
  const rows = useMemo(() => filterRisk(m.rows, q), [m, q])
  const pg = paginate(rows, page, PAGE)
  const upd = (patch: Partial<RiskFilter>) => { setQ({ ...q, ...patch }); setPage(1) }
  const classes = Array.from(new Set(m.rows.map((r) => r.cls)))

  return (
    <div className="space-y-4">
      <div data-testid="risk-bands" className="grid grid-cols-4 gap-4">
        {m.bands.map((b) => (
          <button key={b.band} aria-pressed={q.band === b.band} onClick={() => upd({ band: q.band === b.band ? "All" : (b.band as Band) })}
            className={`rounded-md border bg-surface p-4 text-left ${q.band === b.band ? "border-link" : "border-border"}`}>
            <span className="text-kpi font-semibold">{b.count}</span><span className="block text-body text-textMuted">{b.band}</span>
          </button>
        ))}
      </div>
      {m.disclaimer && <div className="rounded border border-border px-4 py-3 text-body" style={{ backgroundColor: "#fffaeb", color: "#b54708" }}>{m.disclaimer}</div>}
      <Card title="Findings by priority">
        {m.rows.length === 0 ? <EmptyState title="No findings to prioritise" /> : (
          <>
            <div className="mb-4 flex flex-wrap items-center gap-3 text-body">
              <input aria-label="Search findings" placeholder="Search finding, subject or reason…" className={`${sel} w-72`} value={q.search} onChange={(e) => upd({ search: e.target.value })} />
              <select aria-label="Class" className={sel} value={q.cls} onChange={(e) => upd({ cls: e.target.value })}>
                <option value="All">All</option>{classes.map((c) => <option key={c} value={c}>{CLASS_LABEL[c] ?? c}</option>)}
              </select>
              <span className="ml-auto text-textMuted">{rows.length} of {m.rows.length} findings</span>
            </div>
            {rows.length === 0 ? <EmptyState title="No findings match these filters" /> : (
              <>
                <DataTable
                  rowKey={(r) => r.id}
                  rows={pg.items}
                  columns={[
                    { key: "band", header: "Priority", render: (r) => <span className="font-semibold">{r.band}</span> },
                    { key: "title", header: "Finding", render: (r) => r.href ? <Link className="text-link" to={`${r.href}&run=${encodeURIComponent(runId)}`}>{r.title}</Link> : <span>{r.title}</span> },
                    { key: "cls", header: "Class", render: (r) => r.classLabel },
                    { key: "why", header: "Why this priority", render: (r) => <span className="text-textSecondary">{r.reason || "—"}</span> },
                  ]}
                />
                <Pagination page={pg.page} pages={pg.pages} from={pg.from} to={pg.to} total={pg.total} onChange={setPage} />
              </>
            )}
          </>
        )}
      </Card>
    </div>
  )
}

export default function RiskPrioritization() {
  return <RunGate title="Risk Prioritization" subtitle="Triage order for every finding, with the reason for its priority.">{({ report, runId }) => <Body report={report} runId={runId} />}</RunGate>
}
