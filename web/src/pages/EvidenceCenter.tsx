import { useMemo, useState } from "react"
import { Link, useSearchParams } from "react-router-dom"
import { Report } from "../api/types"
import { Card, DataTable, Drawer, EmptyState, Pagination } from "../components/ui/ui"
import { evidenceCitedBy, EvidenceFilter, EvidenceRow, evidenceRows, filterEvidence } from "../model/evidence"
import { dash } from "../model/format"
import { paginate } from "../model/vulns"
import { RunGate } from "./common"

const sel = "border border-border rounded px-2 py-1.5"
const PAGE = 10

function Detail({ row, report, runId }: { row: EvidenceRow; report: Report; runId: string }) {
  const cited = evidenceCitedBy(report, row.id)
  return (
    <div className="space-y-4 p-6 text-body">
      <div><p className="text-micro font-semibold text-textFaint">EVIDENCE · {row.kind.toUpperCase()}</p><h2 className="text-page font-semibold break-all">{dash(row.locator)}</h2><p className="text-textMuted">{row.source}</p></div>
      <section><h3 className="mb-1 font-semibold">Excerpt</h3><pre className="max-h-72 overflow-auto whitespace-pre-wrap rounded bg-page p-3 text-label">{row.excerpt || "—"}</pre></section>
      <dl className="grid grid-cols-[120px_1fr] gap-y-1">
        <dt className="text-textMuted">SHA-256</dt><dd className="break-all font-mono text-label">{dash(row.sha256)}</dd>
        <dt className="text-textMuted">Captured</dt><dd>{dash(row.capturedAt)}</dd>
        <dt className="text-textMuted">Evidence id</dt><dd className="font-mono text-label">{row.id}</dd>
      </dl>
      <section>
        <h3 className="mb-1 font-semibold">Cited by</h3>
        {cited.length === 0 ? <p className="text-textMuted">No finding cites this evidence.</p> : (
          <ul className="space-y-1">
            {cited.map((c) => (
              <li key={c.findingId}>{c.href ? <Link className="text-link" to={`${c.href}&run=${encodeURIComponent(runId)}`}>{c.title}</Link> : <span>{c.title}</span>}</li>
            ))}
          </ul>
        )}
      </section>
    </div>
  )
}

function Body({ report, runId }: { report: Report; runId: string }) {
  const [params, setParams] = useSearchParams()
  const [q, setQ] = useState<EvidenceFilter>({ search: "", kind: "All" })
  const [page, setPage] = useState(1)
  const all = useMemo(() => evidenceRows(report), [report])
  const rows = useMemo(() => filterEvidence(all, q), [all, q])
  const pg = paginate(rows, page, PAGE)
  const kinds = ["All", ...Array.from(new Set(all.map((r) => r.kind)))]
  const open = all.find((r) => r.id === params.get("evidence")) ?? null
  const setOpen = (id: string | null) => setParams((p) => { const n = new URLSearchParams(p); id ? n.set("evidence", id) : n.delete("evidence"); return n })
  const upd = (patch: Partial<EvidenceFilter>) => { setQ({ ...q, ...patch }); setPage(1) }

  return (
    <>
      <Card title="Evidence">
        {all.length === 0 ? <EmptyState title="No evidence was recorded for this run" /> : (
          <>
            <div className="mb-4 flex flex-wrap items-center gap-3 text-body">
              <input aria-label="Search evidence" placeholder="Search locator, source or excerpt…" className={`${sel} w-72`} value={q.search} onChange={(e) => upd({ search: e.target.value })} />
              <select aria-label="Kind" className={sel} value={q.kind} onChange={(e) => upd({ kind: e.target.value })}>{kinds.map((k) => <option key={k}>{k}</option>)}</select>
              <span className="ml-auto text-textMuted">{rows.length} of {all.length} evidence items</span>
            </div>
            {rows.length === 0 ? <EmptyState title="No evidence matches these filters" /> : (
              <>
                <DataTable
                  rowKey={(r) => r.id}
                  onRowClick={(r) => setOpen(r.id)}
                  rows={pg.items}
                  columns={[
                    { key: "loc", header: "Locator", render: (r) => <span className="font-medium text-link break-all">{r.locator}</span> },
                    { key: "src", header: "Source", render: (r) => r.source },
                    { key: "kind", header: "Kind", render: (r) => r.kind },
                    { key: "cited", header: "Cited by", render: (r) => `${r.citedBy} finding${r.citedBy === 1 ? "" : "s"}` },
                  ]}
                />
                <Pagination page={pg.page} pages={pg.pages} from={pg.from} to={pg.to} total={pg.total} onChange={setPage} noun="evidence items" />
              </>
            )}
          </>
        )}
      </Card>
      <Drawer open={!!open} onClose={() => setOpen(null)} label="Evidence details">{open && <Detail row={open} report={report} runId={runId} />}</Drawer>
    </>
  )
}

export default function EvidenceCenter() {
  return <RunGate title="Evidence Center" subtitle="The raw evidence behind every finding, with where it came from.">{({ report, runId }) => <Body report={report} runId={runId} />}</RunGate>
}
