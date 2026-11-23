import { useState } from "react"
import { Link } from "react-router-dom"
import { PageHeader } from "../components/layout/Shell"
import { Card, DataTable, EmptyState, ErrorBanner, Skeleton, StatusBadge } from "../components/ui/ui"
import { useRuns } from "../hooks/hooks"
import { relativeTime } from "../model/format"
import { filterRuns, RunFilter, runRows } from "../model/runs"

const sel = "border border-border rounded px-2 py-1.5"

export default function Repositories() {
  const runs = useRuns()
  const [q, setQ] = useState<RunFilter>({ search: "", status: "All" })
  const head = <PageHeader title="Repositories" subtitle="Every scan this workspace has run." />
  if (runs.state === "loading") return <>{head}<Skeleton /></>
  if (runs.state === "error") return <>{head}<ErrorBanner error={runs.error} /></>
  const all = runRows(runs.data)
  const rows = filterRuns(all, q)

  return (
    <>
      {head}
      <Card>
        {all.length === 0 ? <EmptyState title="No scans yet" hint="Start a scan to see it here." /> : (
          <>
            <div className="mb-4 flex flex-wrap items-center gap-3 text-body">
              <input aria-label="Search repositories" placeholder="Search repository, source or run id…" className={`${sel} w-72`} value={q.search} onChange={(e) => setQ({ ...q, search: e.target.value })} />
              <select aria-label="Status" className={sel} value={q.status} onChange={(e) => setQ({ ...q, status: e.target.value as RunFilter["status"] })}>
                {["All", "Completed", "Failed", "Running"].map((s) => <option key={s}>{s}</option>)}
              </select>
              <span className="ml-auto text-textMuted">{rows.length} of {all.length} scans</span>
            </div>
            {rows.length === 0 ? <EmptyState title="No scans match these filters" /> : (
              <DataTable
                rowKey={(r) => r.id}
                rows={rows}
                columns={[
                  { key: "name", header: "Repository", render: (r) => (
                    <div><p className="font-medium text-textPrimary">{r.name}</p><p className="break-all text-label text-textMuted">{r.target}</p>
                      {r.error && <p className="text-label" style={{ color: "#b42318" }}>{r.error}</p>}</div>) },
                  { key: "status", header: "Status", render: (r) => <StatusBadge status={r.status} /> },
                  { key: "commit", header: "Commit", render: (r) => r.commit },
                  { key: "when", header: "Finished", render: (r) => relativeTime(r.finishedAt) },
                  { key: "id", header: "Run", render: (r) => <span className="font-mono text-label">{r.id}</span> },
                  { key: "open", header: "", render: (r) => r.canOpen ? <Link className="text-link font-medium" to={`/?run=${encodeURIComponent(r.id)}`}>Open</Link> : null },
                ]}
              />
            )}
          </>
        )}
      </Card>
    </>
  )
}
