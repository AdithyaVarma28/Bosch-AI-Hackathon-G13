import { useMemo, useState } from "react"
import { useSearchParams } from "react-router-dom"
import { Report, Severity } from "../api/types"
import { CvePanel } from "../components/CvePanel"
import { Card, DataTable, Drawer, EmptyState, Pagination, SeverityBadge, StatusBadge } from "../components/ui/ui"
import { dash, shortCommit } from "../model/format"
import { filterVulns, NO_FILTER, paginate, sortVulns, SortKey, VulnQuery, vulnRows } from "../model/vulns"
import { RunGate } from "./common"

const PAGE = 9
const SEVERITIES: (Severity | "All")[] = ["All", "Critical", "High", "Medium", "Low", "Unknown"]

function Body({ report, runId }: { report: Report; runId: string }) {
  const [params, setParams] = useSearchParams()
  const [q, setQ] = useState<VulnQuery>(NO_FILTER)
  const [sort, setSort] = useState<SortKey>("severity")
  const [page, setPage] = useState(1)
  const all = useMemo(() => vulnRows(report), [report])
  const rows = useMemo(() => sortVulns(filterVulns(all, q), sort), [all, q, sort])
  const pg = paginate(rows, page, PAGE)
  const selectedId = params.get("finding")
  const selected = selectedId ? report.findings.find((f) => f.id === selectedId) ?? null : null
  const counts = (s: Severity) => all.filter((r) => r.severity === s).length
  const upd = (patch: Partial<VulnQuery>) => { setQ({ ...q, ...patch }); setPage(1) }
  const open = (id: string | null) => setParams((p) => { const n = new URLSearchParams(p); id ? n.set("finding", id) : n.delete("finding"); return n })
  const statuses = ["All", ...Array.from(new Set(all.map((r) => r.status)))]

  return (
    <div className="space-y-4">
      <div className="flex gap-6 text-body text-textMuted">
        <span className="font-semibold text-textPrimary">{report.repo.name}</span>
        <span>Commit {shortCommit(report.repo.commit)}</span>
      </div>
      <Card>
        {all.length === 0 ? <EmptyState title="No vulnerabilities found" hint="The scan completed without matching any known advisories." /> : (
          <>
            <div className="flex flex-wrap items-center gap-3 mb-4 text-body">
              <input aria-label="Search vulnerabilities" placeholder="Search CVE, GHSA, or component…" className="border border-border rounded px-3 py-1.5 w-72" value={q.search} onChange={(e) => upd({ search: e.target.value })} />
              <select aria-label="Severity" className="border border-border rounded px-2 py-1.5" value={q.severity} onChange={(e) => upd({ severity: e.target.value as Severity | "All" })}>
                {SEVERITIES.map((s) => <option key={s}>{s}</option>)}
              </select>
              <select aria-label="Status" className="border border-border rounded px-2 py-1.5" value={q.status} onChange={(e) => upd({ status: e.target.value })}>
                {statuses.map((s) => <option key={s}>{s}</option>)}
              </select>
              <select aria-label="Dependency" className="border border-border rounded px-2 py-1.5" value={q.dependency} onChange={(e) => upd({ dependency: e.target.value as VulnQuery["dependency"] })}>
                {["All", "Direct", "Transitive"].map((s) => <option key={s}>{s}</option>)}
              </select>
              <button className="text-link" onClick={() => { setQ(NO_FILTER); setPage(1) }}>Clear filters</button>
              <span className="ml-auto text-textMuted">{rows.length} findings</span>
              <select aria-label="Sort by" className="border border-border rounded px-2 py-1.5" value={sort} onChange={(e) => setSort(e.target.value as SortKey)}>
                <option value="severity">Sort: Severity</option><option value="cvss">Sort: CVSS</option><option value="band">Sort: Priority</option>
              </select>
            </div>
            <div className="flex gap-2 mb-3 text-label">
              {(["Critical", "High", "Medium", "Low", "Unknown"] as Severity[]).filter((s) => counts(s) > 0).map((s) => <SeverityBadge key={s} severity={s}>{counts(s)} {s}</SeverityBadge>)}
            </div>
            {rows.length === 0 ? <EmptyState title="No findings match these filters" /> : (
              <>
                <DataTable
                  rowKey={(r) => r.id}
                  onRowClick={(r) => open(r.id)}
                  rows={pg.items}
                  columns={[
                    { key: "id", header: "Vulnerability", render: (r) => <div><p className="font-medium text-link">{r.advisoryId}</p><p className="text-label text-textMuted">{r.summary}</p></div> },
                    { key: "comp", header: "Component", render: (r) => r.component },
                    { key: "inst", header: "Installed", render: (r) => dash(r.installed) },
                    { key: "fix", header: "Fixed", render: (r) => dash(r.fixed) },
                    { key: "sev", header: "Severity", render: (r) => <SeverityBadge severity={r.severity} /> },
                    { key: "cvss", header: "CVSS", render: (r) => dash(r.cvss) },
                    { key: "dep", header: "Dependency", render: (r) => r.dependency },
                    { key: "st", header: "Status", render: (r) => <StatusBadge status={r.status} /> },
                  ]}
                />
                <Pagination page={pg.page} pages={pg.pages} from={pg.from} to={pg.to} total={pg.total} onChange={setPage} />
              </>
            )}
          </>
        )}
      </Card>
      <Drawer open={!!selected} onClose={() => open(null)} label="Vulnerability details">
        {selected && <CvePanel finding={selected} runId={runId} />}
      </Drawer>
    </div>
  )
}

export default function Vulnerabilities() {
  return <RunGate title="Vulnerabilities" subtitle="Triage and investigate vulnerabilities across your dependencies.">{({ report, runId }) => <Body report={report} runId={runId} />}</RunGate>
}
