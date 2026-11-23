import { useMemo, useState } from "react"
import { useSearchParams } from "react-router-dom"
import { Report } from "../api/types"
import { Card, DataTable, Drawer, EmptyState, Pagination } from "../components/ui/ui"
import { dash } from "../model/format"
import { paginate } from "../model/vulns"
import { filterSbom, NO_SBOM_FILTER, SbomFilter, SbomRow, sbomModel } from "../model/sbom"
import { RunGate } from "./common"

const sel = "border border-border rounded px-2 py-1.5"
const PAGE = 10

function Detail({ row }: { row: SbomRow }) {
  return (
    <div className="space-y-4 p-6 text-body">
      <div><p className="text-micro font-semibold text-textFaint">SBOM COMPONENT</p><h2 className="text-page font-semibold">{row.name}</h2><p className="font-mono text-label text-textMuted break-all">{row.purl}</p></div>
      <dl className="grid grid-cols-[140px_1fr] gap-y-2">
        <dt className="text-textMuted">Version</dt><dd>{dash(row.version)}</dd>
        <dt className="text-textMuted">Ecosystem</dt><dd>{row.ecosystem}</dd>
        <dt className="text-textMuted">Scope</dt><dd>{row.scope}</dd>
        <dt className="text-textMuted">Dependency type</dt><dd>{row.dependency}</dd>
        <dt className="text-textMuted">Found in</dt><dd>{row.seenBy.length ? row.seenBy.join(", ") : row.source}</dd>
        <dt className="text-textMuted">Registry</dt><dd>{dash(row.registry)}</dd>
        <dt className="text-textMuted">Resolved URL</dt><dd className="break-all">{dash(row.resolvedUrl)}</dd>
        <dt className="text-textMuted">License</dt><dd>{dash(row.license)}</dd>
        <dt className="text-textMuted">Install script</dt><dd>{row.hasInstallScript ? "Yes" : "No"}</dd>
        <dt className="text-textMuted">Integrity</dt><dd className="break-all font-mono text-label">{dash(row.integrity)}</dd>
      </dl>
    </div>
  )
}

function Body({ report, runId }: { report: Report; runId: string }) {
  const [params, setParams] = useSearchParams()
  const [q, setQ] = useState<SbomFilter>(NO_SBOM_FILTER)
  const [page, setPage] = useState(1)
  const { rows: all, summary } = useMemo(() => sbomModel(report), [report])
  const rows = useMemo(() => filterSbom(all, q), [all, q])
  const pg = paginate(rows, page, PAGE)
  const ecosystems = ["All", ...Array.from(new Set(all.map((r) => r.ecosystem)))]
  const openPurl = params.get("component")
  const open = all.find((r) => r.purl === openPurl) ?? null
  const setOpen = (purl: string | null) => setParams((p) => { const n = new URLSearchParams(p); purl ? n.set("component", purl) : n.delete("component"); return n })
  const upd = (patch: Partial<SbomFilter>) => { setQ({ ...q, ...patch }); setPage(1) }
  const failedTools = summary.tools.filter((t) => !t.ok)

  return (
    <div className="space-y-4">
      <div data-testid="sbom-summary" className="grid grid-cols-4 gap-4">
        {[[summary.count, "Components"], [summary.direct, "Direct"], [summary.transitive, "Transitive"], [summary.confidence, "Confidence"]].map(([n, l]) => (
          <div key={String(l)} className="rounded-md border border-border bg-surface p-4"><span className="text-kpi font-semibold">{n}</span><span className="block text-body text-textMuted">{l}</span></div>
        ))}
      </div>
      {(failedTools.length > 0 || summary.notes.length > 0 || summary.confidence === "low") && (
        <div className="rounded border border-border px-4 py-3 text-body" style={{ backgroundColor: "#fffaeb", color: "#b54708" }}>
          <p className="font-semibold">How this SBOM was built</p>
          <p>Resolution: {summary.resolution}</p>
          <ul className="list-disc pl-5">
            {failedTools.map((t) => <li key={t.name}>{t.name}: {t.detail}</li>)}
            {summary.notes.map((n) => <li key={n}>{n}</li>)}
          </ul>
        </div>
      )}
      <Card
        title="Components"
        action={<a className="text-link text-body" href={`/runs/${encodeURIComponent(runId)}/sbom`} target="_blank" rel="noreferrer">Download CycloneDX (JSON)</a>}
      >
        {all.length === 0 ? <EmptyState title="No components in this SBOM" /> : (
          <>
            <div className="mb-4 flex flex-wrap items-center gap-3 text-body">
              <input aria-label="Search components" placeholder="Search name or package URL…" className={`${sel} w-72`} value={q.search} onChange={(e) => upd({ search: e.target.value })} />
              <select aria-label="Ecosystem" className={sel} value={q.ecosystem} onChange={(e) => upd({ ecosystem: e.target.value })}>{ecosystems.map((x) => <option key={x}>{x}</option>)}</select>
              <select aria-label="Scope" className={sel} value={q.scope} onChange={(e) => upd({ scope: e.target.value as SbomFilter["scope"] })}>{["All", "Production", "Development"].map((x) => <option key={x}>{x}</option>)}</select>
              <select aria-label="Dependency type" className={sel} value={q.dependency} onChange={(e) => upd({ dependency: e.target.value as SbomFilter["dependency"] })}>{["All", "Direct", "Transitive"].map((x) => <option key={x}>{x}</option>)}</select>
              <span className="ml-auto text-textMuted">{rows.length} of {all.length} components</span>
            </div>
            {rows.length === 0 ? <EmptyState title="No components match these filters" /> : (
              <>
                <DataTable
                  rowKey={(r) => r.purl}
                  onRowClick={(r) => setOpen(r.purl)}
                  rows={pg.items}
                  columns={[
                    { key: "name", header: "Component", render: (r) => <div><p className="font-medium text-link">{r.name}</p><p className="font-mono text-label text-textMuted">{r.purl}</p></div> },
                    { key: "ver", header: "Version", render: (r) => dash(r.version) },
                    { key: "eco", header: "Ecosystem", render: (r) => r.ecosystem },
                    { key: "scope", header: "Scope", render: (r) => r.scope },
                    { key: "dep", header: "Type", render: (r) => r.dependency },
                    { key: "src", header: "Source", render: (r) => r.source },
                  ]}
                />
                <Pagination page={pg.page} pages={pg.pages} from={pg.from} to={pg.to} total={pg.total} onChange={setPage} noun="components" />
              </>
            )}
          </>
        )}
      </Card>
      <Drawer open={!!open} onClose={() => setOpen(null)} label="Component details">{open && <Detail row={open} />}</Drawer>
    </div>
  )
}

export default function SbomExplorer() {
  return <RunGate title="SBOM Explorer" subtitle="Browse every component in the software bill of materials.">{({ report, runId }) => <Body report={report} runId={runId} />}</RunGate>
}
