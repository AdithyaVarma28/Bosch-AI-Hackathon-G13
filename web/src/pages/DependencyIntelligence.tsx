import { useMemo, useState } from "react"
import { Link, useSearchParams } from "react-router-dom"
import { Report, Severity, VizGraph } from "../api/types"
import { DependencyGraph } from "../components/graph/DependencyGraph"
import { Card, EmptyState, SeverityBadge } from "../components/ui/ui"
import { componentDetails, componentNodes, defaultSelection, focusGraph, GraphFilters, NO_GRAPH_FILTER, Scope } from "../model/graph"
import { dash, shortCommit } from "../model/format"
import { overviewModel, relationshipCount } from "../model/overview"
import { RunGate } from "./common"

const sel = "border border-border rounded px-2 py-1.5"

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return <section className="border-t border-border pt-3"><h3 className="font-semibold mb-1">{title}</h3>{children}</section>
}
function List({ items, empty = "—" }: { items: string[]; empty?: string }) {
  return items.length === 0 ? <p className="text-textMuted">{empty}</p> : <ul className="font-mono text-label space-y-0.5">{items.map((x) => <li key={x}>{x}</li>)}</ul>
}

function Body({ report, viz, runId }: { report: Report; viz: VizGraph; runId: string }) {
  const [params, setParams] = useSearchParams()
  const [filters, setFilters] = useState<GraphFilters>(NO_GRAPH_FILTER)
  const selected = params.get("component") ?? defaultSelection(report.findings)
  const select = (id: string) => setParams((p) => { const n = new URLSearchParams(p); n.set("component", id); return n })
  const graph = useMemo(() => focusGraph(viz, report.findings, selected, filters), [viz, report, selected, filters])
  const d = selected ? componentDetails(viz, report.findings, selected) : null
  const ecosystems = ["All", ...Array.from(new Set(componentNodes(viz).map((n) => n.ecosystem ?? "")))]
  const set = (patch: Partial<GraphFilters>) => setFilters({ ...filters, ...patch })
  const k = overviewModel(report).kpis
  const usageLabel = d?.code.usage === "Referenced" ? "Referenced in source" : d?.code.usage === "Not observed" ? "Not observed in source" : "Unknown"

  return (
    <div className="space-y-4">
      <div className="flex gap-6 text-body text-textMuted">
        <span className="font-semibold text-textPrimary">{report.repo.name}</span>
        <span>Scan {runId}</span><span>Commit {shortCommit(report.repo.commit)}</span>
      </div>
      <div data-testid="dep-summary" className="grid grid-cols-4 gap-4">
        {[[k.components, "Components"], [k.direct, "Direct"], [k.transitive, "Transitive"], [k.critical + k.high, "Critical / High"]].map(([n, l]) => (
          <div key={l} className="bg-surface border border-border rounded-md p-4"><span className="text-kpi font-semibold">{n}</span><span className="block text-body text-textMuted">{l}</span></div>
        ))}
      </div>
      <div className="flex flex-wrap items-center gap-3 text-body">
        <input aria-label="Search components" placeholder="Search components or PURLs…" className={`${sel} w-64`} value={filters.search} onChange={(e) => set({ search: e.target.value })} />
        <select aria-label="Ecosystem" className={sel} value={filters.ecosystem} onChange={(e) => set({ ecosystem: e.target.value })}>{ecosystems.map((x) => <option key={x}>{x}</option>)}</select>
        <select aria-label="Severity" className={sel} value={filters.severity} onChange={(e) => set({ severity: e.target.value as Severity | "All" })}>{["All", "Critical", "High", "Medium", "Low", "Unknown"].map((x) => <option key={x}>{x}</option>)}</select>
        <select aria-label="Scope" className={sel} value={filters.scope} onChange={(e) => set({ scope: e.target.value as "All" | Scope })}>{["All", "Production", "Development"].map((x) => <option key={x}>{x}</option>)}</select>
        <select aria-label="Depth" className={sel} value={String(filters.depth)} onChange={(e) => set({ depth: e.target.value === "All" ? "All" : Number(e.target.value) })}>{["All", "1", "2", "3"].map((x) => <option key={x}>{x}</option>)}</select>
        <label className="flex items-center gap-1"><input type="checkbox" checked={filters.vulnerableOnly} onChange={(e) => set({ vulnerableOnly: e.target.checked })} />Vulnerable only</label>
        <label className="flex items-center gap-1"><input type="checkbox" checked={filters.unreferencedOnly} onChange={(e) => set({ unreferencedOnly: e.target.checked })} />Not observed in source</label>
        <span className="ml-auto text-textMuted">{report.summary.components} components · {relationshipCount(report)} relationships</span>
      </div>
      <div className="grid grid-cols-[2fr_1fr] gap-4">
        <Card title="Dependency graph" subtitle={`${graph.shown} of ${graph.total} components shown · focused dependency paths`}>
          {graph.shown === 0 ? <EmptyState title="No components to show" hint="Nothing matches the current filters." /> : <DependencyGraph graph={graph} onSelect={select} />}
        </Card>
        <Card title="Component details">
          {!d ? <EmptyState title="Select a component" /> : (
            <div className="space-y-3 text-body">
              <div className="flex items-center gap-2"><p className="text-title font-semibold">{d.name}</p><span className="rounded bg-subtle px-1.5 text-label">{dash(d.version)}</span>{d.severity && <SeverityBadge severity={d.severity} />}</div>
              <Section title="Overview">
                <dl className="grid grid-cols-[130px_1fr] gap-y-1">
                  <dt className="text-textMuted">Ecosystem</dt><dd>{d.overview.ecosystem}</dd>
                  <dt className="text-textMuted">Dependency type</dt><dd>{d.overview.dependencyType}</dd>
                  <dt className="text-textMuted">Scope</dt><dd>{dash(d.overview.scope)}</dd>
                  <dt className="text-textMuted">Dependency depth</dt><dd>{dash(d.overview.depth)}</dd>
                  <dt className="text-textMuted">Parent dependency</dt><dd>{dash(d.parent)}</dd>
                  <dt className="text-textMuted">Package URL</dt><dd className="break-all font-mono text-label">{d.purl}</dd>
                </dl>
              </Section>
              <Section title="Security">
                {d.security.length === 0 ? <p className="text-textMuted">No known vulnerabilities for this component.</p> : (
                  <ul className="space-y-2">
                    {d.security.map((v) => (
                      <li key={v.findingId} className="rounded border border-border p-2">
                        <Link className="text-link font-medium" to={`/vulnerabilities?run=${encodeURIComponent(runId)}&finding=${encodeURIComponent(v.findingId)}`}>{v.advisoryId}</Link>
                        <p className="text-label text-textMuted">{v.summary}</p>
                        <p className="text-label">Affected {dash(v.affected)} · Fixed version {dash(v.fixed)}</p>
                        <div className="flex items-center gap-2"><SeverityBadge severity={v.severity}>{v.severity}{v.cvss !== null ? ` · ${v.cvss}` : ""}</SeverityBadge>
                          <a className="text-link text-label" href={v.reference} target="_blank" rel="noreferrer">Advisory</a></div>
                      </li>
                    ))}
                  </ul>
                )}
              </Section>
              <Section title="Code usage">
                <p className="font-medium">{usageLabel}</p>
                <p className="text-label text-textMuted mb-2">{d.code.note}</p>
                <p className="text-label text-textMuted">Files</p><List items={d.code.files} />
                <p className="text-label text-textMuted mt-1">Functions</p><List items={d.code.functions} />
                <p className="text-label text-textMuted mt-1">Routes</p><List items={d.code.routes} />
                <p className="text-label text-textMuted mt-1">Sensitive calls in those functions</p><List items={d.code.sensitiveCalls} />
              </Section>
              <Section title="Dependency path">
                {d.path.length === 0 ? <p className="text-textMuted">—</p> : <ol className="font-mono text-label">{d.path.map((x, i) => <li key={x} style={{ paddingLeft: i * 12 }}>{i ? "└ " : ""}{x.replace(/^pkg:/, "")}</li>)}</ol>}
                <p className="text-label text-textMuted mt-2">Introduced by</p><List items={d.upstream} />
                <p className="text-label text-textMuted mt-1">Depends on</p><List items={d.downstream} />
              </Section>
            </div>
          )}
        </Card>
      </div>
    </div>
  )
}

export default function DependencyIntelligence() {
  return (
    <RunGate title="Dependency Intelligence" subtitle="Understand your software supply chain and investigate component risks." needViz>
      {({ report, viz, runId }) => (viz ? <Body report={report} viz={viz} runId={runId} /> : null)}
    </RunGate>
  )
}
