import { useEffect, useState } from "react"
import { getEvidence } from "../api/client"
import { Evidence, Finding } from "../api/types"
import { cvePanel } from "../model/vulns"
import { dash } from "../model/format"
import { SeverityBadge, StatusBadge } from "./ui/ui"

function EvidenceItem({ runId, id }: { runId: string; id: string }) {
  const [ev, setEv] = useState<Evidence | "failed" | null>(null)
  useEffect(() => {
    let live = true
    getEvidence(runId, id).then((e) => live && setEv(e), () => live && setEv("failed"))
    return () => { live = false }
  }, [runId, id])
  if (ev === null) return <li className="text-textMuted text-body">Loading evidence…</li>
  if (ev === "failed") return <li className="text-textMuted text-body">Evidence {id} could not be loaded.</li>
  return (
    <li className="text-body">
      <p className="font-medium text-textPrimary">{dash(ev.locator)}</p>
      <details><summary className="text-link cursor-pointer text-label">Show excerpt</summary><pre className="mt-1 whitespace-pre-wrap rounded bg-page p-2 text-label">{ev.excerpt}</pre></details>
    </li>
  )
}

export function CvePanel({ finding, runId }: { finding: Finding; runId: string }) {
  const p = cvePanel(finding)
  return (
    <div className="p-6 space-y-5">
      <div>
        <p className="text-micro font-semibold text-textFaint">VULNERABILITY DETAILS</p>
        <h2 className="text-page font-semibold text-textPrimary">{p.advisoryId}</h2>
        <p className="text-body text-textSecondary">{p.summary}</p>
        <div className="mt-2 flex gap-2">
          <SeverityBadge severity={p.severity}>{p.severity}{p.cvss !== null ? ` · CVSS ${p.cvss}` : ""}</SeverityBadge>
          <StatusBadge status={p.status} />
        </div>
      </div>
      <section><h3 className="text-title font-semibold">Advisory</h3><p className="text-body text-textSecondary">{p.advisory}</p></section>
      <dl className="grid grid-cols-[140px_1fr] gap-y-2 text-body">
        <dt className="text-textMuted">Component</dt><dd>{p.component}{p.installed ? `@${p.installed}` : ""}</dd>
        <dt className="text-textMuted">Affected versions</dt><dd>{dash(p.affected)}</dd>
        <dt className="text-textMuted">Fixed version</dt><dd>{dash(p.fixed)}</dd>
        <dt className="text-textMuted">Dependency type</dt><dd>{p.dependencyType}</dd>
        <dt className="text-textMuted">Priority</dt><dd><span className="font-semibold">{p.band}</span> · {dash(p.bandReason)}</dd>
        <dt className="text-textMuted">Source</dt><dd>{p.source.url ? <a className="text-link" href={p.source.url} target="_blank" rel="noreferrer">{p.source.label}</a> : p.source.label}</dd>
      </dl>
      <section>
        <h3 className="text-title font-semibold mb-1">Dependency path</h3>
        {p.path.length === 0 ? <p className="text-body text-textMuted">—</p> : (
          <ol className="rounded bg-page p-3 text-body font-mono">
            {p.path.map((x, i) => <li key={x} style={{ paddingLeft: i * 14 }}>{i > 0 ? "└ " : ""}{x.replace(/^pkg:/, "")}</li>)}
          </ol>
        )}
      </section>
      <section>
        <h3 className="text-title font-semibold mb-1">Supporting evidence</h3>
        {p.evidenceIds.length === 0 ? <p className="text-body text-textMuted">No evidence recorded.</p> : <ul className="space-y-2">{p.evidenceIds.map((id) => <EvidenceItem key={id} runId={runId} id={id} />)}</ul>}
      </section>
      {p.claims.length > 0 && (
        <section>
          <h3 className="text-title font-semibold mb-1">Analysis</h3>
          <ul className="space-y-1 text-body">
            {p.claims.map((c, i) => <li key={i}><span className="mr-2 rounded bg-subtle px-1.5 py-0.5 text-micro uppercase text-textMuted">{c.type}</span>{c.text}</li>)}
          </ul>
        </section>
      )}
    </div>
  )
}
