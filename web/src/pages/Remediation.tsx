import { useSearchParams, Link } from "react-router-dom"
import { Report } from "../api/types"
import { Card, DataTable, Drawer, EmptyState, SeverityBadge } from "../components/ui/ui"
import { dash } from "../model/format"
import { UpgradeOption, upgradeOptions } from "../model/remediation"
import { RunGate } from "./common"

function Detail({ o, runId }: { o: UpgradeOption; runId: string }) {
  return (
    <div className="space-y-4 p-6 text-body">
      <div><p className="text-micro font-semibold text-textFaint">UPGRADE OPTIONS</p><h2 className="text-page font-semibold">{o.name} <span className="text-textMuted">{dash(o.installed)}</span></h2></div>
      <p className="text-textMuted">Highest fixed version listed: {dash(o.highestFix)}. Not verified for compatibility.</p>
      <ul className="space-y-2">
        {o.advisories.map((a) => (
          <li key={a.findingId} className="rounded border border-border p-2">
            <Link className="font-medium text-link" to={`/vulnerabilities?run=${encodeURIComponent(runId)}&finding=${encodeURIComponent(a.findingId)}`}>{a.advisoryId}</Link>
            <p className="text-label text-textMuted">{a.summary}</p>
            <div className="flex items-center gap-2"><SeverityBadge severity={a.severity} /><span className="text-label">{a.fixed ? `Fixed in ${a.fixed}` : "No fixed version listed"}</span></div>
          </li>
        ))}
      </ul>
    </div>
  )
}

function Body({ report, runId }: { report: Report; runId: string }) {
  const [params, setParams] = useSearchParams()
  const options = upgradeOptions(report)
  const open = options.find((o) => o.subject === params.get("component")) ?? null
  const setOpen = (s: string | null) => setParams((p) => { const n = new URLSearchParams(p); s ? n.set("component", s) : n.delete("component"); return n })
  const hasPlan = report.remediation !== null && report.remediation !== undefined

  return (
    <div className="space-y-4">
      <div className="rounded border border-border px-4 py-3 text-body" style={{ backgroundColor: "#fffaeb", color: "#b54708" }}>
        Fixed versions come from public advisories and are not verified for compatibility. Test upgrades before merging.
        {!hasPlan && " Guardian has not generated a remediation plan for this run."}
      </div>
      <Card title="Available upgrades" subtitle="Components with known vulnerabilities, worst first.">
        {options.length === 0 ? <EmptyState title="No upgrades needed" hint="No vulnerable components were found in this scan." /> : (
          <DataTable
            rowKey={(o) => o.subject}
            onRowClick={(o) => setOpen(o.subject)}
            rows={options}
            columns={[
              { key: "name", header: "Component", render: (o) => <span className="font-medium text-link">{o.name}</span> },
              { key: "inst", header: "Installed", render: (o) => dash(o.installed) },
              { key: "n", header: "Advisories", render: (o) => o.count },
              { key: "sev", header: "Worst severity", render: (o) => <SeverityBadge severity={o.worst} /> },
              { key: "fix", header: "Highest fixed version", render: (o) => dash(o.highestFix) },
            ]}
          />
        )}
      </Card>
      {hasPlan && <Card title="Generated remediation"><pre className="overflow-auto whitespace-pre-wrap text-label">{JSON.stringify(report.remediation, null, 2)}</pre></Card>}
      <Drawer open={!!open} onClose={() => setOpen(null)} label="Upgrade options">{open && <Detail o={open} runId={runId} />}</Drawer>
    </div>
  )
}

export default function Remediation() {
  return <RunGate title="Remediation" subtitle="Which upgrades the advisories point to.">{({ report, runId }) => <Body report={report} runId={runId} />}</RunGate>
}
