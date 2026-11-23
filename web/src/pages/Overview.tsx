import { Link, useSearchParams } from "react-router-dom"
import { Report, Severity } from "../api/types"
import { Card, EmptyState, Segments, SeverityBadge, StatTile, StatusBadge } from "../components/ui/ui"
import { dash, relativeTime, shortCommit } from "../model/format"
import { overviewModel } from "../model/overview"
import { scanSteps, scanProgress } from "../model/scan"
import { tokens } from "../theme/tokens"
import { RunGate } from "./common"

function Body({ report, runId }: { report: Report; runId: string }) {
  const [params] = useSearchParams()
  const run = params.get("run")
  const q = run ? `?run=${encodeURIComponent(run)}` : ""
  const m = overviewModel(report)
  const events = Object.entries(report.coverage.node_status).map(([node, status]) => ({ node, status }))
  const progress = scanProgress(scanSteps(events, "done"))
  const withFinding = (id: string) => `/vulnerabilities?run=${encodeURIComponent(runId)}&finding=${encodeURIComponent(id)}`
  const totalVulns = m.kpis.vulnerabilities
  return (
    <div className="space-y-5">
      <Card>
        <div className="flex flex-wrap items-center gap-x-10 gap-y-2 text-body">
          <div><p className="text-micro text-textFaint font-semibold">REPOSITORY</p><p className="font-semibold text-textPrimary">{m.repo.name}</p></div>
          <div><p className="text-micro text-textFaint font-semibold">SOURCE</p><p className="text-link break-all">{m.repo.url}</p></div>
          {m.repo.branch && <div><p className="text-micro text-textFaint font-semibold">BRANCH</p><p>{m.repo.branch}</p></div>}
          <div><p className="text-micro text-textFaint font-semibold">COMMIT</p><p>{shortCommit(m.repo.commit)}</p></div>
          <div><p className="text-micro text-textFaint font-semibold">LAST SCAN</p><p>{relativeTime(m.repo.lastScan)}</p></div>
          <StatusBadge status={m.repo.status} />
        </div>
      </Card>

      <div className="grid grid-cols-4 gap-4">
        <StatTile label="Components discovered" value={m.kpis.components} sub={`across ${report.inventory?.ecosystems?.length ?? 0} ecosystems`} />
        <StatTile label="Vulnerabilities" value={m.kpis.vulnerabilities} sub={`${m.kpis.critical} critical · ${m.kpis.high} high`} />
        <StatTile label="Suspicious changes" value={m.kpis.suspicious} sub={`${m.kpis.containerCi} container/CI findings`} />
        <StatTile label="Dependency relationships" value={m.kpis.relationships} sub={`${m.kpis.direct} direct · ${m.kpis.transitive} transitive`} />
      </div>

      <div className="grid grid-cols-[2fr_1fr] gap-4">
        <Card title="Vulnerability severity" subtitle={`${totalVulns} findings across ${m.affectedComponents} affected components`}
          action={<Link className="text-link text-body" to={`/vulnerabilities${q}`}>View vulnerabilities</Link>}>
          {totalVulns === 0 ? <EmptyState title="No vulnerabilities found" /> : (
            <>
              <Segments items={m.severityBar.map((s) => ({ label: s.severity, count: s.count, color: tokens.severity[s.severity as Severity].fg }))} />
              <div className="mt-4 flex gap-10">
                {m.severityBar.map((s) => (
                  <div key={s.severity}><p className="text-label text-textMuted">{s.severity}</p><p className="text-title font-semibold">{s.count}</p></div>
                ))}
              </div>
            </>
          )}
        </Card>
        <Card title="Dependency ecosystems" subtitle={`${m.kpis.components} components`}>
          <ul className="space-y-2 text-body">
            {m.ecosystems.map((e) => <li key={e.label} className="flex justify-between"><span>{e.label}</span><span className="text-textMuted">{e.count}</span></li>)}
          </ul>
        </Card>
      </div>

      <div className="grid grid-cols-[2fr_1fr] gap-4">
        <Card title="Recent security findings" subtitle="Highest severity first">
          {m.recent.length === 0 ? <EmptyState title="No vulnerabilities found" /> : (
            <table className="w-full text-body text-left">
              <thead><tr className="text-micro uppercase text-textMuted"><th className="py-2">Finding</th><th>Component</th><th>Severity</th><th>Status</th></tr></thead>
              <tbody>
                {m.recent.map((r) => (
                  <tr key={r.id} className="border-t border-border">
                    <td className="py-2"><Link className="text-link" to={withFinding(r.id)}>{r.advisoryId}</Link></td>
                    <td>{r.component}<span className="text-textMuted"> {dash(r.installed)}</span></td>
                    <td><SeverityBadge severity={r.severity} /></td>
                    <td><StatusBadge status={r.status} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
        <div className="space-y-4">
          <Card title="Recent activity">
            <ul className="space-y-3 text-body">
              <li>Scan completed · {m.kpis.components} components</li>
              <li>{m.kpis.suspicious} anomaly signals detected{report.history[0] ? ` · latest commit ${shortCommit(report.history[0].commit)}` : ""}</li>
              <li>Dependency graph updated · {m.kpis.relationships} relationships</li>
            </ul>
          </Card>
          <Card title="Repository analysis" action={<StatusBadge status={m.analysis.warnings > 0 ? "In review" : "Complete"} />}>
            <p className="text-body text-textMuted">{progress.done} of {progress.total} stages completed{m.analysis.warnings > 0 ? ` · ${m.analysis.warnings} with warnings` : ""}</p>
          </Card>
        </div>
      </div>
    </div>
  )
}

export default function Overview() {
  return <RunGate title="Overview" subtitle="Monitor and investigate your software supply chain.">{({ report, runId }) => <Body report={report} runId={runId} />}</RunGate>
}
