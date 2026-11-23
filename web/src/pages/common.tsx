import { ReactNode } from "react"
import { Link } from "react-router-dom"
import { Report, VizGraph } from "../api/types"
import { Card, EmptyState, ErrorBanner, NotAvailable, Skeleton } from "../components/ui/ui"
import { PageHeader } from "../components/layout/Shell"
import { useCurrentRun, useRunData } from "../hooks/hooks"

/** Loads the selected run and renders loading / error / not-available / no-run states, else calls children. */
export function RunGate({ title, subtitle, needViz = false, children }: {
  title: string; subtitle?: string; needViz?: boolean
  children: (d: { report: Report; viz: VizGraph | null; runId: string }) => ReactNode
}) {
  const { runId, runs } = useCurrentRun()
  const { report, viz, notAvailable } = useRunData(runId)
  const head = <PageHeader title={title} subtitle={subtitle} />
  if (runs.state === "error" && !runId) return <>{head}<ErrorBanner error={runs.error} /></>
  if (!runId) {
    if (runs.state === "loading") return <>{head}<Skeleton /></>
    return <>{head}<Card><EmptyState title="No scans yet" hint="Start a scan to see results here." /><p className="text-center"><Link className="text-link underline" to="/scan">Start a scan</Link></p></Card></>
  }
  if (notAvailable) return <>{head}<Card><NotAvailable /></Card></>
  if (report.state === "error") return <>{head}<ErrorBanner error={report.error} /></>
  if (report.state === "loading") return <>{head}<Skeleton rows={6} /></>
  if (needViz && viz.state === "error") return <>{head}<ErrorBanner error={viz.error} /></>
  if (needViz && viz.state === "loading") return <>{head}<Skeleton rows={6} /></>
  return <>{head}{children({ report: report.data, viz: viz.state === "ready" ? viz.data : null, runId })}</>
}
