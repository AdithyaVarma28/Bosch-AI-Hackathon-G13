import { Card, ErrorBanner, Skeleton } from "../components/ui/ui"
import { PageHeader } from "../components/layout/Shell"
import { useCurrentRun, useRunData } from "../hooks/hooks"
import { agentModel } from "../model/agents"

const base: string = (import.meta as any).env?.VITE_API_BASE || (typeof window !== "undefined" ? window.location.origin : "")

export default function Settings() {
  const { runId, runs } = useCurrentRun()
  const { report } = useRunData(runId)
  const head = <PageHeader title="Settings" subtitle="How this workspace is connected and how scans are configured." showNewScan={false} />
  if (runs.state === "loading") return <>{head}<Skeleton /></>
  if (runs.state === "error") return <>{head}<ErrorBanner error={runs.error} /></>
  const cfg = report.state === "ready" ? agentModel(report.data) : null

  return (
    <>
      {head}
      <div className="space-y-4">
        <p className="text-body text-textMuted">Settings are read-only. Scan behaviour is controlled by environment variables and the command line when the server starts.</p>
        <Card title="Connection">
          <dl className="grid grid-cols-[160px_1fr] gap-y-1 text-body">
            <dt className="text-textMuted">API address</dt><dd className="font-mono text-label">{base}</dd>
            <dt className="text-textMuted">Status</dt><dd>Connected · {runs.data.length} scan{runs.data.length === 1 ? "" : "s"} available</dd>
          </dl>
        </Card>
        <Card title="Analysis configuration" subtitle={runId ? `From run ${runId}` : undefined}>
          {!runId ? <p className="text-body text-textMuted">No run selected</p> : !cfg ? <p className="text-body text-textMuted">Loading configuration…</p> : (
            <dl className="grid grid-cols-[160px_1fr] gap-y-2 text-body">
              <dt className="text-textMuted">Language models</dt><dd>{cfg.llm.text}</dd>
              <dt className="text-textMuted">Priority thresholds</dt><dd>{report.state === "ready" ? String(report.data.coverage?.thresholds ?? "—") : "—"}</dd>
              <dt className="text-textMuted">Report schema</dt><dd>{report.state === "ready" ? report.data.schema_version : "—"}</dd>
              <dt className="text-textMuted">Generated</dt><dd>{report.state === "ready" ? report.data.generated_at : "—"}</dd>
            </dl>
          )}
        </Card>
        <Card title="Enabling language-model explanations">
          <p className="text-body">Set the <span className="font-mono">GROQ_API_KEY</span> environment variable before starting <span className="font-mono">guardian serve</span>. New scans then use the LLM agents; without it, deterministic rules are used.</p>
        </Card>
      </div>
    </>
  )
}
