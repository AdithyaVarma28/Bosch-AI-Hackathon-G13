import { useState } from "react"
import { useNavigate, useSearchParams } from "react-router-dom"
import { Report } from "../api/types"
import { PageHeader } from "../components/layout/Shell"
import { Card, ErrorBanner, NotAvailable, StatusBadge } from "../components/ui/ui"
import { useRunData, useScan } from "../hooks/hooks"
import { scanProgress, ScanStep, scanSteps, scanSummaryLine } from "../model/scan"

const GITHUB = /^https?:\/\/(www\.)?github\.com\/[\w.-]+\/[\w.-]+(\.git)?\/?$/
const LOCAL = /^([A-Za-z]:[\\/]|\/)/
export const validRepo = (v: string) => GITHUB.test(v.trim()) || LOCAL.test(v.trim())

function Icon({ s }: { s: ScanStep["status"] }) {
  const map = { done: "✓", running: "◌", degraded: "!", failed: "✕", pending: "—" } as const
  return <span aria-hidden="true" className={s === "running" ? "animate-spin inline-block" : ""}>{map[s]}</span>
}

function Steps({ steps }: { steps: ScanStep[] }) {
  return (
    <ol className="divide-y divide-border">
      {steps.map((s) => (
        <li key={s.key} data-status={s.status} className="flex items-center gap-3 py-3 text-body">
          <Icon s={s.status} />
          <div className="flex-1">
            <p className="font-medium">{s.number}. {s.title}{s.status === "degraded" && <span className="ml-2 text-label" style={{ color: "#b54708" }}>completed with warnings</span>}</p>
            <p className="text-label text-textMuted">{s.description}</p>
          </div>
          <span className="text-label text-textMuted">{s.seconds === null ? "—" : `${s.seconds}s`}</span>
        </li>
      ))}
    </ol>
  )
}

export default function RepositoryScanning() {
  const [params, setParams] = useSearchParams()
  const nav = useNavigate()
  const scan = useScan()
  const [url, setUrl] = useState("")
  const [invalid, setInvalid] = useState(false)
  const existing = params.get("run")
  const showExisting = !!existing && scan.status === "idle"
  const loaded = useRunData(showExisting ? existing : null)

  const submit = async () => {
    if (!validRepo(url)) { setInvalid(true); return }
    setInvalid(false)
    await scan.start(url.trim())
  }
  const running = scan.status === "running"

  let steps: ScanStep[]
  let report: Report | null = null
  let status: "running" | "done" | "failed" | null = null
  if (showExisting && loaded.report.state === "ready") {
    report = loaded.report.data
    const evs = Object.entries(report.coverage.node_status).map(([node, st]) => ({ node, status: st }))
    steps = scanSteps(evs, "done"); status = "done"
  } else {
    steps = scanSteps(scan.events, scan.status === "idle" ? "running" : scan.status)
    if (scan.status !== "idle") status = scan.status
    if (scan.report?.state === "ready") report = scan.report.data
  }
  const progress = scanProgress(steps)
  const total = Math.round(steps.reduce((a, s) => a + (s.seconds ?? 0), 0) * 10) / 10
  const runId = showExisting ? existing : scan.runId

  return (
    <>
      <PageHeader title="Repository Scanning" subtitle="Scan a GitHub repository to analyse its software supply chain." showNewScan={false} />
      <div className="space-y-4">
        <Card title="GitHub repository" subtitle="Enter the repository URL to begin analysis.">
          <div className="flex gap-3">
            <input aria-label="Repository URL" className="flex-1 border border-border rounded px-3 py-2 text-body" placeholder="https://github.com/owner/repository" value={url} onChange={(e) => setUrl(e.target.value)} onKeyDown={(e) => e.key === "Enter" && submit()} />
            <button className="rounded bg-textPrimary px-4 text-nav font-medium text-white disabled:opacity-50" disabled={running} onClick={submit}>{running ? "Scanning…" : "Start scan"}</button>
          </div>
          {invalid && <p role="alert" className="mt-2 text-label" style={{ color: "#b42318" }}>Enter a GitHub repository URL such as https://github.com/owner/repository, or a local path.</p>}
          <p className="mt-2 text-label text-textMuted">Read-only repository analysis. Nothing is changed in the repository.</p>
        </Card>

        {scan.error && <ErrorBanner error={scan.error} />}
        {showExisting && loaded.notAvailable && <Card><NotAvailable /></Card>}
        {showExisting && loaded.report.state === "error" && !loaded.notAvailable && <ErrorBanner error={loaded.report.error} />}

        {(status !== null || (showExisting && loaded.report.state === "ready")) && (
          <Card title="Repository analysis" subtitle={runId ? `Scan ${runId}` : undefined} action={status && <StatusBadge status={status === "done" ? "Complete" : status === "failed" ? "Failed" : "In progress"} />}>
            <p className="text-body text-textMuted mb-2">{progress.done} of {progress.total} stages completed{status === "done" ? ` · ${total}s total` : ""}</p>
            <div className="h-1.5 w-full rounded bg-subtle mb-2"><div className="h-full rounded" style={{ width: `${(progress.done / 7) * 100}%`, backgroundColor: "#12b76a" }} /></div>
            <Steps steps={steps} />
          </Card>
        )}

        {scan.status === "failed" && scan.runError && <div role="alert" className="rounded border p-4 text-body" style={{ color: "#b42318", backgroundColor: "#fef3f2", borderColor: "#b42318" }}>Scan failed: {scan.runError}</div>}

        {status === "done" && report && runId && (
          <div className="flex items-center justify-between rounded border border-border bg-surface p-4 text-body" style={{ backgroundColor: "#ecfdf3" }}>
            <span><strong>Analysis complete</strong> · {scanSummaryLine(report)}</span>
            <button className="rounded bg-textPrimary px-3 py-1.5 text-nav font-medium text-white" onClick={() => { setParams({ run: runId }); nav(`/?run=${encodeURIComponent(runId)}`) }}>View Overview</button>
          </div>
        )}
      </div>
    </>
  )
}
