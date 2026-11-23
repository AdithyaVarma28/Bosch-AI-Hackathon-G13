import { Report, RunEvent } from "../api/types"

export type StepKey = "discovery" | "manifests" | "sbom" | "dependencies" | "vulnerabilities" | "anomalies" | "report"
export interface ScanStep { key: StepKey; number: number; title: string; description: string; status: "pending" | "running" | "done" | "degraded" | "failed"; seconds: number | null }

// Pipeline nodes as emitted by PlanB (verified against the captured event log).
export const STEP_NODES: Record<StepKey, string[]> = {
  discovery: ["ingest"],
  manifests: ["cartographer"],
  sbom: ["resolver_sbom"],
  dependencies: ["code_index", "graph"],
  vulnerabilities: ["vuln_intel"],
  anomalies: ["change_anomaly", "container_ci", "discrepancies", "package_signals", "secrets"],
  report: ["dossier_agent", "supervisor", "correlator", "evidence_agent", "report"],
}
const META: Record<StepKey, { title: string; fallback: string }> = {
  discovery: { title: "Repository discovery", fallback: "Fetching the repository and reading its structure" },
  manifests: { title: "Manifest analysis", fallback: "Reading dependency manifests, lockfiles, CI and container files" },
  sbom: { title: "SBOM generation", fallback: "Resolving components and building the software bill of materials" },
  dependencies: { title: "Dependency mapping", fallback: "Mapping code usage and dependency relationships" },
  vulnerabilities: { title: "Vulnerability detection", fallback: "Matching components against advisories" },
  anomalies: { title: "Anomaly analysis", fallback: "Looking for suspicious changes and configuration risks" },
  report: { title: "Report generation", fallback: "Prioritising findings and writing the report" },
}
const KEYS = Object.keys(STEP_NODES) as StepKey[]
const FINISHED = ["ok", "skipped", "degraded"]

export function scanSteps(events: RunEvent[], runStatus: "running" | "done" | "failed"): ScanStep[] {
  const last = new Map<string, RunEvent>() // idempotent: the last event per node wins, replays change nothing
  for (const e of events) if (e.node !== "run") last.set(e.node, e)

  let firstIncomplete = -1
  const steps = KEYS.map((key, i): ScanStep => {
    const members = STEP_NODES[key]
    const seen = members.filter((m) => last.has(m)).map((m) => last.get(m)!)
    const failed = seen.some((e) => e.status === "failed")
    const all = seen.length === members.length
    const finished = all && seen.every((e) => FINISHED.includes(e.status))
    let status: ScanStep["status"] = "pending"
    if (failed) status = "failed"
    else if (finished) status = seen.some((e) => e.status === "degraded") ? "degraded" : "done"
    else if (seen.length > 0) status = "running"
    if (!["done", "degraded", "failed"].includes(status) && firstIncomplete < 0) firstIncomplete = i
    const msg = [...seen].reverse().find((e) => e.message)?.message
    return {
      key, number: i + 1, title: META[key].title, description: msg ?? META[key].fallback, status,
      seconds: seen.length ? Math.round(seen.reduce((a, e) => a + (e.seconds ?? 0), 0) * 100) / 100 : null,
    }
  })

  const anyFailed = steps.some((s) => s.status === "failed")
  if (runStatus === "running" && !anyFailed && firstIncomplete >= 0 && steps[firstIncomplete].status === "pending") steps[firstIncomplete].status = "running"
  if (runStatus === "done" && !anyFailed) for (const s of steps) if (s.status === "pending" || s.status === "running") s.status = "done"
  if (runStatus === "failed" && !anyFailed && firstIncomplete >= 0) steps[firstIncomplete].status = "failed"
  return steps
}

export function scanProgress(steps: ScanStep[]): { done: number; total: 7 } {
  return { done: steps.filter((s) => s.status === "done" || s.status === "degraded").length, total: 7 }
}

export function scanSummaryLine(report: Report | null): string {
  if (!report) return ""
  const s = report.summary
  return `${s.components} components · ${s.vulnerabilities} vulnerabilities · ${s.supply_chain_signals + s.container_ci} anomaly signals`
}
