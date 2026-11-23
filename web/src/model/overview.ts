import { Report, Severity } from "../api/types"
import { VulnRow, vulnRows } from "./vulns"

export interface OverviewModel {
  repo: { name: string; url: string; branch: string | null; commit: string | null; lastScan: string; status: "Completed" | "Failed" | "Running" }
  kpis: { components: number; direct: number; transitive: number; vulnerabilities: number; critical: number; high: number; suspicious: number; containerCi: number; relationships: number }
  severityBar: { severity: Severity; count: number }[]
  affectedComponents: number
  ecosystems: { label: string; count: number }[]
  recent: VulnRow[]
  analysis: { done: number; total: number; warnings: number }
}

const ECO_LABEL: Record<string, string> = { pypi: "Python", npm: "JavaScript", maven: "Java", go: "Go", cargo: "Rust" }

/** Links in the dependency graph: application -> direct dependencies, plus component -> component edges. */
export const relationshipCount = (r: Report): number => (r.summary?.direct ?? 0) + (r.graph?.counts?.["edge:DEPENDS_ON"] ?? 0)

export function overviewModel(report: Report): OverviewModel {
  const rows = vulnRows(report)
  const count = (s: Severity) => rows.filter((r) => r.severity === s).length
  const bar: { severity: Severity; count: number }[] = (["Critical", "High", "Medium", "Low"] as Severity[]).map((s) => ({ severity: s, count: count(s) }))
  if (count("Unknown") > 0) bar.push({ severity: "Unknown", count: count("Unknown") })
  const nodeStatus = report.coverage?.node_status ?? {}
  const nodes = Object.values(nodeStatus)
  const failed = nodes.some((s) => s === "failed")
  const langs = report.inventory?.languages ?? {}
  const ecosystems = Object.entries(langs).map(([label, n]) => ({ label, count: n as number }))
  for (const e of report.inventory?.ecosystems ?? []) {
    if (!ecosystems.some((x) => x.label === ECO_LABEL[e])) ecosystems.push({ label: ECO_LABEL[e] ?? e, count: 0 })
  }
  const images = report.graph?.counts?.image ?? 0
  if (images) ecosystems.push({ label: "Container", count: images })
  const s = report.summary
  return {
    repo: {
      name: report.repo.name, url: report.repo.url, branch: report.repo.branch ?? null, commit: report.repo.commit ?? null,
      lastScan: report.generated_at, status: failed ? "Failed" : "Completed",
    },
    kpis: {
      components: s.components, direct: s.direct, transitive: s.transitive, vulnerabilities: s.vulnerabilities,
      critical: count("Critical"), high: count("High"), suspicious: s.supply_chain_signals, containerCi: s.container_ci,
      relationships: relationshipCount(report),
    },
    severityBar: bar,
    affectedComponents: new Set(rows.map((r) => r.subject)).size,
    ecosystems,
    recent: rows.slice(0, 4),
    analysis: { done: nodes.filter((x) => x === "ok" || x === "degraded" || x === "skipped").length, total: nodes.length, warnings: nodes.filter((x) => x === "degraded").length },
  }
}
