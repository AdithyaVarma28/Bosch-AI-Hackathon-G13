import { Claim, Report } from "../api/types"

export interface StageRow { node: string; label: string; status: "Completed" | "Completed with warnings" | "Skipped" | "Failed"; reason: string | null }
export interface AgentModel {
  stages: StageRow[]
  llm: { configured: boolean; text: string }
  errors: string[]
  code: { filesTotal: number; filesParsed: number; filesFailed: number; dynamicImports: number; languages: string }
  dossier: { appType: string; exposure: string; summary: string; claims: Claim[] } | null
}

const LABELS: Record<string, string> = {
  ingest: "Fetch and open the repository",
  cartographer: "Read manifests, lockfiles, CI and container files",
  code_index: "Parse source code statically (never executed)",
  resolver_sbom: "Resolve components and build the SBOM",
  graph: "Build the dependency and code graph",
  dossier_agent: "Summarise what the application is and how exposed it is",
  supervisor: "Decide which detectors to run",
  change_anomaly: "Compare git history for suspicious changes",
  container_ci: "Check Dockerfiles, compose files and CI workflows",
  discrepancies: "Compare declared, resolved and imported packages",
  package_signals: "Look for typosquats, deprecations and install scripts",
  secrets: "Look for hard-coded credentials",
  vuln_intel: "Match components against known advisories",
  correlator: "Merge findings and assign priority bands",
  evidence_agent: "Attach evidence and explanations to findings",
  report: "Write the report",
}

export function agentModel(report: Report): AgentModel {
  const cov = report.coverage ?? ({} as Report["coverage"])
  const skipped = (cov.skipped ?? {}) as Record<string, string>
  const code = (cov.code ?? {}) as Record<string, any>
  const toolFailures = Object.entries((cov.sbom_tools ?? {}) as Record<string, string>).filter(([, v]) => /^failed|unavailable|error/i.test(v)).map(([k, v]) => `${k}: ${v}`)

  const reasonFor = (node: string, status: string): string | null => {
    if (status === "skipped") return skipped[node] ?? "Skipped"
    if (status !== "degraded") return null
    if (node === "resolver_sbom") return toolFailures.length ? toolFailures.join("; ") : "SBOM built with reduced confidence"
    if (node === "code_index") return `${code.files_failed ?? 0} of ${code.files_total ?? 0} files could not be parsed`
    return "Completed with warnings"
  }

  const stages: StageRow[] = Object.entries(cov.node_status ?? {}).map(([node, status]) => ({
    node, label: LABELS[node] ?? node,
    status: status === "ok" ? "Completed" : status === "degraded" ? "Completed with warnings" : status === "skipped" ? "Skipped" : "Failed",
    reason: reasonFor(node, status),
  }))

  const d = report.dossier
  return {
    stages,
    llm: { configured: !/not configured/i.test(String(cov.llm ?? "")) && !!cov.llm, text: String(cov.llm ?? "—") },
    errors: ((cov.pipeline_errors ?? []) as unknown[]).map(String),
    code: {
      filesTotal: code.files_total ?? 0, filesParsed: code.files_parsed ?? 0, filesFailed: code.files_failed ?? 0,
      dynamicImports: code.dynamic_imports ?? 0,
      languages: Object.entries((code.languages ?? {}) as Record<string, number>).map(([k, v]) => `${k} ${v}`).join(", ") || "—",
    },
    dossier: d ? { appType: d.app_type ?? "—", exposure: d.exposure ?? "—", summary: d.summary ?? "", claims: d.claims ?? [] } : null,
  }
}
