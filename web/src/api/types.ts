export type Severity = "Critical" | "High" | "Medium" | "Low" | "Unknown"
export type Band = "P0" | "P1" | "P2" | "P3" | "Unprioritized"
export type FindingClass = "vuln" | "anomaly" | "container" | "ci" | "secret" | "sbom_quality" | "discrepancy"

export interface Claim { text: string; type: "fact" | "inference" | "unknown"; evidence_ids: string[]; confidence: string; verifier_status: string; reason?: string | null }
export interface Explanation { claims: Claim[]; counterfactual?: string | null; notes?: string; generated_by?: string }
export interface Finding {
  id: string; cls: FindingClass; subject: string; title: string; locator: string; detector: string
  classification: string; signals: Record<string, any>; band: Band; band_reason: string; status: string
  raw_evidence_ids: string[]; attack_class: string | null; explanation?: Explanation
}
export interface HistoryEntry { commit: string; date: string; author: string; message: string; files_changed: string[]; added: string[]; removed: string[]; changed: Record<string, any>[]; baseline?: boolean; discovered_by?: string }
export interface Report {
  schema_version: string; generated_at: string; run_id: string
  repo: { url: string; owner: string | null; name: string; branch: string | null; commit: string | null; is_local: boolean }
  summary: { components: number; direct: number; transitive: number; findings: number; bands: Record<string, number>; vulnerabilities: number; supply_chain_signals: number; container_ci: number; secrets: number }
  inventory: { ecosystems?: string[]; languages?: Record<string, number>; manifests?: { path: string; ecosystem: string; dependency_count?: number }[] } & Record<string, any>
  graph: { counts: Record<string, number> } & Record<string, any>
  history: HistoryEntry[]; findings: Finding[]
  sbom: SbomSection
  dossier?: { app_type?: string; exposure?: string; summary?: string; claims?: Claim[] } | null
  integrity?: { artifact_sha256?: Record<string, string> } | null
  remediation?: unknown
  validation?: unknown
  vex?: unknown
  evidence: Record<string, Evidence>
  coverage: { node_status: Record<string, string>; degraded?: string[]; failed?: string[]; skipped?: Record<string, string> } & Record<string, any>
}
export interface SbomComponent {
  purl: string; name: string; version?: string | null; ecosystem: string; scope?: string; direct?: boolean | null; source?: string; seen_by?: string[]
  origin?: { registry?: string | null; resolved_url?: string | null; integrity?: string | null; source_repo?: string | null; license?: string | null; has_install_script?: boolean }
}
export interface SbomSection {
  path?: string
  report?: { tools?: Record<string, string>; confidence?: string; resolution?: string; notes?: string[]; jaccard?: number | null }
  components: SbomComponent[]
}
export interface RunSummary { run_id: string; repo_name: string; target: string; status: "running" | "done" | "failed"; commit: string | null; finished_at: string | null; error: string | null }
export interface RunEvent { node: string; status: string; message?: string; seconds?: number }
export interface VizNode { id: string; type: string; label: string; ecosystem?: string; version?: string; depth?: number; direct?: boolean; risk?: string; vulns?: number; findings?: string[]; [k: string]: any }
export interface VizEdge { s: string; t: string; rel: string; status?: string; loc?: string }
export interface VizGraph { nodes: VizNode[]; edges: VizEdge[]; blast: Record<string, { dependents?: string[]; introducers?: string[]; package?: string; files?: string[]; functions?: string[]; routes?: string[]; exposed?: string[] }>; ecosystems?: unknown }
export interface Evidence { id: string; kind: string; source: string; locator: string; excerpt: string; sha256: string; captured_at: string; run_id: string }

export class ApiError extends Error {
  path: string
  status: number | null
  constructor(path: string, status: number | null, message: string) {
    super(message)
    this.name = "ApiError"
    this.path = path
    this.status = status
  }
}
