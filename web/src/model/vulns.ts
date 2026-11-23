import { Band, Claim, Finding, Report, Severity } from "../api/types"
import { splitPurl, severityRank, toSeverity } from "./format"

export interface VulnRow {
  id: string; advisoryId: string; summary: string; component: string; installed: string | null; fixed: string | null
  severity: Severity; cvss: number | null; dependency: "Direct" | "Transitive" | "—"; status: string; band: Band; subject: string
}

export interface CvePanel {
  advisoryId: string; summary: string; severity: Severity; cvss: number | null; status: string; advisory: string
  component: string; installed: string | null; affected: string | null; fixed: string | null; dependencyType: string
  source: { label: string; url: string | null }; path: string[]; band: Band; bandReason: string
  evidenceIds: string[]; claims: Claim[]; importedBy: string[]; exposedRoutes: string[]
}

const statusLabel = (s: string) => (s === "open" ? "Open" : s ? s.charAt(0).toUpperCase() + s.slice(1) : "—")

export function vulnRow(f: Finding): VulnRow {
  const s = f.signals ?? {}
  const { name, version } = splitPurl(f.subject)
  const fixed: string[] = Array.isArray(s.fixed_versions) ? s.fixed_versions : []
  return {
    id: f.id,
    advisoryId: s.advisory_id ?? f.locator,
    summary: s.summary ?? f.title,
    component: name,
    installed: version,
    fixed: fixed.length ? fixed.join(", ") : null,
    severity: toSeverity(s.severity_band),
    cvss: typeof s.cvss === "number" ? s.cvss : null,
    dependency: s.direct === true ? "Direct" : s.direct === false ? "Transitive" : "—",
    status: statusLabel(f.status),
    band: f.band,
    subject: f.subject,
  }
}

// A package with no severity but band P0 (e.g. a known-malicious package) must not sink to the bottom.
const effectiveRank = (r: VulnRow) => (r.severity === "Unknown" && r.band === "P0" ? -1 : severityRank(r.severity))

export function vulnRows(report: Report): VulnRow[] {
  return report.findings
    .filter((f) => f.cls === "vuln")
    .map(vulnRow)
    .sort((a, b) => effectiveRank(a) - effectiveRank(b) || (b.cvss ?? -1) - (a.cvss ?? -1) || a.advisoryId.localeCompare(b.advisoryId))
}

export function cvePanel(f: Finding): CvePanel {
  const row = vulnRow(f)
  const s = f.signals ?? {}
  const advisoryId = row.advisoryId
  const url = advisoryId ? `https://osv.dev/vulnerability/${encodeURIComponent(advisoryId)}` : null
  return {
    advisoryId,
    summary: row.summary,
    severity: row.severity,
    cvss: row.cvss,
    status: row.status,
    advisory: s.summary ?? f.title,
    component: row.component,
    installed: row.installed,
    affected: row.installed ? `${row.installed} (installed)` : null,
    fixed: row.fixed,
    dependencyType: row.dependency,
    source: { label: "OSV", url },
    path: Array.isArray(s.path) ? s.path : [],
    band: f.band,
    bandReason: f.band_reason,
    evidenceIds: f.raw_evidence_ids ?? [],
    claims: f.explanation?.claims ?? [],
    importedBy: Array.isArray(s.imported_by) ? s.imported_by : [],
    exposedRoutes: Array.isArray(s.exposed_routes) ? s.exposed_routes : [],
  }
}

export interface VulnQuery { search: string; severity: Severity | "All"; status: string | "All"; dependency: "Direct" | "Transitive" | "All" }
export const NO_FILTER: VulnQuery = { search: "", severity: "All", status: "All", dependency: "All" }

export function filterVulns(rows: VulnRow[], q: VulnQuery): VulnRow[] {
  const needle = q.search.trim().toLowerCase()
  return rows.filter(
    (r) =>
      (!needle || [r.advisoryId, r.summary, r.component].some((x) => x.toLowerCase().includes(needle))) &&
      (q.severity === "All" || r.severity === q.severity) &&
      (q.status === "All" || r.status === q.status) &&
      (q.dependency === "All" || r.dependency === q.dependency),
  )
}

export type SortKey = "severity" | "cvss" | "band"
const BAND_ORDER: Band[] = ["P0", "P1", "P2", "P3", "Unprioritized"]
export function sortVulns(rows: VulnRow[], key: SortKey): VulnRow[] {
  if (key === "severity") return rows
  const out = [...rows]
  if (key === "cvss") return out.sort((a, b) => (b.cvss ?? -1) - (a.cvss ?? -1))
  return out.sort((a, b) => BAND_ORDER.indexOf(a.band) - BAND_ORDER.indexOf(b.band))
}

export function paginate<T>(items: T[], page: number, size: number) {
  const pages = Math.max(1, Math.ceil(items.length / size))
  const p = Math.min(Math.max(1, page), pages)
  const start = (p - 1) * size
  const slice = items.slice(start, start + size)
  return { items: slice, page: p, pages, from: items.length ? start + 1 : 0, to: start + slice.length, total: items.length }
}
