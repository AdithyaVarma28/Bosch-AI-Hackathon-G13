import { Band, Report } from "../api/types"
import { findingHref } from "./evidence"

export interface RiskRow { id: string; title: string; cls: string; classLabel: string; band: Band; reason: string; subject: string; href: string | null }
export interface RiskFilter { band: Band | "All"; cls: string | "All"; search: string }

const BANDS: Band[] = ["P0", "P1", "P2", "P3", "Unprioritized"]
export const CLASS_LABEL: Record<string, string> = {
  vuln: "Vulnerability", anomaly: "Suspicious change", container: "Container", ci: "CI/CD", secret: "Secret", discrepancy: "Dependency mismatch", sbom_quality: "SBOM quality",
}

export function riskModel(report: Report) {
  const findings = report.findings ?? []
  const count = (b: Band) => findings.filter((f) => f.band === b).length
  const bands = BANDS.map((band) => ({ band, count: count(band) })).filter((b) => b.band !== "Unprioritized" || b.count > 0)
  const rows: RiskRow[] = findings
    .map((f) => ({ id: f.id, title: f.title, cls: f.cls, classLabel: CLASS_LABEL[f.cls] ?? f.cls, band: f.band, reason: f.band_reason, subject: f.subject, href: findingHref(f) }))
    .sort((a, b) => BANDS.indexOf(a.band) - BANDS.indexOf(b.band) || a.title.localeCompare(b.title))
  return { bands, rows, disclaimer: String(report.coverage?.thresholds ?? "") }
}

export function filterRisk(rows: RiskRow[], q: RiskFilter): RiskRow[] {
  const n = q.search.trim().toLowerCase()
  return rows.filter((r) => (q.band === "All" || r.band === q.band) && (q.cls === "All" || r.cls === q.cls) && (!n || [r.title, r.subject, r.reason].some((x) => x.toLowerCase().includes(n))))
}
