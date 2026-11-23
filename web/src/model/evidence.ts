import { Report } from "../api/types"

export interface EvidenceRow { id: string; kind: string; source: string; locator: string; excerpt: string; sha256: string; capturedAt: string; citedBy: number }
export interface EvidenceFilter { search: string; kind: string | "All" }

export function evidenceRows(report: Report): EvidenceRow[] {
  const cites = new Map<string, number>()
  for (const f of report.findings ?? []) for (const id of f.raw_evidence_ids ?? []) cites.set(id, (cites.get(id) ?? 0) + 1)
  return Object.values(report.evidence ?? {})
    .map((e) => ({ id: e.id, kind: e.kind, source: e.source, locator: e.locator, excerpt: e.excerpt ?? "", sha256: e.sha256, capturedAt: e.captured_at, citedBy: cites.get(e.id) ?? 0 }))
    .sort((a, b) => b.citedBy - a.citedBy || a.source.localeCompare(b.source) || a.id.localeCompare(b.id))
}

/** Findings that cite an evidence item, with the page where the finding can be opened (null when no page shows it). */
export function evidenceCitedBy(report: Report, evidenceId: string): { findingId: string; title: string; cls: string; href: string | null }[] {
  return (report.findings ?? [])
    .filter((f) => (f.raw_evidence_ids ?? []).includes(evidenceId))
    .map((f) => ({
      findingId: f.id, title: f.title, cls: f.cls,
      href: f.cls === "vuln" ? `/vulnerabilities?finding=${encodeURIComponent(f.id)}`
        : ["anomaly", "container", "ci", "discrepancy"].includes(f.cls) ? `/anomalies?signal=${encodeURIComponent(f.id)}` : null,
    }))
}

export function filterEvidence(rows: EvidenceRow[], q: EvidenceFilter): EvidenceRow[] {
  const n = q.search.trim().toLowerCase()
  return rows.filter((r) => (q.kind === "All" || r.kind === q.kind) && (!n || [r.locator, r.source, r.excerpt, r.id].some((x) => x.toLowerCase().includes(n))))
}
