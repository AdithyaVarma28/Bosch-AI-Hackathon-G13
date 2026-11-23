import { Report } from "../api/types"
import { dash } from "./format"

export interface SbomRow {
  purl: string; name: string; version: string | null; ecosystem: string; scope: "Production" | "Development" | "—"
  dependency: "Direct" | "Transitive" | "—"; source: string; registry: string | null; resolvedUrl: string | null
  integrity: string | null; license: string | null; hasInstallScript: boolean; seenBy: string[]
}
export interface SbomSummary {
  count: number; direct: number; transitive: number; confidence: string; resolution: string
  tools: { name: string; ok: boolean; detail: string }[]; notes: string[]
}
export interface SbomFilter { search: string; ecosystem: string | "All"; scope: "All" | "Production" | "Development"; dependency: "All" | "Direct" | "Transitive" }
export const NO_SBOM_FILTER: SbomFilter = { search: "", ecosystem: "All", scope: "All", dependency: "All" }

export function sbomModel(report: Report): { rows: SbomRow[]; summary: SbomSummary } {
  const sb = report.sbom
  const comps = sb?.components ?? []
  const rows: SbomRow[] = comps.map((c) => ({
    purl: c.purl, name: c.name, version: c.version ?? null, ecosystem: c.ecosystem,
    scope: c.scope === "prod" ? "Production" : c.scope === "dev" ? "Development" : "—",
    dependency: c.direct === true ? "Direct" : c.direct === false ? "Transitive" : "—",
    source: dash(c.source), registry: c.origin?.registry ?? null, resolvedUrl: c.origin?.resolved_url ?? null,
    integrity: c.origin?.integrity ?? null, license: c.origin?.license ?? null,
    hasInstallScript: c.origin?.has_install_script === true, seenBy: c.seen_by ?? [],
  }))
  const rp = sb?.report ?? {}
  return {
    rows,
    summary: {
      count: rows.length,
      direct: rows.filter((r) => r.dependency === "Direct").length,
      transitive: rows.filter((r) => r.dependency === "Transitive").length,
      confidence: dash(rp.confidence), resolution: dash(rp.resolution),
      tools: Object.entries(rp.tools ?? {}).map(([name, detail]) => ({ name, ok: !/^failed|unavailable|error/i.test(detail), detail })),
      notes: rp.notes ?? [],
    },
  }
}

export function filterSbom(rows: SbomRow[], q: SbomFilter): SbomRow[] {
  const n = q.search.trim().toLowerCase()
  return rows.filter((r) =>
    (!n || r.name.toLowerCase().includes(n) || r.purl.toLowerCase().includes(n)) &&
    (q.ecosystem === "All" || r.ecosystem === q.ecosystem) &&
    (q.scope === "All" || r.scope === q.scope) &&
    (q.dependency === "All" || r.dependency === q.dependency))
}
