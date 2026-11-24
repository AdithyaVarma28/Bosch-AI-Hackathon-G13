import { Claim, Report } from "../api/types"

export interface ValidationModel {
  claims: { total: number; verified: number; downgraded: number; other: number; byType: { fact: number; inference: number; unknown: number } }
  sbom: { crossCheck: "Performed" | "Not performed"; confidence: string; tools: { name: string; ok: boolean; detail: string }[] }
  integrity: { name: string; sha256: string }[]
  limits: string[]
  thresholds: string
}

export function validationModel(report: Report): ValidationModel {
  const all: Claim[] = [...(report.findings ?? []).flatMap((f) => f.explanation?.claims ?? []), ...(report.dossier?.claims ?? [])]
  const byType = { fact: 0, inference: 0, unknown: 0 }
  for (const c of all) if (c.type in byType) byType[c.type]++
  const rep = report.sbom?.report ?? {}
  const tools = Object.entries(rep.tools ?? {}).map(([name, detail]) => ({ name, ok: !/^failed|unavailable|error/i.test(detail), detail }))
  const verified = all.filter((c) => c.verifier_status === "verified").length
  const downgraded = all.filter((c) => c.verifier_status === "downgraded").length
  return {
    claims: { total: all.length, verified, downgraded, other: all.length - verified - downgraded, byType },
    sbom: { crossCheck: tools.some((t) => t.ok) && rep.jaccard != null ? "Performed" : "Not performed", confidence: rep.confidence ?? "—", tools },
    integrity: Object.entries(report.integrity?.artifact_sha256 ?? {}).map(([name, sha256]) => ({ name, sha256 })),
    limits: ((report.coverage?.unsupported ?? []) as unknown[]).map(String),
    thresholds: String(report.coverage?.thresholds ?? ""),
  }
}
