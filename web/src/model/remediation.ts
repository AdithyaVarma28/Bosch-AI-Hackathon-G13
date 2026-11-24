import { Report, Severity } from "../api/types"
import { severityRank, splitPurl, toSeverity } from "./format"

export interface UpgradeOption {
  subject: string; name: string; installed: string | null; ecosystem: string; worst: Severity; count: number
  advisories: { advisoryId: string; findingId: string; severity: Severity; fixed: string | null; summary: string }[]
  /** The largest fixed version any advisory lists. Compatibility is not checked. */
  highestFix: string | null
}

// Numeric, segment-by-segment comparison ("2.10.0" > "2.9.0"). Non-numeric parts compare as text.
export function compareVersions(a: string, b: string): number {
  const pa = a.split(/[.+-]/), pb = b.split(/[.+-]/)
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] ?? "0", y = pb[i] ?? "0"
    const nx = /^\d+$/.test(x), ny = /^\d+$/.test(y)
    const d = nx && ny ? Number(x) - Number(y) : x.localeCompare(y)
    if (d !== 0) return d < 0 ? -1 : 1
  }
  return 0
}

/** The smallest fixed version that is newer than the installed one, per advisory. */
function pickFix(fixed: string[], installed: string | null): string | null {
  if (fixed.length === 0) return null
  const sorted = [...fixed].sort(compareVersions)
  const newer = installed ? sorted.filter((v) => compareVersions(v, installed) > 0) : sorted
  return (newer.length ? newer : sorted)[0]
}

export function upgradeOptions(report: Report): UpgradeOption[] {
  const by = new Map<string, UpgradeOption>()
  for (const f of report.findings ?? []) {
    if (f.cls !== "vuln") continue
    const { name, version, ecosystem } = splitPurl(f.subject)
    const fixedAll: string[] = Array.isArray(f.signals?.fixed_versions) ? f.signals.fixed_versions : []
    const sev = toSeverity(f.signals?.severity_band)
    let o = by.get(f.subject)
    if (!o) { o = { subject: f.subject, name, installed: version, ecosystem, worst: sev, count: 0, advisories: [], highestFix: null }; by.set(f.subject, o) }
    o.count++
    if (severityRank(sev) < severityRank(o.worst)) o.worst = sev
    o.advisories.push({ advisoryId: f.signals?.advisory_id ?? f.locator, findingId: f.id, severity: sev, fixed: pickFix(fixedAll, version), summary: f.signals?.summary ?? f.title })
  }
  for (const o of by.values()) {
    const fixes = o.advisories.map((a) => a.fixed).filter((x): x is string => !!x)
    o.highestFix = fixes.length ? fixes.sort(compareVersions).at(-1)! : null
    o.advisories.sort((a, b) => severityRank(a.severity) - severityRank(b.severity))
  }
  return [...by.values()].sort((a, b) => severityRank(a.worst) - severityRank(b.worst) || b.count - a.count || a.name.localeCompare(b.name))
}
