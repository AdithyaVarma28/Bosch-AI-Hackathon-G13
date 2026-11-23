import { Band, Finding, Report } from "../api/types"

export interface AnomalyItem {
  id: string; title: string; subtitle: string; kind: "anomaly" | "container" | "ci" | "discrepancy"; band: Band; status: "New"
  commit: string | null
  detail: {
    whatChanged: string; file: string | null; commit: string | null
    diff: { previous: string; current: string } | null
    rationale: string; evidenceIds: string[]; baseline: string | null
  }
}

const KINDS = ["anomaly", "container", "ci", "discrepancy"]
const BAND_ORDER: Band[] = ["P0", "P1", "P2", "P3", "Unprioritized"]

// Real signal keys (from the captured fixture): version_jump {from,to}, resolved_host_changed {from_host,host},
// integrity/new-dependency {commit}, install_script {script,command}, non_registry_source {host,url}.
function diffOf(s: Record<string, any>): { previous: string; current: string } | null {
  if (s.from != null && s.to != null) return { previous: String(s.from), current: String(s.to) }
  if (s.from_host != null && s.host != null) return { previous: String(s.from_host), current: String(s.host) }
  return null
}

function fileOf(f: Finding): string | null {
  const loc = f.locator ?? ""
  const m = loc.match(/^([^@:]+\.[A-Za-z]+|Dockerfile|[\w./-]*\/[\w./-]+)(?:[:@].*)?$/)
  return m && !loc.startsWith("commit:") && !loc.startsWith("package:") && !loc.startsWith("registry:") && !loc.startsWith("name:") ? m[1] : null
}

export function anomalyItems(report: Report): AnomalyItem[] {
  const baseline = report.history?.find((h) => h.baseline)?.commit ?? null
  return report.findings
    .filter((f) => KINDS.includes(f.cls))
    .map((f): AnomalyItem => {
      const s = f.signals ?? {}
      const commit: string | null = typeof s.commit === "string" ? s.commit : null
      return {
        id: f.id,
        title: f.title,
        subtitle: f.locator || "—",
        kind: f.cls as AnomalyItem["kind"],
        band: f.band,
        status: "New",
        commit,
        detail: {
          whatChanged: f.title,
          file: fileOf(f),
          commit,
          diff: diffOf(s),
          rationale: f.band_reason || "",
          evidenceIds: f.raw_evidence_ids ?? [],
          baseline,
        },
      }
    })
    .sort((a, b) => BAND_ORDER.indexOf(a.band) - BAND_ORDER.indexOf(b.band) || a.title.localeCompare(b.title))
}

export function anomalyCounts(items: AnomalyItem[]): { all: number; new: number } {
  return { all: items.length, new: items.filter((i) => i.status === "New").length }
}
