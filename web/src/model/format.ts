import { Severity } from "../api/types"

export const dash = (v: unknown): string =>
  v === null || v === undefined || v === "" || (typeof v === "number" && Number.isNaN(v)) ? "—" : String(v)

export const shortCommit = (c: string | null | undefined): string => (c ? c.slice(0, 7) : "—")

/** "pkg:pypi/requests@2.31.0" -> { name: "requests", version: "2.31.0", ecosystem: "pypi" } */
export function splitPurl(purl: string): { name: string; version: string | null; ecosystem: string } {
  const body = purl.replace(/^pkg:/, "")
  const slash = body.indexOf("/")
  const ecosystem = slash >= 0 ? body.slice(0, slash) : ""
  const rest = slash >= 0 ? body.slice(slash + 1) : body
  const at = rest.lastIndexOf("@")
  if (at > 0) return { name: decodeURIComponent(rest.slice(0, at)), version: rest.slice(at + 1) || null, ecosystem }
  return { name: decodeURIComponent(rest), version: null, ecosystem }
}

const ORDER: Severity[] = ["Critical", "High", "Medium", "Low", "Unknown"]
export const severityRank = (s: Severity): number => ORDER.indexOf(s)

export function toSeverity(v: unknown): Severity {
  return typeof v === "string" && (ORDER as string[]).includes(v) ? (v as Severity) : "Unknown"
}

export function relativeTime(iso: string | null | undefined, now: Date = new Date()): string {
  if (!iso) return "—"
  const t = Date.parse(iso)
  if (Number.isNaN(t)) return "—"
  const s = Math.max(0, Math.round((now.getTime() - t) / 1000))
  if (s < 60) return "just now"
  if (s < 3600) return `${Math.floor(s / 60)} min ago`
  if (s < 86400) return `${Math.floor(s / 3600)} hr ago`
  return `${Math.floor(s / 86400)} d ago`
}
