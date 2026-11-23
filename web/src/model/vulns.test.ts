import report from "../fixtures/report.mini-shop.json"
import { Report } from "../api/types"
import { cvePanel, filterVulns, NO_FILTER, paginate, sortVulns, vulnRows } from "./vulns"
import { dash, relativeTime, severityRank, shortCommit, splitPurl } from "./format"
import { overviewModel } from "./overview"

const rep = report as unknown as Report
const clone = (): Report => JSON.parse(JSON.stringify(rep))
const withVuln = (mut: (s: Record<string, any>) => void): Report => {
  const r = clone()
  const f = r.findings.find((x) => x.cls === "vuln")!
  mut(f.signals)
  r.findings = [f]
  return r
}

test("format helpers handle missing values", () => {
  expect([dash(null), dash(undefined), dash(NaN), dash(""), dash(0)]).toEqual(["—", "—", "—", "—", "0"])
  expect(shortCommit("df87b2a5e64e")).toBe("df87b2a")
  expect(shortCommit(null)).toBe("—")
  expect(splitPurl("pkg:pypi/requests@2.25.1")).toEqual({ name: "requests", version: "2.25.1", ecosystem: "pypi" })
  expect(splitPurl("pkg:npm/lodash")).toMatchObject({ name: "lodash", version: null })
  expect(severityRank("Critical")).toBeLessThan(severityRank("Unknown"))
  expect(relativeTime("2026-11-23T10:00:00Z", new Date("2026-11-23T12:00:00Z"))).toBe("2 hr ago")
  expect(relativeTime("garbage")).toBe("—")
})

test("vulnRows keeps only vulnerabilities, worst first", () => {
  const rows = vulnRows(rep)
  expect(rows.length).toBe(rep.summary.vulnerabilities)
  const ranks = rows.filter((r) => r.severity !== "Unknown").map((r) => severityRank(r.severity))
  expect(ranks).toEqual([...ranks].sort((a, b) => a - b))
  expect(rows[1]).toMatchObject({ advisoryId: "GHSA-xvch-5gv4-984h", severity: "Critical", cvss: 9.8 })
})
test("a row splits component and installed version from the package url", () => {
  const r = vulnRows(rep).find((x) => x.advisoryId === "GHSA-9wx4-h78v-vm56")!
  expect(r).toMatchObject({ component: "requests", installed: "2.25.1", fixed: "2.32.0", dependency: "Direct" })
})
test("a malicious-package advisory with no severity is Unknown, with null cvss and fixed version", () => {
  const r = vulnRows(rep).find((x) => x.advisoryId === "MAL-2025-25502")!
  expect([r.severity, r.cvss, r.fixed]).toEqual(["Unknown", null, null])
})
test("direct is Transitive when false and an em dash when absent", () => {
  expect(vulnRows(rep).find((x) => x.advisoryId === "GHSA-xvch-5gv4-984h")!.dependency).toBe("Transitive")
  expect(vulnRows(withVuln((s) => delete s.direct))[0].dependency).toBe("—")
})
test("cvePanel carries path, band, reason, evidence ids and claims", () => {
  const f = rep.findings.find((x) => x.cls === "vuln" && x.signals.advisory_id === "GHSA-xvch-5gv4-984h")!
  const p = cvePanel(f)
  expect(p.path).toEqual(["pkg:npm/mkdirp@0.5.1", "pkg:npm/minimist@0.0.8"])
  expect([p.band, p.bandReason]).toEqual([f.band, f.band_reason])
  expect(p.evidenceIds).toEqual(f.raw_evidence_ids)
  expect(p.claims.length).toBeGreaterThan(0)
  expect(p.source.url).toContain("osv.dev")
})
test("cvePanel tolerates a finding with no explanation, path or signals", () => {
  const p = cvePanel({ id: "x", cls: "vuln", subject: "pkg:pypi/a@1", title: "t", locator: "L", detector: "d", classification: "C", signals: {}, band: "P3", band_reason: "", status: "open", raw_evidence_ids: [], attack_class: null })
  expect([p.claims, p.path, p.fixed, p.cvss]).toEqual([[], [], null, null])
})
test("filterVulns combines search, severity and dependency", () => {
  const rows = vulnRows(rep)
  expect(filterVulns(rows, { ...NO_FILTER, search: "REQUESTS" }).every((r) => r.component === "requests")).toBe(true)
  const f = filterVulns(rows, { ...NO_FILTER, severity: "Medium", dependency: "Transitive" })
  expect(f.length).toBeGreaterThan(0)
  expect(f.every((r) => r.severity === "Medium" && r.dependency === "Transitive")).toBe(true)
  expect(filterVulns(rows, { ...NO_FILTER, search: "zzzz-nothing" })).toEqual([])
})
test("sorting by priority band orders P0 first", () => {
  expect(sortVulns(vulnRows(rep), "band")[0].band).toBe("P0")
  expect(sortVulns(vulnRows(rep), "cvss")[0].cvss).toBe(9.8)
})
test("paginate reports from, to and pages, and clamps the page", () => {
  const r = (n: number) => Array.from({ length: n }, (_, i) => i)
  expect(paginate(r(95), 2, 9)).toMatchObject({ from: 10, to: 18, pages: 11, total: 95 })
  expect(paginate(r(5), 9, 9).page).toBe(1)
  expect(paginate([], 1, 9)).toMatchObject({ from: 0, to: 0, total: 0, pages: 1 })
})
test("a 500-vulnerability report is handled without truncation in the model", () => {
  const r = clone()
  const base = r.findings.find((f) => f.cls === "vuln")!
  r.findings = Array.from({ length: 500 }, (_, i) => ({ ...base, id: `v${i}`, signals: { ...base.signals, advisory_id: `GHSA-${i}` } }))
  expect(vulnRows(r).length).toBe(500)
})

test("overviewModel counts match the report summary", () => {
  const m = overviewModel(rep)
  expect(m.kpis).toMatchObject({ components: 13, vulnerabilities: 13, suspicious: 12, containerCi: 8, relationships: 13 })
  expect(m.kpis.critical).toBe(1)
  expect(m.repo).toMatchObject({ name: "guardian-fixture", branch: null, status: "Completed" })
  expect(m.recent.length).toBe(4)
  expect(m.analysis).toEqual({ done: 16, total: 16, warnings: 1 })
})
test("the severity bar omits Unknown unless present", () => {
  expect(overviewModel(rep).severityBar.map((s) => s.severity)).toEqual(["Critical", "High", "Medium", "Low", "Unknown"])
  const noUnknown = clone()
  noUnknown.findings = noUnknown.findings.filter((f) => f.signals.severity_band)
  expect(overviewModel(noUnknown).severityBar.map((s) => s.severity)).toEqual(["Critical", "High", "Medium", "Low"])
})
test("a report with zero findings gives zero counts and an empty recent list", () => {
  const e = clone()
  e.findings = []
  e.summary = { ...e.summary, vulnerabilities: 0 }
  const m = overviewModel(e)
  expect([m.kpis.critical, m.recent.length, m.affectedComponents]).toEqual([0, 0, 0])
})
test("a failed pipeline node marks the scan Failed", () => {
  const f = clone()
  f.coverage.node_status.vuln_intel = "failed"
  expect(overviewModel(f).repo.status).toBe("Failed")
})

test("a malicious-package advisory with unknown severity but band P0 is ranked first", () => {
  expect(vulnRows(rep)[0].advisoryId).toBe("MAL-2025-25502")
})
