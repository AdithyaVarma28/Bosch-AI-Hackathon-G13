import report from "../fixtures/report.mini-shop.json"
import { Report, RunSummary } from "../api/types"
import { evidenceRows, evidenceCitedBy, filterEvidence } from "./evidence"
import { filterSbom, sbomModel, NO_SBOM_FILTER } from "./sbom"
import { filterRuns, runRows } from "./runs"

const rep = report as unknown as Report
const clone = (): Report => JSON.parse(JSON.stringify(rep))

// ---- SBOM -----------------------------------------------------------------
test("sbomModel lists every component with version, scope and dependency type", () => {
  const m = sbomModel(rep)
  expect(m.rows.length).toBe(13)
  const deb = m.rows.find((r) => r.name === "debug")!
  expect(deb).toMatchObject({ version: "4.3.4", ecosystem: "npm", scope: "Production", dependency: "Direct", source: "lockfile", registry: "registry.npmjs.org" })
})
test("the summary reports confidence, resolution and which tools failed, without hiding it", () => {
  const s = sbomModel(rep).summary
  expect(s).toMatchObject({ count: 13, confidence: "low", resolution: "committed" })
  expect(s.tools.map((t) => [t.name, t.ok])).toEqual([["syft", false], ["trivy", false]])
  expect(s.notes.length).toBe(3)
})
test("a component without a version or origin shows nulls, not undefined", () => {
  const r = clone()
  r.sbom.components[0] = { purl: "pkg:npm/x", name: "x", ecosystem: "npm" } as any
  const row = sbomModel(r).rows[0]
  expect([row.version, row.registry, row.license, row.integrity, row.hasInstallScript]).toEqual([null, null, null, null, false])
  expect(row.dependency).toBe("—")
})
test("filterSbom combines search, ecosystem, scope and dependency type", () => {
  const rows = sbomModel(rep).rows
  expect(filterSbom(rows, { ...NO_SBOM_FILTER, search: "FLASK" }).map((r) => r.name)).toEqual(["flask"])
  expect(filterSbom(rows, { ...NO_SBOM_FILTER, ecosystem: "pypi" }).every((r) => r.ecosystem === "pypi")).toBe(true)
  expect(filterSbom(rows, { ...NO_SBOM_FILTER, scope: "Development" }).every((r) => r.scope === "Development")).toBe(true)
  expect(filterSbom(rows, { ...NO_SBOM_FILTER, dependency: "Transitive" }).length).toBe(2)
})
test("a report with no sbom section yields an empty model", () => {
  const r = clone(); delete (r as any).sbom
  expect(sbomModel(r)).toMatchObject({ rows: [], summary: { count: 0, confidence: "—" } })
})

// ---- Evidence ---------------------------------------------------------------
test("evidenceRows lists every evidence item with the number of findings that cite it", () => {
  const rows = evidenceRows(rep)
  expect(rows.length).toBe(Object.keys(rep.evidence).length)
  const cited = rep.findings.reduce((a, f) => a + f.raw_evidence_ids.length, 0)
  expect(rows.reduce((a, r) => a + r.citedBy, 0)).toBe(cited)
})
test("evidenceCitedBy returns the findings and where to open them", () => {
  const f = rep.findings.find((x) => x.cls === "vuln")!
  const found = evidenceCitedBy(rep, f.raw_evidence_ids[0])
  expect(found.some((c) => c.findingId === f.id)).toBe(true)
  expect(found.find((c) => c.findingId === f.id)!.href).toContain(`/vulnerabilities?`)
  const an = rep.findings.find((x) => x.cls === "anomaly")!
  expect(evidenceCitedBy(rep, an.raw_evidence_ids[0]).find((c) => c.findingId === an.id)!.href).toContain("/anomalies?")
})
test("filterEvidence searches locator, source and excerpt and filters by kind", () => {
  const rows = evidenceRows(rep)
  expect(filterEvidence(rows, { search: "dockerfile", kind: "All" }).length).toBeGreaterThan(0)
  expect(filterEvidence(rows, { search: "", kind: "derived" }).every((r) => r.kind === "derived")).toBe(true)
  expect(filterEvidence(rows, { search: "zzz-none", kind: "All" })).toEqual([])
})
test("a report with no evidence gives an empty list", () => {
  const r = clone(); r.evidence = {} as any
  expect(evidenceRows(r)).toEqual([])
  delete (r as any).evidence
  expect(evidenceRows(r)).toEqual([])
})

// ---- Runs ---------------------------------------------------------------------
const runs: RunSummary[] = [
  { run_id: "b", repo_name: "shop", target: "https://github.com/a/shop", status: "done", commit: "abcdef1234", finished_at: "2026-11-23T12:00:00Z", error: null },
  { run_id: "c", repo_name: "api", target: "C:/x/api", status: "failed", commit: null, finished_at: "2026-11-23T11:00:00Z", error: "RuntimeError: boom" },
  { run_id: "a", repo_name: "web", target: "https://github.com/a/web", status: "running", commit: null, finished_at: null, error: null },
]
test("runRows shortens the commit, labels the status and keeps the error", () => {
  const r = runRows(runs)
  expect(r[0]).toMatchObject({ id: "b", commit: "abcdef1", status: "Completed", canOpen: true })
  expect(r[1]).toMatchObject({ status: "Failed", error: "RuntimeError: boom", canOpen: false })
  expect(r[2]).toMatchObject({ status: "Running", canOpen: false, finishedAt: null })
})
test("filterRuns searches name, target and run id and filters by status", () => {
  const r = runRows(runs)
  expect(filterRuns(r, { search: "GITHUB", status: "All" }).map((x) => x.id)).toEqual(["b", "a"])
  expect(filterRuns(r, { search: "", status: "Failed" }).map((x) => x.id)).toEqual(["c"])
})
