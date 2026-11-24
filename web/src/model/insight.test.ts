import report from "../fixtures/report.mini-shop.json"
import { Report } from "../api/types"
import { agentModel } from "./agents"
import { filterRisk, riskModel } from "./risk"
import { upgradeOptions } from "./remediation"
import { validationModel } from "./validation"

const rep = report as unknown as Report
const clone = (): Report => JSON.parse(JSON.stringify(rep))

// ---- Agent activity -----------------------------------------------------------
test("every pipeline stage is listed with a plain-language label and status", () => {
  const m = agentModel(rep)
  expect(m.stages.length).toBe(Object.keys(rep.coverage.node_status).length)
  expect(m.stages.find((s) => s.node === "ingest")).toMatchObject({ status: "Completed", label: expect.stringMatching(/repository/i) })
})
test("degraded stages explain why", () => {
  const sbom = agentModel(rep).stages.find((s) => s.node === "resolver_sbom")!
  expect(sbom.status).toBe("Completed with warnings")
  expect(sbom.reason).toMatch(/syft/i)
})
test("failed and skipped stages are reported with their reason", () => {
  const r = clone()
  r.coverage.node_status.secrets = "failed"
  r.coverage.node_status.container_ci = "skipped"
  r.coverage.skipped = { container_ci: "no Dockerfiles" }
  const s = agentModel(r).stages
  expect(s.find((x) => x.node === "secrets")!.status).toBe("Failed")
  expect(s.find((x) => x.node === "container_ci")).toMatchObject({ status: "Skipped", reason: "no Dockerfiles" })
})
test("the llm state, code coverage, pipeline errors and dossier are summarised", () => {
  const m = agentModel(rep)
  expect(m.llm).toMatchObject({ configured: false })
  expect(m.llm.text).toMatch(/GROQ_API_KEY/)
  expect(m.code.filesTotal).toBeGreaterThan(0)
  expect(m.errors).toEqual([])
  expect(m.dossier?.appType).toBeTruthy()
})
test("a report without coverage or dossier does not crash", () => {
  const r = clone()
  delete (r as any).coverage
  delete (r as any).dossier
  const m = agentModel(r)
  expect(m.stages).toEqual([])
  expect(m.dossier).toBeNull()
})

// ---- Risk prioritization --------------------------------------------------------
test("bands count matches the report and Unprioritized appears only when present", () => {
  const m = riskModel(rep)
  expect(m.bands.map((b) => [b.band, b.count])).toEqual([["P0", 5], ["P1", 9], ["P2", 6], ["P3", 14]])
  const r = clone()
  r.findings[0].band = "Unprioritized"
  expect(riskModel(r).bands.at(-1)).toMatchObject({ band: "Unprioritized", count: 1 })
})
test("rows are ordered by band and carry the reason and a link to where the finding is shown", () => {
  const rows = riskModel(rep).rows
  expect(rows.length).toBe(rep.findings.length)
  expect(rows[0].band).toBe("P0")
  expect(rows[0].reason).toBeTruthy()
  expect(rows.find((r) => r.cls === "vuln")!.href).toContain("/vulnerabilities?finding=")
  expect(rows.find((r) => r.cls === "secret")!.href).toBeNull()
})
test("filterRisk filters by band, class and search", () => {
  const rows = riskModel(rep).rows
  expect(filterRisk(rows, { band: "P0", cls: "All", search: "" }).every((r) => r.band === "P0")).toBe(true)
  expect(filterRisk(rows, { band: "All", cls: "secret", search: "" }).length).toBe(1)
  expect(filterRisk(rows, { band: "All", cls: "All", search: "typosquat" }).length).toBeGreaterThan(0)
})
test("the thresholds disclaimer is passed through", () => {
  expect(riskModel(rep).disclaimer).toMatch(/unvalidated/i)
})

// ---- Remediation ------------------------------------------------------------------
test("upgrade options group advisories by component with the fixed versions listed", () => {
  const o = upgradeOptions(rep)
  const req = o.find((x) => x.name === "requests")!
  expect(req).toMatchObject({ installed: "2.25.1", count: 4, worst: "Medium" })
  expect(req.advisories.map((a) => a.fixed).sort()).toEqual(["2.31.0", "2.32.0", "2.32.4", "2.33.0"])
  expect(req.highestFix).toBe("2.33.0")
})
test("components are ordered by worst severity, then advisory count", () => {
  const o = upgradeOptions(rep)
  expect(o[0]).toMatchObject({ name: "minimist", worst: "Critical" })
  const sev = o.map((x) => x.worst)
  expect(sev.indexOf("Critical")).toBeLessThan(sev.indexOf("Medium"))
})
test("an advisory with no fixed version is shown as having none, not hidden", () => {
  const lodahs = upgradeOptions(rep).find((x) => x.name === "lodahs")!
  expect(lodahs.advisories.every((a) => a.fixed === null)).toBe(true)
  expect(lodahs.highestFix).toBeNull()
})
test("a report with no vulnerabilities has no upgrade options", () => {
  const r = clone(); r.findings = []
  expect(upgradeOptions(r)).toEqual([])
})
test("highestFix compares versions numerically, not as text", () => {
  const r = clone()
  const base = r.findings.find((x) => x.cls === "vuln" && x.subject === "pkg:pypi/requests@2.25.1")!
  const mk = (id: string, fixed: string) => ({ ...base, id, signals: { ...base.signals, advisory_id: id, fixed_versions: [fixed] } })
  r.findings = [mk("A", "2.9.0"), mk("B", "2.10.0")]
  expect(upgradeOptions(r)[0].highestFix).toBe("2.10.0")
})
test("per advisory the smallest fixed version newer than the installed one is chosen", () => {
  const r = clone()
  const f = r.findings.find((x) => x.cls === "vuln" && x.subject === "pkg:pypi/flask@2.0.1" && x.signals.fixed_versions.length === 2)!
  r.findings = [f]
  expect(upgradeOptions(r)[0].advisories[0].fixed).toBe("2.2.5")
})

// ---- Validation ----------------------------------------------------------------------
test("claim verification is counted by status and type", () => {
  const v = validationModel(rep)
  expect(v.claims.total).toBeGreaterThan(0)
  expect(v.claims.verified + v.claims.downgraded + v.claims.other).toBe(v.claims.total)
  expect(v.claims.downgraded).toBeGreaterThan(0)
  expect(v.claims.byType.fact + v.claims.byType.inference + v.claims.byType.unknown).toBe(v.claims.total)
})
test("the SBOM cross-check is reported honestly when the tools failed", () => {
  const v = validationModel(rep)
  expect(v.sbom.crossCheck).toBe("Not performed")
  expect(v.sbom.tools.every((t) => !t.ok)).toBe(true)
})
test("integrity hashes and known limits are listed", () => {
  const v = validationModel(rep)
  expect(v.integrity.length).toBeGreaterThan(0)
  expect(v.integrity[0].sha256).toMatch(/^[0-9a-f]{64}$/)
  expect(v.limits.length).toBeGreaterThan(0)
})
test("a report with no validation inputs yields zeros, not a crash", () => {
  const r = clone(); r.findings = []; delete (r as any).integrity; delete (r as any).dossier
  const v = validationModel(r)
  expect(v.claims.total).toBe(0)
  expect(v.integrity).toEqual([])
})
