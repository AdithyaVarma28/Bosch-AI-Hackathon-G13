import report from "../fixtures/report.mini-shop.json"
import { Report } from "../api/types"
import { anomalyCounts, anomalyItems } from "./anomalies"

const rep = report as unknown as Report
const items = anomalyItems(rep)
const byTitle = (t: string) => items.find((i) => i.title.includes(t))!

test("only anomaly, container, ci and discrepancy findings are listed (secrets and vulns are not)", () => {
  expect(items.every((i) => ["anomaly", "container", "ci", "discrepancy"].includes(i.kind))).toBe(true)
  expect(items.length).toBe(rep.findings.filter((f) => !["vuln", "secret"].includes(f.cls)).length)
})
test("a version jump finding yields a previous and current diff", () => {
  expect(byTitle("Major version jump").detail.diff).toEqual({ previous: "2.6.9", current: "4.3.4" })
})
test("a changed registry host yields a host diff", () => {
  expect(byTitle("Resolved source of lodash moved").detail.diff).toEqual({ previous: "registry.npmjs.org", current: "deps.example.invalid" })
})
test("a finding with no before and after has a null diff", () => {
  expect(byTitle("Container runs as root").detail.diff).toBeNull()
})
test("file and commit come from the locator and signals", () => {
  expect(byTitle("Container runs as root").detail.file).toBe("Dockerfile")
  expect(byTitle("Major version jump").detail.commit).toMatch(/^70459f7/)
  expect(byTitle("Major version jump").detail.file).toBeNull()
})
test("every item keeps its evidence ids and the baseline commit", () => {
  const f = rep.findings.find((x) => x.title === byTitle("Container runs as root").title)!
  expect(byTitle("Container runs as root").detail.evidenceIds).toEqual(f.raw_evidence_ids)
  expect(items[0].detail.baseline).toMatch(/^7538df0/)
})
test("items are ordered by band then title", () => {
  const order = ["P0", "P1", "P2", "P3"]
  const ranks = items.map((i) => order.indexOf(i.band))
  expect(ranks).toEqual([...ranks].sort((a, b) => a - b))
})
test("anomalyCounts reports all and new", () => {
  expect(anomalyCounts(items)).toEqual({ all: items.length, new: items.length })
})
test("an empty report gives an empty list and no history means a null baseline", () => {
  const e = JSON.parse(JSON.stringify(rep)) as Report
  e.findings = []
  expect(anomalyItems(e)).toEqual([])
  const n = JSON.parse(JSON.stringify(rep)) as Report
  n.history = []
  expect(anomalyItems(n)[0].detail.baseline).toBeNull()
})
test("missing locator and signals do not throw", () => {
  const e = JSON.parse(JSON.stringify(rep)) as Report
  e.findings = [{ ...e.findings.find((f) => f.cls === "anomaly")!, locator: "", signals: undefined as any }]
  expect(() => anomalyItems(e)).not.toThrow()
})
