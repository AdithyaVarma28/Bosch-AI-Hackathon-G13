import eventsFx from "../fixtures/events.mini-shop.json"
import report from "../fixtures/report.mini-shop.json"
import { Report, RunEvent } from "../api/types"
import { scanProgress, scanSteps, scanSummaryLine, STEP_NODES } from "./scan"

const events = eventsFx as RunEvent[]
const step = (evs: RunEvent[], key: string, status: "running" | "done" | "failed" = "running") => scanSteps(evs, status).find((s) => s.key === key)!

test("scanSteps always returns seven steps in order", () => {
  expect(scanSteps([], "running").map((s) => s.key)).toEqual(["discovery", "manifests", "sbom", "dependencies", "vulnerabilities", "anomalies", "report"])
})
test("every node in the captured event log is mapped to a step", () => {
  const mapped = Object.values(STEP_NODES).flat()
  for (const e of events.filter((e) => e.node !== "run")) expect(mapped).toContain(e.node)
})
test("the full captured log completes all seven steps and SBOM is degraded", () => {
  const s = scanSteps(events, "done")
  expect(s.every((x) => x.status === "done" || x.status === "degraded")).toBe(true)
  expect(s.find((x) => x.key === "sbom")!.status).toBe("degraded")
  expect(scanProgress(s)).toEqual({ done: 7, total: 7 })
})
test("a partial log shows earlier steps done and the next one running", () => {
  const s = scanSteps(events.slice(0, 3), "running")
  expect(s[0].status).toBe("done")
  expect(s[1].status).toBe("done")
  expect(s[2].status).toBe("running") // first step with nothing reported yet
  expect(s[3].status).toBe("running") // code_index reported, graph not yet: partially done
  expect(s[4].status).toBe("pending")
})
test("duplicated events give the same result", () => {
  expect(scanSteps([...events, ...events], "done")).toEqual(scanSteps(events, "done"))
})
test("a failed member makes the step failed and a failed run marks the first incomplete step failed", () => {
  expect(step([{ node: "vuln_intel", status: "failed" }], "vulnerabilities").status).toBe("failed")
  expect(scanSteps(events.slice(0, 3), "failed").filter((s) => s.status === "failed").map((s) => s.key)).toEqual(["sbom"])
})
test("durations are the sum of member seconds", () => {
  const sum = events.filter((e) => STEP_NODES.anomalies.includes(e.node)).reduce((a, e) => a + (e.seconds ?? 0), 0)
  expect(step(events, "anomalies", "done").seconds).toBeCloseTo(sum, 1)
})
test("steps with no events are pending while running and done when the run is done", () => {
  expect(scanSteps([], "running")[1].status).toBe("pending")
  expect(scanSteps([], "running")[0].status).toBe("running")
  const d = scanSteps([], "done")
  expect(d.every((s) => s.status === "done" && s.seconds === null)).toBe(true)
})
test("a step uses the message of its last reported member", () => {
  expect(step(events, "manifests", "done").description).toContain("declared deps")
})
test("scanSummaryLine formats counts and tolerates a null report", () => {
  expect(scanSummaryLine(report as unknown as Report)).toBe("13 components · 13 vulnerabilities · 20 anomaly signals")
  expect(scanSummaryLine(null)).toBe("")
})

test("a failed run marks only one step failed and never reports pending steps as done", () => {
  const evs = [{ node: "ingest", status: "failed" }]
  const s = scanSteps(evs, "failed")
  expect(s.filter((x) => x.status === "failed").map((x) => x.key)).toEqual(["discovery"])
  const d = scanSteps(evs, "done")
  expect(d.find((x) => x.key === "discovery")!.status).toBe("failed")
  expect(scanProgress(d).done).toBeLessThan(7)
})
