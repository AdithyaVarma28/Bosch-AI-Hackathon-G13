import report from "../fixtures/report.mini-shop.json"
import events from "../fixtures/events.mini-shop.json"
import { getReport, listRuns, startScan } from "./client"
import { subscribeEvents } from "./events"

const ok = (body: unknown, status = 200) => vi.fn().mockResolvedValue({ ok: status < 400, status, json: async () => body })
afterEach(() => vi.unstubAllGlobals())

test("getReport returns the parsed report", async () => {
  vi.stubGlobal("fetch", ok(report))
  expect((await getReport("r1")).repo.name).toBe("guardian-fixture")
})
test("a non-2xx response throws ApiError with the path and status", async () => {
  vi.stubGlobal("fetch", ok({}, 404))
  await expect(getReport("r1")).rejects.toMatchObject({ path: "/runs/r1/report", status: 404 })
})
test("a network failure throws ApiError with null status", async () => {
  vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("Failed to fetch")))
  await expect(listRuns()).rejects.toMatchObject({ path: "/runs", status: null })
})
test("startScan sends only the repository url", async () => {
  const f = ok({ run_id: "x" })
  vi.stubGlobal("fetch", f)
  await startScan("https://github.com/a/b")
  expect(JSON.parse(f.mock.calls[0][1].body)).toEqual({ repo_url: "https://github.com/a/b" })
})

class FakeES {
  static last: FakeES
  closed = false
  onmessage: ((m: { data: string }) => void) | null = null
  onerror: (() => void) | null = null
  constructor(public url: string) { FakeES.last = this }
  close() { this.closed = true }
  emit(o: unknown) { this.onmessage?.({ data: JSON.stringify(o) }) }
}
test("subscribeEvents forwards events and calls onEnd on the final run message", () => {
  vi.stubGlobal("EventSource", FakeES)
  const seen: string[] = []
  let end: unknown = null
  subscribeEvents("r1", (e) => seen.push(e.node), (f) => (end = f), () => {})
  for (const e of events) FakeES.last.emit(e)
  expect(seen.length).toBe(events.length - 1)
  expect(end).toEqual({ status: "done" })
  expect(FakeES.last.closed).toBe(true)
})
test("unsubscribe closes the stream", () => {
  vi.stubGlobal("EventSource", FakeES)
  subscribeEvents("r1", () => {}, () => {}, () => {})()
  expect(FakeES.last.closed).toBe(true)
})
test("a stream error surfaces as ApiError", () => {
  vi.stubGlobal("EventSource", FakeES)
  let err: any
  subscribeEvents("r1", () => {}, () => {}, (e) => (err = e))
  FakeES.last.onerror?.()
  expect(err).toMatchObject({ path: "/runs/r1/events", status: null })
})
test("the captured fixtures match the declared types", () => {
  const classes = ["vuln", "anomaly", "container", "ci", "secret", "sbom_quality", "discrepancy"]
  expect(report.findings.every((f) => classes.includes(f.cls))).toBe(true)
  expect(events.at(-1)).toMatchObject({ node: "run" })
})
