import { ReactNode } from "react"
import { MemoryRouter } from "react-router-dom"
import { act, renderHook, waitFor } from "@testing-library/react"
import report from "../fixtures/report.mini-shop.json"
import events from "../fixtures/events.mini-shop.json"
import runs from "../fixtures/runs.json"
import { ApiError } from "../api/types"
import * as client from "../api/client"
import * as ev from "../api/events"
import { useCurrentRun, useRunData, useRuns, useScan } from "./hooks"

vi.mock("../api/client")
vi.mock("../api/events")
const c = vi.mocked(client)
const e = vi.mocked(ev)
afterEach(() => vi.resetAllMocks())

const wrap = (url = "/") => ({ children }: { children: ReactNode }) => <MemoryRouter initialEntries={[url]}>{children}</MemoryRouter>

test("useRuns reports loading, then ready", async () => {
  c.listRuns.mockResolvedValue(runs as any)
  const { result } = renderHook(() => useRuns(), { wrapper: wrap() })
  expect(result.current.state).toBe("loading")
  await waitFor(() => expect(result.current.state).toBe("ready"))
})
test("a failing request becomes an error state naming the path, not an empty ready state", async () => {
  c.listRuns.mockRejectedValue(new ApiError("/runs", null, "Failed to fetch"))
  const { result } = renderHook(() => useRuns(), { wrapper: wrap() })
  await waitFor(() => expect(result.current).toMatchObject({ state: "error", error: { path: "/runs" } }))
})
test("with no run in the url the newest finished run is selected", async () => {
  c.listRuns.mockResolvedValue([{ run_id: "new", status: "running" }, { run_id: "b", status: "done" }, { run_id: "a", status: "done" }] as any)
  const { result } = renderHook(() => useCurrentRun(), { wrapper: wrap() })
  await waitFor(() => expect(result.current.runId).toBe("b"))
})
test("an explicit run in the url wins", async () => {
  c.listRuns.mockResolvedValue([{ run_id: "b", status: "done" }] as any)
  const { result } = renderHook(() => useCurrentRun(), { wrapper: wrap("/?run=zzz") })
  expect(result.current.runId).toBe("zzz")
})
test("no runs at all gives a null run id", async () => {
  c.listRuns.mockResolvedValue([])
  const { result } = renderHook(() => useCurrentRun(), { wrapper: wrap() })
  await waitFor(() => expect(result.current.runs.state).toBe("ready"))
  expect(result.current.runId).toBeNull()
})
test("a 404 for the run sets notAvailable", async () => {
  c.getReport.mockRejectedValue(new ApiError("/runs/x/report", 404, ""))
  c.getViz.mockRejectedValue(new ApiError("/runs/x/viz", 404, ""))
  const { result } = renderHook(() => useRunData("x"), { wrapper: wrap() })
  await waitFor(() => expect(result.current.notAvailable).toBe(true))
})
test("useRunData loads report and viz for a run", async () => {
  c.getReport.mockResolvedValue(report as any)
  c.getViz.mockResolvedValue({ nodes: [], edges: [], blast: {} })
  const { result } = renderHook(() => useRunData("x"), { wrapper: wrap() })
  await waitFor(() => expect(result.current.report.state).toBe("ready"))
  expect(result.current.viz.state).toBe("ready")
})

function fakeStream() {
  let on: any = {}
  e.subscribeEvents.mockImplementation((_id, onEvent, onEnd, onError) => { on = { onEvent, onEnd, onError }; return () => {} })
  return { get: () => on }
}
test("useScan posts the url, follows events and ends with the run status", async () => {
  c.startScan.mockResolvedValue({ run_id: "r1" })
  c.getReport.mockResolvedValue(report as any)
  const s = fakeStream()
  const { result } = renderHook(() => useScan(), { wrapper: wrap() })
  await act(async () => { await result.current.start("https://github.com/a/b") })
  expect(result.current.status).toBe("running")
  act(() => { for (const x of events.filter((x) => x.node !== "run")) s.get().onEvent(x) })
  act(() => s.get().onEnd({ status: "done" }))
  expect(result.current.status).toBe("done")
  expect(result.current.events.length).toBe(events.length - 1)
  await waitFor(() => expect(result.current.report?.state).toBe("ready"))
})
test("replayed events are not appended twice", async () => {
  c.startScan.mockResolvedValue({ run_id: "r1" })
  const s = fakeStream()
  const { result } = renderHook(() => useScan(), { wrapper: wrap() })
  await act(async () => { await result.current.start("x") })
  act(() => { s.get().onEvent(events[0]); s.get().onEvent(events[0]) })
  expect(result.current.events.length).toBe(1)
})
test("a failed start sets error and status failed", async () => {
  c.startScan.mockRejectedValue(new ApiError("/runs", 422, "bad url"))
  const { result } = renderHook(() => useScan(), { wrapper: wrap() })
  await act(async () => { await result.current.start("nope") })
  expect(result.current.status).toBe("failed")
  expect(result.current.error).toMatchObject({ status: 422 })
})
test("a failed run does not fetch a report and exposes the run error", async () => {
  c.startScan.mockResolvedValue({ run_id: "r1" })
  c.getRun.mockResolvedValue({ run_id: "r1", error: "RuntimeError: boom" } as any)
  const s = fakeStream()
  const { result } = renderHook(() => useScan(), { wrapper: wrap() })
  await act(async () => { await result.current.start("x") })
  act(() => s.get().onEnd({ status: "failed" }))
  expect(result.current.status).toBe("failed")
  expect(c.getReport).not.toHaveBeenCalled()
  await waitFor(() => expect(result.current.runError).toBe("RuntimeError: boom"))
})

test("when the run changes the old run's data is never shown", async () => {
  let resolveB: (v: any) => void = () => {}
  c.getReport.mockImplementation((id: string) => (id === "a" ? Promise.resolve({ run_id: "a" } as any) : new Promise((r) => (resolveB = r))))
  c.getViz.mockResolvedValue({ nodes: [], edges: [], blast: {} })
  const { result, rerender } = renderHook(({ id }) => useRunData(id), { wrapper: wrap(), initialProps: { id: "a" } })
  await waitFor(() => expect(result.current.report.state).toBe("ready"))
  rerender({ id: "b" })
  expect(result.current.report.state).toBe("loading")
  resolveB({ run_id: "b" })
})
