import { MemoryRouter } from "react-router-dom"
import { act, render, screen, waitFor } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import report from "../fixtures/report.mini-shop.json"
import events from "../fixtures/events.mini-shop.json"
import runs from "../fixtures/runs.json"
import { ApiError } from "../api/types"
import * as client from "../api/client"
import * as ev from "../api/events"
import App from "../App"

vi.mock("../api/client")
vi.mock("../api/events")
const c = vi.mocked(client)
const e = vi.mocked(ev)
let on: any
const renderAt = (url = "/scan") => render(<MemoryRouter initialEntries={[url]}><App /></MemoryRouter>)
beforeEach(() => {
  c.listRuns.mockResolvedValue(runs as any)
  c.startScan.mockResolvedValue({ run_id: "new1" })
  c.getViz.mockResolvedValue({ nodes: [], edges: [], blast: {} })
  c.getReport.mockResolvedValue(report as any)
  e.subscribeEvents.mockImplementation((_id, onEvent, onEnd, onError) => { on = { onEvent, onEnd, onError }; return () => {} })
})
afterEach(() => vi.resetAllMocks())

const start = async (url = "https://github.com/acme/shop") => {
  await userEvent.type(screen.getByLabelText("Repository URL"), url)
  await userEvent.click(screen.getByText("Start scan"))
}
const feed = (n: number) => act(() => { for (const x of events.filter((x) => x.node !== "run").slice(0, n)) on.onEvent(x) })

test("an invalid url shows an inline message and does not start a scan", async () => {
  renderAt()
  await start("not a url")
  expect(screen.getByRole("alert")).toHaveTextContent(/GitHub repository URL/)
  expect(c.startScan).not.toHaveBeenCalled()
})
test("a valid url starts a scan and shows seven steps", async () => {
  renderAt()
  await start()
  expect(c.startScan).toHaveBeenCalledWith("https://github.com/acme/shop")
  expect(await screen.findByText("0 of 7 stages completed")).toBeInTheDocument()
  expect(screen.getAllByRole("listitem").filter((li) => li.hasAttribute("data-status")).length).toBe(7)
})
test("events update the steps and the progress text", async () => {
  renderAt()
  await start()
  await screen.findByText("0 of 7 stages completed")
  feed(2)
  expect(await screen.findByText("2 of 7 stages completed")).toBeInTheDocument()
})
test("replayed events do not double count", async () => {
  renderAt()
  await start()
  await screen.findByText("0 of 7 stages completed")
  feed(2); feed(2)
  expect(screen.getByText("2 of 7 stages completed")).toBeInTheDocument()
})
test("completion shows the summary line and View Overview opens the new run", async () => {
  renderAt()
  await start()
  await screen.findByText("0 of 7 stages completed")
  feed(99)
  act(() => on.onEnd({ status: "done" }))
  expect(await screen.findByText(/13 components · 13 vulnerabilities · 20 anomaly signals/)).toBeInTheDocument()
  await userEvent.click(screen.getByText("View Overview"))
  await waitFor(() => expect(screen.getByTestId("topbar")).toHaveTextContent("RUN new1"))
})
test("Start scan is disabled while a scan is running", async () => {
  renderAt()
  await start()
  expect(await screen.findByText("Scanning…")).toBeDisabled()
})
test("a failed run shows its error and keeps the form usable", async () => {
  c.getRun.mockResolvedValue({ run_id: "new1", status: "failed", error: "RuntimeError: boom" } as any)
  renderAt()
  await start()
  await screen.findByText("0 of 7 stages completed")
  act(() => on.onEnd({ status: "failed" }))
  expect(await screen.findByText(/RuntimeError: boom/)).toBeInTheDocument()
  expect(screen.getByText("Start scan")).toBeEnabled()
})
test("a failed start request shows the error banner", async () => {
  c.startScan.mockRejectedValue(new ApiError("/runs", 422, "bad"))
  renderAt()
  await start()
  expect(await screen.findByRole("alert")).toHaveTextContent("422")
})
test("opening a finished run shows the completed state without starting anything", async () => {
  renderAt("/scan?run=r1")
  expect(await screen.findByText("Analysis complete", { exact: false })).toBeInTheDocument()
  expect(screen.getByText("7 of 7 stages completed", { exact: false })).toBeInTheDocument()
  expect(c.startScan).not.toHaveBeenCalled()
})
test("a 404 run shows Run not available", async () => {
  c.getReport.mockRejectedValue(new ApiError("/runs/zz/report", 404, ""))
  renderAt("/scan?run=zz")
  expect(await screen.findByText("Run not available")).toBeInTheDocument()
})
test("a degraded step is flagged and the scan still completes", async () => {
  renderAt()
  await start()
  await screen.findByText("0 of 7 stages completed")
  feed(99)
  act(() => on.onEnd({ status: "done" }))
  expect(await screen.findByText("completed with warnings")).toBeInTheDocument()
  expect(screen.getByText("7 of 7 stages completed", { exact: false })).toBeInTheDocument()
})
