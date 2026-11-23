import { MemoryRouter } from "react-router-dom"
import { render, screen, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import report from "../fixtures/report.mini-shop.json"
import runs from "../fixtures/runs.json"
import { ApiError } from "../api/types"
import * as client from "../api/client"
import App from "../App"

vi.mock("../api/client")
const c = vi.mocked(client)
const renderAt = (url = "/anomalies?run=r1") => render(<MemoryRouter initialEntries={[url]}><App /></MemoryRouter>)
beforeEach(() => {
  c.listRuns.mockResolvedValue(runs as any)
  c.getViz.mockResolvedValue({ nodes: [], edges: [], blast: {} })
  c.getReport.mockResolvedValue(report as any)
  c.getEvidence.mockResolvedValue({ id: "e", kind: "raw", source: "s", locator: "package-lock.json:42", excerpt: "integrity sha512-abc", sha256: "x", captured_at: "", run_id: "r1" })
})
afterEach(() => vi.resetAllMocks())
const list = () => within(screen.getByText("Detected changes").closest("section")!)

test("lists every anomaly-class finding and selects the first", async () => {
  renderAt()
  await screen.findByText("Detected changes")
  expect(list().getAllByRole("button").length).toBeGreaterThan(15)
  expect(screen.getByText("What changed")).toBeInTheDocument()
})
test("the not-confirmed-threats notice is always shown", async () => {
  renderAt()
  expect(await screen.findByText(/Signals are not confirmed threats/)).toBeInTheDocument()
})
test("tabs show the counts", async () => {
  renderAt()
  expect(await screen.findByText(/All signals\s+\d+/)).toBeInTheDocument()
  expect(screen.getByText(/New\s+\d+/)).toBeInTheDocument()
})
test("selecting an item shows its detail and a diff for a version jump", async () => {
  renderAt()
  await userEvent.click(await screen.findByText(/Major version jump/))
  expect(screen.getByText("2.6.9")).toBeInTheDocument()
  expect(screen.getByText("4.3.4")).toBeInTheDocument()
})
test("evidence excerpt is shown when there is no diff", async () => {
  renderAt()
  await userEvent.click(await screen.findByText(/Container runs as root/))
  expect(await screen.findAllByText("package-lock.json:42")).not.toHaveLength(0)
})
test("the Comparing line shows baseline and scan commits, and is hidden without history", async () => {
  renderAt()
  expect(await screen.findByText(/Comparing 7538df0 → df87b2a/)).toBeInTheDocument()
})
test("no history hides the Comparing line instead of showing undefined", async () => {
  const r = JSON.parse(JSON.stringify(report)); r.history = []
  c.getReport.mockResolvedValue(r)
  renderAt()
  await screen.findByText("Detected changes")
  expect(screen.queryByText(/Comparing/)).toBeNull()
  expect(screen.queryByText(/undefined/)).toBeNull()
})
test("an empty run shows No suspicious changes detected", async () => {
  const r = JSON.parse(JSON.stringify(report)); r.findings = []
  c.getReport.mockResolvedValue(r)
  renderAt()
  expect(await screen.findByText("No suspicious changes detected")).toBeInTheDocument()
})
test("a failing request shows the error banner", async () => {
  c.getReport.mockRejectedValue(new ApiError("/runs/r1/report", null, "x"))
  renderAt()
  expect(await screen.findByRole("alert")).toBeInTheDocument()
})
test("the selection survives a reload through ?signal=", async () => {
  const id = (report as any).findings.find((f: any) => f.title.startsWith("Major version jump")).id
  renderAt(`/anomalies?run=r1&signal=${id}`)
  expect(await screen.findByText("4.3.4")).toBeInTheDocument()
})
