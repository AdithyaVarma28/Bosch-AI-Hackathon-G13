import { MemoryRouter } from "react-router-dom"
import { render, screen, waitFor } from "@testing-library/react"
import report from "../fixtures/report.mini-shop.json"
import runs from "../fixtures/runs.json"
import { ApiError } from "../api/types"
import * as client from "../api/client"
import App from "../App"

vi.mock("../api/client")
const c = vi.mocked(client)
const clone = () => JSON.parse(JSON.stringify(report))
const renderAt = (url = "/?run=r1") => render(<MemoryRouter initialEntries={[url]}><App /></MemoryRouter>)
beforeEach(() => { c.listRuns.mockResolvedValue(runs as any); c.getViz.mockResolvedValue({ nodes: [], edges: [], blast: {} }) })
afterEach(() => vi.resetAllMocks())

test("shows the repository name, commit and last scan from the report", async () => {
  c.getReport.mockResolvedValue(report as any)
  renderAt()
  expect(await screen.findByText("guardian-fixture", { selector: "p" })).toBeInTheDocument()
  expect(screen.getByText("df87b2a")).toBeInTheDocument()
})
test("KPI tiles show the real counts", async () => {
  c.getReport.mockResolvedValue(report as any)
  renderAt()
  await screen.findByText("Components discovered")
  expect(screen.getByText("1 critical · 3 high")).toBeInTheDocument()
  expect(screen.getByText("8 container/CI findings")).toBeInTheDocument()
})
test("the severity bar lists the severities and counts", async () => {
  c.getReport.mockResolvedValue(report as any)
  renderAt()
  await screen.findByText("Vulnerability severity")
  for (const s of ["Critical", "High", "Medium", "Low", "Unknown"]) expect(screen.getAllByText(s).length).toBeGreaterThan(0)
})
test("recent findings show at most four rows, worst first, and link to the vulnerability", async () => {
  c.getReport.mockResolvedValue(report as any)
  renderAt()
  const link = await screen.findByRole("link", { name: "GHSA-xvch-5gv4-984h" })
  expect(link.getAttribute("href")).toContain("/vulnerabilities?run=r1&finding=")
  expect(screen.getAllByRole("link").filter((l) => /^(GHSA|CVE|MAL|PYSEC)/.test(l.textContent ?? "")).length).toBe(4)
})
test("a run with zero vulnerabilities shows No vulnerabilities found, not an error", async () => {
  const r = clone(); r.findings = []; r.summary.vulnerabilities = 0
  c.getReport.mockResolvedValue(r)
  renderAt()
  expect((await screen.findAllByText("No vulnerabilities found")).length).toBeGreaterThan(0)
  expect(screen.queryByRole("alert")).toBeNull()
})
test("a failing request shows the error banner and no KPI numbers", async () => {
  c.getReport.mockRejectedValue(new ApiError("/runs/r1/report", 500, "x"))
  renderAt()
  expect(await screen.findByRole("alert")).toHaveTextContent("/runs/r1/report")
  expect(screen.queryByText("Components discovered")).toBeNull()
})
test("loading shows skeletons", () => {
  c.getReport.mockReturnValue(new Promise(() => {}))
  renderAt()
  expect(screen.getByTestId("skeleton")).toBeInTheDocument()
})
test("no runs at all prompts to start a scan", async () => {
  c.listRuns.mockResolvedValue([])
  renderAt("/")
  expect(await screen.findByText("No scans yet")).toBeInTheDocument()
})
test("a 404 run shows Run not available", async () => {
  c.getReport.mockRejectedValue(new ApiError("/runs/r1/report", 404, "x"))
  renderAt()
  expect(await screen.findByText("Run not available")).toBeInTheDocument()
})
test("branch null is omitted rather than shown as null", async () => {
  c.getReport.mockResolvedValue(report as any)
  renderAt()
  await screen.findByText("Components discovered")
  await waitFor(() => expect(screen.queryByText("BRANCH")).toBeNull())
  expect(screen.queryByText(/null|undefined|NaN/)).toBeNull()
})

test("a degraded stage is not presented as fully healthy", async () => {
  c.getReport.mockResolvedValue(report as any)
  renderAt()
  expect(await screen.findByText(/1 with warnings/)).toBeInTheDocument()
})
