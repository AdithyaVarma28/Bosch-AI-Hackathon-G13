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
const clone = () => JSON.parse(JSON.stringify(report))
const renderAt = (url: string) => render(<MemoryRouter initialEntries={[url]}><App /></MemoryRouter>)
beforeEach(() => {
  c.listRuns.mockResolvedValue(runs as any)
  c.getReport.mockResolvedValue(report as any)
  c.getViz.mockResolvedValue({ nodes: [], edges: [], blast: {} })
})
afterEach(() => vi.resetAllMocks())

// ---- Agent Activity ------------------------------------------------------------
test("agent activity lists every pipeline stage with its status", async () => {
  renderAt("/agents?run=r1")
  expect(await screen.findByText("Fetch and open the repository")).toBeInTheDocument()
  expect(screen.getAllByText("Completed").length).toBeGreaterThan(10)
})
test("a degraded stage shows why", async () => {
  renderAt("/agents?run=r1")
  expect(await screen.findByText(/syft: failed/i)).toBeInTheDocument()
  expect(screen.getAllByText("Completed with warnings").length).toBe(1)
})
test("the llm state and the dossier summary are shown, and no errors says so", async () => {
  renderAt("/agents?run=r1")
  expect(await screen.findByText(/GROQ_API_KEY/)).toBeInTheDocument()
  expect(screen.getAllByText(/web application \(flask\)/).length).toBeGreaterThan(0)
  expect(screen.getByText("No pipeline errors")).toBeInTheDocument()
})
test("pipeline errors are listed when present", async () => {
  const r = clone(); r.coverage.pipeline_errors = ["vuln_intel: timeout"]; r.coverage.node_status.vuln_intel = "failed"
  c.getReport.mockResolvedValue(r)
  renderAt("/agents?run=r1")
  expect(await screen.findByText("vuln_intel: timeout")).toBeInTheDocument()
  expect(screen.getAllByText("Failed").length).toBeGreaterThan(0)
})

// ---- Risk Prioritization ----------------------------------------------------------
test("risk shows the band counts and the unvalidated-threshold warning", async () => {
  renderAt("/risk?run=r1")
  const tiles = await screen.findByTestId("risk-bands")
  expect(tiles).toHaveTextContent("5P0")
  expect(tiles).toHaveTextContent("14P3")
  expect(screen.getByText(/unvalidated/i)).toBeInTheDocument()
})
test("risk rows show the reason and link to the finding", async () => {
  renderAt("/risk?run=r1")
  const row = (await screen.findAllByRole("row"))[1]
  expect(row).toHaveTextContent("P0")
  expect(within(row).getByRole("link").getAttribute("href")).toMatch(/^\/(vulnerabilities|anomalies)\?/)
})
test("clicking a band tile filters the list", async () => {
  renderAt("/risk?run=r1")
  await userEvent.click(await screen.findByRole("button", { name: /P3/ }))
  expect(screen.getByText(/14 of 34 findings/)).toBeInTheDocument()
})
test("risk search and class filter can narrow to nothing", async () => {
  renderAt("/risk?run=r1")
  await userEvent.type(await screen.findByLabelText("Search findings"), "zzz-none")
  expect(await screen.findByText("No findings match these filters")).toBeInTheDocument()
})
test("a run with no findings shows an empty state", async () => {
  const r = clone(); r.findings = []
  c.getReport.mockResolvedValue(r)
  renderAt("/risk?run=r1")
  expect(await screen.findByText("No findings to prioritise")).toBeInTheDocument()
})

// ---- Remediation ------------------------------------------------------------------
test("remediation lists components with the fixed versions from advisories", async () => {
  renderAt("/remediation?run=r1")
  const row = (await screen.findByText("requests")).closest("tr")!
  expect(row).toHaveTextContent("2.25.1")
  expect(row).toHaveTextContent("2.33.0")
})
test("remediation is clear that these are advisory data, not a verified plan", async () => {
  renderAt("/remediation?run=r1")
  expect(await screen.findByText(/not verified for compatibility/i)).toBeInTheDocument()
  expect(screen.getByText(/has not generated a remediation plan/i)).toBeInTheDocument()
})
test("an advisory without a fixed version says so", async () => {
  renderAt("/remediation?run=r1")
  await userEvent.click((await screen.findByText("lodahs")).closest("tr")!)
  expect((await screen.findAllByText("No fixed version listed")).length).toBeGreaterThan(0)
})
test("no vulnerabilities means nothing to upgrade", async () => {
  const r = clone(); r.findings = []
  c.getReport.mockResolvedValue(r)
  renderAt("/remediation?run=r1")
  expect(await screen.findByText("No upgrades needed")).toBeInTheDocument()
})

// ---- Validation -------------------------------------------------------------------
test("validation shows claim verification counts including downgraded claims", async () => {
  renderAt("/validation?run=r1")
  const tiles = await screen.findByTestId("claim-summary")
  expect(tiles).toHaveTextContent("Verified")
  expect(tiles).toHaveTextContent("Downgraded")
})
test("validation says the SBOM cross-check was not performed when the tools failed", async () => {
  renderAt("/validation?run=r1")
  expect(await screen.findByText("Not performed")).toBeInTheDocument()
  expect(screen.getByText(/syft: failed/i)).toBeInTheDocument()
})
test("validation lists artifact hashes and what Guardian cannot check", async () => {
  renderAt("/validation?run=r1")
  expect(await screen.findByText("facts.json")).toBeInTheDocument()
  expect(screen.getByText(/Runtime reachability/)).toBeInTheDocument()
})
test("validation does not pretend a formal validation report exists", async () => {
  renderAt("/validation?run=r1")
  expect(await screen.findByText(/no separate validation report was generated/i)).toBeInTheDocument()
})

// ---- Settings ---------------------------------------------------------------------
test("settings shows the connection and the analysis configuration, read-only", async () => {
  renderAt("/settings?run=r1")
  expect(await screen.findByText(/Connected/)).toBeInTheDocument()
  expect(screen.getAllByText(/GROQ_API_KEY/).length).toBeGreaterThan(0)
  expect(screen.getByText(/read-only/i)).toBeInTheDocument()
  expect(screen.queryByRole("button", { name: /save/i })).toBeNull()
})
test("settings shows the connection error when the server cannot be reached", async () => {
  c.listRuns.mockRejectedValue(new ApiError("/runs", null, "x"))
  renderAt("/settings")
  expect(await screen.findByRole("alert")).toHaveTextContent(/could not reach/i)
})
test("settings works with no run selected", async () => {
  c.listRuns.mockResolvedValue([])
  renderAt("/settings")
  expect(await screen.findByText("No run selected")).toBeInTheDocument()
})

// ---- shared -----------------------------------------------------------------------
test("a 404 run shows Run not available on the new pages", async () => {
  c.getReport.mockRejectedValue(new ApiError("/runs/zz/report", 404, ""))
  renderAt("/risk?run=zz")
  expect(await screen.findByText("Run not available")).toBeInTheDocument()
})
