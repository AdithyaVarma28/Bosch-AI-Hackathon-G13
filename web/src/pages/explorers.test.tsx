import { MemoryRouter } from "react-router-dom"
import { render, screen, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import report from "../fixtures/report.mini-shop.json"
import { ApiError } from "../api/types"
import * as client from "../api/client"
import App from "../App"

vi.mock("../api/client")
const c = vi.mocked(client)
const RUNS = [
  { run_id: "r2", repo_name: "shop", target: "https://github.com/acme/shop", status: "done", commit: "abcdef1234", finished_at: "2026-11-23T12:00:00Z", error: null },
  { run_id: "r3", repo_name: "api", target: "C:/x/api", status: "failed", commit: null, finished_at: "2026-11-23T11:00:00Z", error: "RuntimeError: boom" },
  { run_id: "r1", repo_name: "web", target: "https://github.com/acme/web", status: "running", commit: null, finished_at: null, error: null },
]
const renderAt = (url: string) => render(<MemoryRouter initialEntries={[url]}><App /></MemoryRouter>)
beforeEach(() => {
  c.listRuns.mockResolvedValue(RUNS as any)
  c.getReport.mockResolvedValue(report as any)
  c.getViz.mockResolvedValue({ nodes: [], edges: [], blast: {} })
})
afterEach(() => vi.resetAllMocks())

// ---- Repositories ------------------------------------------------------------
test("repositories lists every scan with status, commit and target", async () => {
  renderAt("/repositories")
  expect(await screen.findByText("shop")).toBeInTheDocument()
  expect(screen.getByText("abcdef1")).toBeInTheDocument()
  const table = within(screen.getByRole("table"))
  expect(table.getByText("Completed")).toBeInTheDocument()
  expect(table.getByText("Failed")).toBeInTheDocument()
  expect(table.getByText("Running")).toBeInTheDocument()
})
test("only completed scans can be opened, and opening one selects that run", async () => {
  renderAt("/repositories")
  await screen.findByText("shop")
  expect(screen.getAllByRole("link", { name: /^Open/ }).length).toBe(1)
  await userEvent.click(screen.getByRole("link", { name: /^Open/ }))
  expect(screen.getByTestId("topbar")).toHaveTextContent("RUN r2")
})
test("a failed scan shows its error", async () => {
  renderAt("/repositories")
  expect(await screen.findByText(/RuntimeError: boom/)).toBeInTheDocument()
})
test("search and status filter narrow the list", async () => {
  renderAt("/repositories")
  await userEvent.type(await screen.findByLabelText("Search repositories"), "acme/web")
  expect(screen.queryByText("shop")).toBeNull()
  expect(screen.getByText("web")).toBeInTheDocument()
  await userEvent.clear(screen.getByLabelText("Search repositories"))
  await userEvent.selectOptions(screen.getByLabelText("Status"), "Failed")
  expect(screen.getAllByRole("row").length).toBe(2)
})
test("no scans shows an empty state", async () => {
  c.listRuns.mockResolvedValue([])
  renderAt("/repositories")
  expect(await screen.findByText("No scans yet")).toBeInTheDocument()
})
test("a failing request shows the error banner", async () => {
  c.listRuns.mockRejectedValue(new ApiError("/runs", null, "x"))
  renderAt("/repositories")
  expect(await screen.findByRole("alert")).toHaveTextContent(/could not reach/i)
})

// ---- SBOM Explorer -------------------------------------------------------------
test("sbom explorer shows summary tiles and an honest note when the SBOM tools failed", async () => {
  renderAt("/sbom?run=r1")
  expect(await screen.findByTestId("sbom-summary")).toHaveTextContent("13Components")
  expect(screen.getByTestId("sbom-summary")).toHaveTextContent("lowConfidence")
  expect(screen.getByText(/syft: failed/i)).toBeInTheDocument()
  expect(screen.getByText(/built from native lockfile\/manifest parsing only/i)).toBeInTheDocument()
})
test("sbom table paginates and filters", async () => {
  renderAt("/sbom?run=r1")
  expect(await screen.findByText("Showing 1–10 of 13 components")).toBeInTheDocument()
  await userEvent.type(screen.getByLabelText("Search components"), "flask")
  expect(screen.getAllByRole("row").length).toBe(2)
  await userEvent.clear(screen.getByLabelText("Search components"))
  await userEvent.selectOptions(screen.getByLabelText("Ecosystem"), "npm")
  expect(screen.getByText(/of 6 components/)).toBeInTheDocument()
})
test("clicking a component shows its origin, integrity and a download link for the CycloneDX file", async () => {
  renderAt("/sbom?run=r1")
  await userEvent.click(await screen.findByText("debug"))
  const dlg = await screen.findByRole("dialog")
  expect(within(dlg).getByText("registry.npmjs.org")).toBeInTheDocument()
  expect(within(dlg).getByText(/sha512-A8GKp77/)).toBeInTheDocument()
  expect(screen.getByRole("link", { name: /Download CycloneDX/ })).toHaveAttribute("href", "/runs/r1/sbom")
})
test("an empty sbom shows an empty state, not an error", async () => {
  const r = JSON.parse(JSON.stringify(report))
  r.sbom.components = []
  c.getReport.mockResolvedValue(r)
  renderAt("/sbom?run=r1")
  expect(await screen.findByText("No components in this SBOM")).toBeInTheDocument()
})
test("sbom explorer shows the error banner when the report cannot be loaded", async () => {
  c.getReport.mockRejectedValue(new ApiError("/runs/r1/report", 500, "x"))
  renderAt("/sbom?run=r1")
  expect(await screen.findByRole("alert")).toBeInTheDocument()
})

// ---- Evidence Center ------------------------------------------------------------
const evCount = Object.keys((report as any).evidence).length
test("evidence center lists evidence with source, locator and how many findings cite it", async () => {
  renderAt("/evidence?run=r1")
  expect(await screen.findByText(`${evCount} of ${evCount} evidence items`)).toBeInTheDocument()
  expect(screen.getAllByText("Dockerfile:1-8").length).toBeGreaterThan(0)
})
test("evidence can be searched", async () => {
  renderAt("/evidence?run=r1")
  await userEvent.type(await screen.findByLabelText("Search evidence"), "zzz-none")
  expect(await screen.findByText("No evidence matches these filters")).toBeInTheDocument()
})
test("opening evidence shows the excerpt, hash and the findings that cite it", async () => {
  renderAt("/evidence?run=r1")
  await userEvent.click((await screen.findAllByText("Dockerfile:1-8"))[0])
  const dlg = await screen.findByRole("dialog")
  expect(within(dlg).getByText(/FROM node:latest/)).toBeInTheDocument()
  expect(within(dlg).getByText(/763b67377f12/)).toBeInTheDocument()
  expect(within(dlg).getAllByRole("link").length).toBeGreaterThan(0)
})
test("a run with no evidence shows an empty state", async () => {
  const r = JSON.parse(JSON.stringify(report))
  r.evidence = {}
  c.getReport.mockResolvedValue(r)
  renderAt("/evidence?run=r1")
  expect(await screen.findByText("No evidence was recorded for this run")).toBeInTheDocument()
})
test("a 404 run shows Run not available on the new pages", async () => {
  c.getReport.mockRejectedValue(new ApiError("/runs/zz/report", 404, ""))
  renderAt("/evidence?run=zz")
  expect(await screen.findByText("Run not available")).toBeInTheDocument()
})
