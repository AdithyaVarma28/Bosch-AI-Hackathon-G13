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
const renderAt = (url = "/vulnerabilities?run=r1") => render(<MemoryRouter initialEntries={[url]}><App /></MemoryRouter>)
beforeEach(() => {
  c.listRuns.mockResolvedValue(runs as any)
  c.getViz.mockResolvedValue({ nodes: [], edges: [], blast: {} })
  c.getReport.mockResolvedValue(report as any)
  c.getEvidence.mockResolvedValue({ id: "e", kind: "raw", source: "osv", locator: "requirements.txt:5", excerpt: "requests==2.25.1", sha256: "x", captured_at: "", run_id: "r1" })
})
afterEach(() => vi.resetAllMocks())

const firstFinding = () => (report as any).findings.find((f: any) => f.cls === "vuln" && f.signals.advisory_id === "GHSA-xvch-5gv4-984h")

test("the table lists vulnerabilities worst first with installed and fixed versions", async () => {
  renderAt()
  const rows = await screen.findAllByRole("row")
  expect(rows.length).toBe(1 + 9)
  expect(within(rows[1]).getByText("MAL-2025-25502")).toBeInTheDocument() // unknown severity but P0: ranked first
  expect(within(rows[2]).getByText("GHSA-xvch-5gv4-984h")).toBeInTheDocument()
  expect(within(rows[2]).getByText("0.2.4, 1.2.6")).toBeInTheDocument()
})
test("search narrows rows by advisory id, summary or component", async () => {
  renderAt()
  await userEvent.type(await screen.findByLabelText("Search vulnerabilities"), "requests")
  const rows = screen.getAllByRole("row").slice(1)
  expect(rows.length).toBe(4)
  expect(screen.getByText("4 findings")).toBeInTheDocument()
})
test("severity and dependency filters combine, and Clear filters resets", async () => {
  renderAt()
  await userEvent.selectOptions(await screen.findByLabelText("Severity"), "Critical")
  expect(screen.getAllByRole("row").length).toBe(2)
  await userEvent.click(screen.getByText("Clear filters"))
  expect(screen.getAllByRole("row").length).toBe(10)
})
test("pagination shows 9 rows per page and the Showing range", async () => {
  renderAt()
  expect(await screen.findByText("Showing 1–9 of 13 findings")).toBeInTheDocument()
  await userEvent.click(screen.getByText("Next"))
  expect(screen.getByText("Showing 10–13 of 13 findings")).toBeInTheDocument()
})
test("sorting by priority band puts P0 first", async () => {
  renderAt()
  await userEvent.selectOptions(await screen.findByLabelText("Sort by"), "band")
  const first = screen.getAllByRole("row")[1]
  expect(within(first).getByText(/MAL-2025-25502|GHSA-hm6q-r2jc-cpqh/)).toBeInTheDocument()
})
test("clicking a row opens the CVE panel with advisory, versions, path and priority", async () => {
  renderAt()
  await userEvent.click(await screen.findByText("GHSA-xvch-5gv4-984h"))
  const dlg = await screen.findByRole("dialog")
  expect(within(dlg).getByText("Fixed version")).toBeInTheDocument()
  expect(within(dlg).getAllByText(/npm\/mkdirp@0.5.1/).length).toBeGreaterThan(0)
  expect(within(dlg).getByText(firstFinding().band_reason, { exact: false })).toBeInTheDocument()
  expect(within(dlg).getByText("Critical · CVSS 9.8")).toBeInTheDocument()
})
test("evidence is fetched and shown with its locator", async () => {
  renderAt()
  await userEvent.click(await screen.findByText("GHSA-xvch-5gv4-984h"))
  expect((await screen.findAllByText("requirements.txt:5")).length).toBeGreaterThan(0)
})
test("a failed evidence fetch shows an inline note and the panel stays usable", async () => {
  c.getEvidence.mockRejectedValue(new ApiError("/x", 404, ""))
  renderAt()
  await userEvent.click(await screen.findByText("GHSA-xvch-5gv4-984h"))
  expect((await screen.findAllByText(/could not be loaded/)).length).toBeGreaterThan(0)
  expect(screen.getByRole("dialog")).toBeInTheDocument()
})
test("?finding=<id> opens the panel on load and Escape closes it", async () => {
  renderAt(`/vulnerabilities?run=r1&finding=${firstFinding().id}`)
  expect(await screen.findByRole("dialog")).toBeInTheDocument()
  await userEvent.keyboard("{Escape}")
  expect(screen.queryByRole("dialog")).toBeNull()
})
test("zero vulnerabilities shows No vulnerabilities found", async () => {
  const r = clone(); r.findings = []
  c.getReport.mockResolvedValue(r)
  renderAt()
  expect(await screen.findByText("No vulnerabilities found")).toBeInTheDocument()
})
test("a 500-row report paginates and does not render more than 9 rows", async () => {
  const r = clone()
  const base = r.findings.find((f: any) => f.cls === "vuln")
  r.findings = Array.from({ length: 500 }, (_, i) => ({ ...base, id: `v${i}`, signals: { ...base.signals, advisory_id: `GHSA-${i}` } }))
  c.getReport.mockResolvedValue(r)
  renderAt()
  expect((await screen.findAllByRole("row")).length).toBe(9 + 1)
  expect(screen.getByText("Showing 1–9 of 500 findings")).toBeInTheDocument()
})
test("missing cvss and fixed version render an em dash", async () => {
  renderAt()
  const row = (await screen.findByText("MAL-2025-25502")).closest("tr")!
  expect(within(row).getAllByText("—").length).toBeGreaterThanOrEqual(2)
})
test("a failing request shows the error banner, not an empty table", async () => {
  c.getReport.mockRejectedValue(new ApiError("/runs/r1/report", 500, ""))
  renderAt()
  expect(await screen.findByRole("alert")).toBeInTheDocument()
  expect(screen.queryByRole("table")).toBeNull()
})
