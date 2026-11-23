import { MemoryRouter } from "react-router-dom"
import { render, screen, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import report from "../fixtures/report.mini-shop.json"
import viz from "../fixtures/viz.mini-shop.json"
import runs from "../fixtures/runs.json"
import { ApiError } from "../api/types"
import * as client from "../api/client"

const created: any[] = []
vi.mock("cytoscape", () => {
  const fn: any = () => {
    const inst: any = {
      destroyed: false, elements: () => ({ remove: () => {} }), add: vi.fn(), batch: (f: () => void) => f(), on: vi.fn(),
      layout: () => ({ run: () => {} }), fit: () => {}, zoom: () => 1, destroy() { inst.destroyed = true },
    }
    created.push(inst)
    return inst
  }
  fn.use = () => {}
  return { default: fn }
})
vi.mock("cytoscape-dagre", () => ({ default: {} }))
vi.mock("../api/client")
const c = vi.mocked(client)
import App from "../App"

const renderAt = (url = "/dependencies?run=r1") => render(<MemoryRouter initialEntries={[url]}><App /></MemoryRouter>)
beforeEach(() => {
  created.length = 0
  c.listRuns.mockResolvedValue(runs as any)
  c.getReport.mockResolvedValue(report as any)
  c.getViz.mockResolvedValue(viz as any)
})
afterEach(() => vi.resetAllMocks())

test("the page selects the most severe vulnerable component by default and shows its details", async () => {
  renderAt()
  expect(await screen.findByText("Component details")).toBeInTheDocument()
  const panel = within(screen.getByText("Component details").closest("section")!)
  expect(panel.getByText("pkg:npm/minimist@0.0.8")).toBeInTheDocument()
  expect(panel.getByText("Transitive")).toBeInTheDocument()
})
test("the graph card says N of M components shown", async () => {
  renderAt()
  expect(await screen.findByText(/of 13 components shown/)).toBeInTheDocument()
})
test("associated vulnerabilities link to the vulnerability panel", async () => {
  renderAt()
  const link = await screen.findByRole("link", { name: "GHSA-xvch-5gv4-984h" })
  expect(link.getAttribute("href")).toContain("/vulnerabilities?run=r1&finding=")
})
test("the legend and zoom controls are present", async () => {
  renderAt()
  expect(await screen.findByLabelText("Legend")).toHaveTextContent("Selected path")
  expect(screen.getByLabelText("Zoom in")).toBeInTheDocument()
})
test("filters change the shown count", async () => {
  renderAt()
  await userEvent.selectOptions(await screen.findByLabelText("Ecosystem"), "pypi")
  expect(screen.getByText(/of 13 components shown/).textContent).not.toMatch(/^11 of/)
})
test("DependencyGraph creates one instance and destroys it on unmount", async () => {
  const { unmount } = renderAt()
  await screen.findByTestId("graph-canvas")
  expect(created.length).toBe(1)
  unmount()
  expect(created[0].destroyed).toBe(true)
})
test("a search with no match shows an empty state instead of a blank canvas", async () => {
  renderAt()
  await userEvent.type(await screen.findByLabelText("Search components"), "zzz-none")
  expect(await screen.findByText("No components to show")).toBeInTheDocument()
})
test("a run with no vulnerable components still renders", async () => {
  const r = JSON.parse(JSON.stringify(report)); r.findings = []
  c.getReport.mockResolvedValue(r)
  renderAt()
  expect(await screen.findByTestId("graph-canvas")).toBeInTheDocument()
  expect(screen.getByText("Select a component")).toBeInTheDocument()
})
test("a failing viz request shows the error banner", async () => {
  c.getViz.mockRejectedValue(new ApiError("/runs/r1/viz", 404, ""))
  renderAt()
  expect(await screen.findByRole("alert")).toHaveTextContent("/runs/r1/viz")
})

test("the header counts direct links plus dependency edges as relationships", async () => {
  renderAt()
  expect(await screen.findByText("13 components · 13 relationships")).toBeInTheDocument()
})

test("the details panel has overview, security, code usage and dependency path sections", async () => {
  renderAt("/dependencies?run=r1&component=pkg:pypi/flask@2.0.1")
  for (const h of ["Overview", "Security", "Code usage", "Dependency path"]) expect(await screen.findByRole("heading", { name: h })).toBeInTheDocument()
  const panel = within(screen.getByText("Component details").closest("section")!)
  expect(panel.getByText("Production")).toBeInTheDocument()
  expect(screen.getAllByText("app/api/routes.py").length).toBeGreaterThan(0)
  expect(screen.getByText("POST /checkout")).toBeInTheDocument()
  expect(screen.getAllByText("Fixed version", { exact: false }).length).toBe(2)
})
test("code usage says referenced in source and does not claim execution", async () => {
  renderAt("/dependencies?run=r1&component=pkg:pypi/flask@2.0.1")
  expect(await screen.findByText(/not proof that the code runs/i)).toBeInTheDocument()
  expect(screen.getByText("Referenced in source")).toBeInTheDocument()
})
test("a package with no source references shows Not observed in source", async () => {
  renderAt("/dependencies?run=r1&component=pkg:pypi/pytest@7.0.0")
  const panel = within((await screen.findByText("Component details")).closest("section")!)
  expect(await panel.findByText("Not observed in source")).toBeInTheDocument()
})
test("summary tiles show components, direct, transitive and critical/high counts", async () => {
  renderAt()
  const tiles = await screen.findByTestId("dep-summary")
  expect(tiles).toHaveTextContent("13Components")
  expect(tiles).toHaveTextContent("11Direct")
  expect(tiles).toHaveTextContent("2Transitive")
  expect(tiles).toHaveTextContent("4Critical / High")
})
test("scope and vulnerable-only controls change the graph", async () => {
  renderAt()
  await userEvent.selectOptions(await screen.findByLabelText("Scope"), "Development")
  expect(screen.getByText(/of 13 components shown/).textContent).toMatch(/^[0-4] of/)
  await userEvent.click(screen.getByLabelText("Vulnerable only"))
  expect(screen.getByText(/of 13 components shown/)).toBeInTheDocument()
})
test("the legend explains severity colours and source usage", async () => {
  renderAt()
  const legend = await screen.findByLabelText("Legend")
  for (const t of ["Critical / High", "Medium", "No known finding", "Referenced in source"]) expect(legend).toHaveTextContent(t)
})
