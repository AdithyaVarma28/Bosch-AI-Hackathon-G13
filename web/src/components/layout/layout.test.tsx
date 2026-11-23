import { MemoryRouter } from "react-router-dom"
import { render, screen, waitFor } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import runs from "../../fixtures/runs.json"
import * as client from "../../api/client"
import App from "../../App"

vi.mock("../../api/client")
const c = vi.mocked(client)
beforeEach(() => {
  c.listRuns.mockResolvedValue(runs as any)
  c.getReport.mockRejectedValue(new Error("x"))
  c.getViz.mockRejectedValue(new Error("x"))
})
afterEach(() => vi.resetAllMocks())

const renderApp = (url = "/") => render(<MemoryRouter initialEntries={[url]}><App /></MemoryRouter>)

test("the product name is shown in the sidebar", () => {
  renderApp()
  expect(screen.getByText("GUARDIAN AI")).toBeInTheDocument()
})
test("the live pages are links and the rest are disabled with Coming soon", () => {
  renderApp()
  for (const l of ["Overview", "Repositories", "Dependency Intelligence", "Vulnerabilities", "Anomaly Detection", "SBOM Explorer", "Evidence Center"]) expect(screen.getByRole("link", { name: l })).toBeInTheDocument()
  for (const l of ["Agent Activity", "Risk Prioritization", "Remediation", "Validation", "Settings"]) {
    expect(screen.queryByRole("link", { name: l })).toBeNull()
    expect(screen.getByText(l).closest("[aria-disabled='true']")).not.toBeNull()
  }
  expect(screen.getAllByTitle("Coming soon").length).toBe(5)
})
test("the active page is marked aria-current", () => {
  renderApp("/vulnerabilities")
  expect(screen.getByRole("link", { name: "Vulnerabilities" })).toHaveAttribute("aria-current", "page")
})
test("the run query parameter survives navigation", async () => {
  renderApp("/?run=abc")
  expect(screen.getByRole("link", { name: "Vulnerabilities" })).toHaveAttribute("href", "/vulnerabilities?run=abc")
})
test("the top bar shows the run id, or NO RUN", async () => {
  renderApp("/?run=abc")
  expect(screen.getByTestId("topbar")).toHaveTextContent("RUN abc")
})
test("New Scan goes to the scan page", async () => {
  renderApp("/vulnerabilities?run=abc")
  await userEvent.click(screen.getByRole("link", { name: /New Scan/ }))
  await waitFor(() => expect(screen.getByTestId("topbar")).toHaveTextContent("Repository Scanning"))
})
test("an unknown path renders a not-found card in the shell", () => {
  renderApp("/nope")
  expect(screen.getByText("This page does not exist.")).toBeInTheDocument()
  expect(screen.getByTestId("sidebar")).toBeInTheDocument()
})
test("sidebar and top bar use the Figma sizes", () => {
  renderApp()
  expect(screen.getByTestId("sidebar")).toHaveStyle({ width: "224px" })
  expect(screen.getByTestId("topbar")).toHaveStyle({ height: "56px" })
})

test("every sidebar item has its own icon", () => {
  renderApp()
  const icons = Array.from(document.querySelectorAll("[data-testid='sidebar'] svg[data-icon]")).map((e) => e.getAttribute("data-icon"))
  expect(icons.length).toBe(13)
  expect(new Set(icons).size).toBe(13)
})
test("icons are decorative and inherit the text colour", () => {
  renderApp()
  const svg = document.querySelector("[data-testid='sidebar'] svg[data-icon]")!
  expect(svg.getAttribute("aria-hidden")).toBe("true")
  expect(svg.getAttribute("stroke")).toBe("currentColor")
})
