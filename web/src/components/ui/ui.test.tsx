import { useState } from "react"
import { render, screen } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { ApiError } from "../../api/types"
import { tokens } from "../../theme/tokens"
import { DataTable, Drawer, EmptyState, ErrorBanner, Pagination, Segments, SeverityBadge, Skeleton } from "./ui"

test("SeverityBadge shows the severity name and uses the token colours", () => {
  render(<SeverityBadge severity="Critical" />)
  expect(screen.getByText("Critical")).toHaveStyle({ color: tokens.severity.Critical.fg })
})
test("Unknown has its own neutral style", () => {
  render(<SeverityBadge severity="Unknown" />)
  expect(screen.getByText("Unknown")).toHaveStyle({ color: tokens.severity.Unknown.fg })
})
const rows = [{ id: "1", name: "alpha" }, { id: "2", name: "beta" }]
const cols = [{ key: "n", header: "Name", render: (r: (typeof rows)[number]) => r.name }]
test("DataTable renders headers and rows and calls onRowClick", async () => {
  const fn = vi.fn()
  render(<DataTable columns={cols} rows={rows} rowKey={(r) => r.id} onRowClick={fn} />)
  expect(screen.getByText("Name")).toBeInTheDocument()
  await userEvent.click(screen.getByText("beta"))
  expect(fn).toHaveBeenCalledWith(rows[1])
})
test("DataTable rows are keyboard activatable with Enter", async () => {
  const fn = vi.fn()
  render(<DataTable columns={cols} rows={rows} rowKey={(r) => r.id} onRowClick={fn} />)
  screen.getByText("alpha").closest("tr")!.focus()
  await userEvent.keyboard("{Enter}")
  expect(fn).toHaveBeenCalledWith(rows[0])
})
test("Pagination disables Previous on the first page and Next on the last", () => {
  const { rerender } = render(<Pagination page={1} pages={3} from={1} to={9} total={24} onChange={() => {}} />)
  expect(screen.getByText("Previous")).toBeDisabled()
  expect(screen.getByText("Showing 1–9 of 24 findings")).toBeInTheDocument()
  rerender(<Pagination page={3} pages={3} from={19} to={24} total={24} onChange={() => {}} />)
  expect(screen.getByText("Next")).toBeDisabled()
})
test("EmptyState and ErrorBanner are distinct, and the banner names the path and status", () => {
  render(<><EmptyState title="No vulnerabilities found" /><ErrorBanner error={new ApiError("/runs", 500, "boom")} /></>)
  expect(screen.getByTestId("empty-state")).toBeInTheDocument()
  expect(screen.getByRole("alert")).toHaveTextContent("/runs")
  expect(screen.getByRole("alert")).toHaveTextContent("500")
})
test("ErrorBanner for a network failure says it could not reach the server", () => {
  render(<ErrorBanner error={new ApiError("/runs", null, "x")} />)
  expect(screen.getByRole("alert")).toHaveTextContent(/could not reach/i)
})
test("Skeleton is marked busy", () => {
  render(<Skeleton />)
  expect(screen.getByTestId("skeleton")).toHaveAttribute("aria-busy", "true")
})
test("Segments draws widths proportional to counts and skips zero counts", () => {
  render(<Segments items={[{ label: "a", count: 3, color: "#111111" }, { label: "b", count: 0, color: "#222222" }, { label: "c", count: 1, color: "#333333" }]} />)
  const segs = screen.getAllByTestId("segment")
  expect(segs.length).toBe(2)
  expect(segs[0]).toHaveStyle({ width: "75%" })
})
function Host() {
  const [open, setOpen] = useState(false)
  return <><button onClick={() => setOpen(true)}>opener</button><Drawer open={open} onClose={() => setOpen(false)} label="Details">content</Drawer></>
}
test("Drawer closes on Escape and on the close button and restores focus", async () => {
  render(<Host />)
  await userEvent.click(screen.getByText("opener"))
  expect(screen.getByRole("dialog", { name: "Details" })).toBeInTheDocument()
  await userEvent.keyboard("{Escape}")
  expect(screen.queryByRole("dialog")).toBeNull()
  expect(screen.getByText("opener")).toHaveFocus()
  await userEvent.click(screen.getByText("opener"))
  await userEvent.click(screen.getByLabelText("Close"))
  expect(screen.queryByRole("dialog")).toBeNull()
})
