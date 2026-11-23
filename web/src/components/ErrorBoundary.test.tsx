import { render, screen } from "@testing-library/react"
import { ErrorBoundary } from "./ErrorBoundary"

function Boom(): never { throw new Error("bad report") }

test("a crashing child shows a fallback instead of a blank page", () => {
  vi.spyOn(console, "error").mockImplementation(() => {})
  render(<ErrorBoundary><Boom /></ErrorBoundary>)
  expect(screen.getByRole("alert")).toHaveTextContent("could not be displayed")
})
test("a healthy child renders normally", () => {
  render(<ErrorBoundary><p>fine</p></ErrorBoundary>)
  expect(screen.getByText("fine")).toBeInTheDocument()
})
