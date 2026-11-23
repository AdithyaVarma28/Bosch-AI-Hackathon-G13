import { Component, ReactNode } from "react"

export class ErrorBoundary extends Component<{ children: ReactNode }, { failed: boolean }> {
  state = { failed: false }
  static getDerivedStateFromError() { return { failed: true } }
  componentDidCatch(e: unknown) { console.error("page crashed", e) }
  render() {
    if (!this.state.failed) return this.props.children
    return (
      <div role="alert" className="m-8 rounded border border-border bg-surface p-6 text-body">
        <p className="font-semibold">This page could not be displayed.</p>
        <p className="text-textMuted">The data for this run may be incomplete. Try another run or start a new scan.</p>
      </div>
    )
  }
}
