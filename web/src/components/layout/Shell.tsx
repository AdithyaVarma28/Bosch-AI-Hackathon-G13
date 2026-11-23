import { ReactNode } from "react"
import { Link, NavLink, useLocation, useSearchParams } from "react-router-dom"
import { tokens } from "../../theme/tokens"
import { useCurrentRun } from "../../hooks/hooks"
import { Icon, ICON_FOR } from "./icons"

export interface NavItem { label: string; path: string | null }
// Order and grouping follow the Figma sidebar. path === null means the page is not built yet.
export const NAV: { section: string; items: NavItem[] }[] = [
  { section: "WORKSPACE", items: [{ label: "Overview", path: "/" }, { label: "Repositories", path: "/repositories" }] },
  { section: "SECURITY", items: [
    { label: "Dependency Intelligence", path: "/dependencies" }, { label: "Vulnerabilities", path: "/vulnerabilities" },
    { label: "Anomaly Detection", path: "/anomalies" }, { label: "SBOM Explorer", path: "/sbom" } ] },
  { section: "INVESTIGATION", items: [
    { label: "Evidence Center", path: "/evidence" }, { label: "Agent Activity", path: null }, { label: "Risk Prioritization", path: null },
    { label: "Remediation", path: null }, { label: "Validation", path: null } ] },
  { section: "SYSTEM", items: [{ label: "Settings", path: null }] },
]
// Repository Scanning is reached through the New Scan button, as in the design.
export const PAGE_TITLES: Record<string, string> = {
  "/": "Overview", "/dependencies": "Dependency Intelligence", "/vulnerabilities": "Vulnerabilities", "/anomalies": "Anomaly Detection", "/scan": "Repository Scanning",
  "/repositories": "Repositories", "/sbom": "SBOM Explorer", "/evidence": "Evidence Center",
}

export function Sidebar() {
  const [params] = useSearchParams()
  const run = params.get("run")
  const withRun = (p: string) => (run ? `${p}?run=${encodeURIComponent(run)}` : p)
  return (
    <nav data-testid="sidebar" className="fixed left-0 top-0 h-screen bg-surface border-r border-border overflow-y-auto" style={{ width: tokens.layout.sidebar }}>
      <div className="flex items-center gap-3 px-5 h-14">
        <span style={{ color: tokens.colors.accentSolid }}><Icon name="brand" size={24} /></span>
        <span className="font-bold text-[16px] text-textPrimary">GUARDIAN AI</span>
      </div>
      {NAV.map((g) => (
        <div key={g.section} className="px-3 mt-4">
          <p className="px-2 mb-1 text-micro font-semibold text-textFaint tracking-wide">{g.section}</p>
          {g.items.map((it) =>
            it.path ? (
              <NavLink key={it.label} to={withRun(it.path)} end={it.path === "/"}
                className={({ isActive }) => `flex items-center gap-2 h-8 px-2 rounded text-nav ${isActive ? "font-semibold bg-accentSoft text-accent" : "font-medium text-textMuted hover:bg-page"}`}>
                <Icon name={ICON_FOR[it.label]} />{it.label}
              </NavLink>
            ) : (
              <div key={it.label} aria-disabled="true" title="Coming soon" className="flex items-center gap-2 h-8 px-2 rounded text-nav font-medium text-textFaint cursor-not-allowed">
                <Icon name={ICON_FOR[it.label]} />{it.label}
              </div>
            ),
          )}
        </div>
      ))}
    </nav>
  )
}

export function TopBar({ crumb, runId }: { crumb: string; runId: string | null }) {
  return (
    <header data-testid="topbar" className="flex items-center justify-between border-b border-border bg-page" style={{ height: tokens.layout.topbar, paddingLeft: tokens.layout.gutter, paddingRight: tokens.layout.gutter }}>
      <p className="text-body text-textMuted">Workspace <span className="mx-2 text-textFaint">/</span><span className="font-medium text-textPrimary">{crumb}</span></p>
      <span className="rounded bg-subtle px-2.5 py-1 text-micro font-semibold text-textMuted uppercase" title="Selected run">{runId ? `RUN ${runId}` : "NO RUN"}</span>
    </header>
  )
}

export function PageHeader({ title, subtitle, showNewScan = true }: { title: string; subtitle?: string; showNewScan?: boolean }) {
  const [params] = useSearchParams()
  const run = params.get("run")
  return (
    <div className="flex items-start justify-between mb-6">
      <div>
        <h1 className="text-[26px] leading-[39px] font-semibold text-textPrimary">{title}</h1>
        {subtitle && <p className="text-body text-textMuted">{subtitle}</p>}
      </div>
      {showNewScan && (
        <Link to={run ? `/scan?run=${encodeURIComponent(run)}` : "/scan"} className="flex items-center gap-1 rounded bg-textPrimary px-3 h-8 text-nav font-medium text-white">+ New Scan</Link>
      )}
    </div>
  )
}

export function Shell({ children }: { children: ReactNode }) {
  const { pathname } = useLocation()
  const { runId } = useCurrentRun()
  return (
    <div className="min-h-screen bg-page">
      <Sidebar />
      <div style={{ marginLeft: tokens.layout.sidebar }}>
        <TopBar crumb={PAGE_TITLES[pathname] ?? "Not found"} runId={runId} />
        <main style={{ padding: tokens.layout.gutter }}>{children}</main>
      </div>
    </div>
  )
}
