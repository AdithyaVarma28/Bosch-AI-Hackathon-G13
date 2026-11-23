import { ReactNode, useEffect, useRef } from "react"
import { ApiError, Severity } from "../../api/types"
import { tokens } from "../../theme/tokens"

export function SeverityBadge({ severity, children }: { severity: Severity; children?: ReactNode }) {
  const t = tokens.severity[severity]
  return (
    <span className="inline-flex items-center rounded px-2 py-1 text-label font-medium whitespace-nowrap" style={{ color: t.fg, backgroundColor: t.bg }}>
      {children ?? severity}
    </span>
  )
}

export function StatusBadge({ status }: { status: string }) {
  const t = (tokens.status as Record<string, { bg: string; fg: string }>)[status] ?? tokens.status.Open
  return <span className="inline-flex items-center rounded px-2 py-1 text-label font-medium" style={{ color: t.fg, backgroundColor: t.bg }}>{status}</span>
}

export function Card({ title, subtitle, action, children, className = "" }: { title?: ReactNode; subtitle?: ReactNode; action?: ReactNode; children?: ReactNode; className?: string }) {
  return (
    <section className={`bg-surface border border-border rounded-md ${className}`}>
      {(title || action) && (
        <header className="flex items-start justify-between px-5 pt-4">
          <div>
            {title && <h2 className="text-title font-semibold text-textPrimary">{title}</h2>}
            {subtitle && <p className="text-body text-textMuted mt-0.5">{subtitle}</p>}
          </div>
          {action}
        </header>
      )}
      <div className="p-5">{children}</div>
    </section>
  )
}

export function StatTile({ label, value, sub }: { label: string; value: ReactNode; sub?: ReactNode }) {
  return (
    <div className="bg-surface border border-border rounded-md p-5">
      <p className="text-body text-textMuted">{label}</p>
      <p className="text-kpi font-semibold text-textPrimary mt-1">{value}</p>
      {sub && <p className="text-label text-textMuted mt-1">{sub}</p>}
    </div>
  )
}

export function Segments({ items }: { items: { label: string; count: number; color: string }[] }) {
  const total = items.reduce((a, i) => a + i.count, 0)
  return (
    <div className="flex h-2 w-full overflow-hidden rounded bg-subtle" role="img" aria-label="Severity distribution">
      {total > 0 && items.filter((i) => i.count > 0).map((i) => (
        <div key={i.label} data-testid="segment" title={`${i.label}: ${i.count}`} style={{ width: `${(i.count / total) * 100}%`, backgroundColor: i.color }} />
      ))}
    </div>
  )
}

export interface Column<T> { key: string; header: string; width?: string; render: (row: T) => ReactNode }
export function DataTable<T>({ columns, rows, rowKey, onRowClick }: { columns: Column<T>[]; rows: T[]; rowKey: (r: T) => string; onRowClick?: (r: T) => void }) {
  return (
    <table className="w-full text-body text-left border-collapse">
      <thead>
        <tr className="text-micro uppercase text-textMuted">
          {columns.map((c) => <th key={c.key} className="px-4 py-3 font-semibold" style={{ width: c.width }}>{c.header}</th>)}
        </tr>
      </thead>
      <tbody>
        {rows.map((r) => (
          <tr
            key={rowKey(r)}
            className={`border-t border-border ${onRowClick ? "cursor-pointer hover:bg-page" : ""}`}
            tabIndex={onRowClick ? 0 : undefined}
            onClick={() => onRowClick?.(r)}
            onKeyDown={(e) => { if (onRowClick && (e.key === "Enter" || e.key === " ")) { e.preventDefault(); onRowClick(r) } }}
          >
            {columns.map((c) => <td key={c.key} className="px-4 py-3 align-middle">{c.render(r)}</td>)}
          </tr>
        ))}
      </tbody>
    </table>
  )
}

export function Pagination({ page, pages, from, to, total, onChange, noun = "findings" }: { page: number; pages: number; from: number; to: number; total: number; onChange: (p: number) => void; noun?: string }) {
  return (
    <div className="flex items-center justify-between px-4 py-3 border-t border-border text-body text-textMuted">
      <span>Showing {from}–{to} of {total} {noun}</span>
      <div className="flex gap-2">
        <button className="px-3 py-1 border border-border rounded disabled:opacity-40" disabled={page <= 1} onClick={() => onChange(page - 1)}>Previous</button>
        <button className="px-3 py-1 border border-border rounded disabled:opacity-40" disabled={page >= pages} onClick={() => onChange(page + 1)}>Next</button>
      </div>
    </div>
  )
}

export function EmptyState({ title, hint }: { title: string; hint?: string }) {
  return (
    <div className="text-center py-12" data-testid="empty-state">
      <p className="text-title font-semibold text-textPrimary">{title}</p>
      {hint && <p className="text-body text-textMuted mt-1">{hint}</p>}
    </div>
  )
}

export function ErrorBanner({ error, onRetry }: { error: ApiError; onRetry?: () => void }) {
  const msg = error.status === null ? `Could not reach the Guardian server (${error.path}). Is it running?` : `Request ${error.path} failed with status ${error.status}.`
  return (
    <div role="alert" className="border rounded-md p-4 text-body flex items-center justify-between" style={{ backgroundColor: tokens.severity.Critical.bg, color: tokens.severity.Critical.fg, borderColor: tokens.severity.Critical.fg }}>
      <span>{msg}</span>
      {onRetry && <button className="underline" onClick={onRetry}>Retry</button>}
    </div>
  )
}

export function Skeleton({ rows = 4 }: { rows?: number }) {
  return (
    <div data-testid="skeleton" aria-busy="true" className="space-y-3">
      {Array.from({ length: rows }, (_, i) => <div key={i} className="h-4 rounded bg-subtle animate-pulse" />)}
    </div>
  )
}

export function NotAvailable({ what = "Run" }: { what?: string }) {
  return <EmptyState title={`${what} not available`} hint="It may have been lost when the server restarted. Start a new scan." />
}

export function Drawer({ open, onClose, label, children }: { open: boolean; onClose: () => void; label: string; children: ReactNode }) {
  const opener = useRef<Element | null>(null)
  useEffect(() => {
    if (!open) return
    opener.current = document.activeElement
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") onClose() }
    document.addEventListener("keydown", onKey)
    return () => { document.removeEventListener("keydown", onKey); (opener.current as HTMLElement | null)?.focus?.() }
  }, [open, onClose])
  if (!open) return null
  return (
    <div className="fixed inset-0 z-40 flex justify-end bg-black/20" onClick={onClose}>
      <aside role="dialog" aria-label={label} className="h-full w-[520px] max-w-full overflow-y-auto bg-surface border-l border-border shadow-xl" onClick={(e) => e.stopPropagation()}>
        <button className="absolute top-3 right-4 text-textMuted" aria-label="Close" onClick={onClose}>✕</button>
        {children}
      </aside>
    </div>
  )
}
