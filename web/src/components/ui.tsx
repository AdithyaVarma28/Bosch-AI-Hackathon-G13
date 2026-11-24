// Shared components (docs/stage6.md section 6): EntityLink, chips, badges, evidence, code, states, peek drawer, timeline.
import { createContext, ReactNode, useContext, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import {
  AlertTriangle, Bot, Box, ChevronRight, CircleCheck, CircleDot, Cloud, Database, ExternalLink, File, FunctionSquare,
  GitCommit, KeyRound, Loader2, Package, Route as RouteIcon, ShieldAlert, Sparkles, X,
} from "lucide-react";
import { Risk, Step, useEntity } from "../api";

export const cx = (...c: (string | false | null | undefined)[]) => c.filter(Boolean).join(" ");

// ---------------------------------------------------------------- entity links
export function entityHref(scan: string, id: string): string {
  const e = encodeURIComponent(id);
  if (/^[FA]-\d+$/.test(id)) return `/scans/${scan}/findings/${id}`;
  if (id.startsWith("file:")) return `/scans/${scan}/files/${id.slice(5)}`;
  if (id.startsWith("module:")) return `/scans/${scan}/modules/${e}`;
  if (id.startsWith("pkg:")) return `/scans/${scan}/packages/${e}`;
  if (id.startsWith("fn:") || id.startsWith("class:")) return `/scans/${scan}/functions/${e}`;
  if (id.startsWith("commit:")) return `/scans/${scan}/commits/${e}`;
  if (id.startsWith("route:") || id.startsWith("cli:")) return `/scans/${scan}/flows?entry=${e}`;
  return `/scans/${scan}/entity/${e}`;
}

export function EntityIcon({ id, className = "h-3.5 w-3.5" }: { id: string; className?: string }) {
  const p = id.split(":")[0];
  const I = /^[FA]-\d+$/.test(id) ? ShieldAlert : ({ module: Box, file: File, pkg: Package, fn: FunctionSquare, class: FunctionSquare,
    route: RouteIcon, cli: RouteIcon, table: Database, svc: Cloud, env: KeyRound, commit: GitCommit } as Record<string, any>)[p] ?? CircleDot;
  return <I className={cx(className, "shrink-0 opacity-70")} aria-hidden />;
}

export function shortLabel(id: string): string {
  const [kind, ...rest] = id.split(":");
  const r = rest.join(":");
  if (kind === "fn") return r.split("::").pop() + "()";
  if (kind === "pkg") return r.split("/").slice(1).join("/").replace("@", " ");
  if (kind === "svc" || kind === "env" || kind === "module" || kind === "file" || kind === "route" || kind === "table") return r;
  return r || id;
}

/** Real <a href> (Ctrl/Cmd/middle-click opens a new tab). */
export function EntityLink({ id, label, scan }: { id: string; label?: string; scan?: string }) {
  const params = useParams();
  const s = scan ?? params.scanId ?? "";
  return (
    <Link to={entityHref(s, id)} className="inline-flex items-center gap-1 text-indigo-700 hover:underline dark:text-indigo-300">
      <EntityIcon id={id} />
      <span className="truncate">{label ?? shortLabel(id)}</span>
    </Link>
  );
}

// ---------------------------------------------------------------- chips + badges
const RISK_STYLE: Record<string, string> = {
  critical: "bg-red-100 text-red-800 ring-red-300 dark:bg-red-950 dark:text-red-200",
  high: "bg-orange-100 text-orange-800 ring-orange-300 dark:bg-orange-950 dark:text-orange-200",
  medium: "bg-amber-100 text-amber-800 ring-amber-300 dark:bg-amber-950 dark:text-amber-200",
  low: "bg-slate-100 text-slate-700 ring-slate-300 dark:bg-slate-800 dark:text-slate-200",
};
const RISK_ICON: Record<string, string> = { critical: "▲▲", high: "▲", medium: "◆", low: "▽" };

export function RiskChip({ risk, prefix }: { risk?: Risk | string | null; prefix?: string }) {
  if (!risk) return <span className="text-xs text-slate-400">—</span>;
  return (
    <span className={cx("inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-xs font-semibold ring-1 capitalize", RISK_STYLE[risk] ?? RISK_STYLE.low)}>
      <span aria-hidden>{RISK_ICON[risk] ?? "•"}</span>{prefix ? `${prefix} ` : ""}{risk}
    </span>
  );
}

export function SeverityChip({ cvss, band }: { cvss?: number | null; band?: string }) {
  if (cvss == null && !band) return <span className="text-xs text-slate-400">—</span>;
  return <span className="inline-flex items-center gap-1 rounded bg-slate-900 px-1.5 py-0.5 text-xs font-medium text-white dark:bg-slate-700">
    CVSS {cvss ?? "?"} <span className="opacity-70 capitalize">{band}</span></span>;
}

export function ConfidenceChip({ c }: { c?: string }) {
  const dots = c === "high" ? 3 : c === "medium" ? 2 : 1;
  return <span className="inline-flex items-center gap-1 text-xs text-slate-600 dark:text-slate-300" title={`confidence ${c}`}>
    <span aria-hidden className="tracking-tighter">{"●".repeat(dots)}{"○".repeat(3 - dots)}</span>Conf: {c}</span>;
}

export function FactBadge() {
  return <span className="inline-flex items-center gap-1 rounded bg-emerald-50 px-1.5 py-0.5 text-[11px] font-medium text-emerald-800 ring-1 ring-emerald-200 dark:bg-emerald-950 dark:text-emerald-200"><CircleCheck className="h-3 w-3" />Fact</span>;
}

export function AIBadge({ confidence, by }: { confidence?: string | number; by?: string }) {
  if (by && by !== "ai") return <span className="inline-flex items-center gap-1 rounded bg-sky-50 px-1.5 py-0.5 text-[11px] font-medium text-sky-800 ring-1 ring-sky-200 dark:bg-sky-950 dark:text-sky-200"><Bot className="h-3 w-3" />Rules{confidence != null ? ` · confidence ${confidence}` : ""}</span>;
  return <span className="inline-flex items-center gap-1 rounded bg-violet-50 px-1.5 py-0.5 text-[11px] font-medium text-violet-800 ring-1 ring-violet-200 dark:bg-violet-950 dark:text-violet-200"><Sparkles className="h-3 w-3" />AI{confidence != null ? ` · confidence ${confidence}` : ""}</span>;
}

export function ReviewBadge({ status }: { status?: string }) {
  const s = status ?? "not_required";
  const style = s === "pending" ? "bg-yellow-100 text-yellow-900 ring-yellow-300" : s === "confirmed" ? "bg-emerald-100 text-emerald-900 ring-emerald-300"
    : s === "dismissed" ? "bg-slate-200 text-slate-700 ring-slate-300" : s === "overridden" ? "bg-sky-100 text-sky-900 ring-sky-300" : "bg-white text-slate-500 ring-slate-200";
  return <span className={cx("whitespace-nowrap rounded px-1.5 py-0.5 text-xs ring-1", style)}>{s === "pending" ? "● review pending" : s.replace("_", " ")}</span>;
}

// ---------------------------------------------------------------- evidence + code
export function EvidenceItem({ e }: { e: any }) {
  const { scanId = "" } = useParams();
  if (e.url) return <a className="inline-flex items-center gap-1 text-indigo-700 hover:underline dark:text-indigo-300" href={e.url} target="_blank" rel="noreferrer"><ExternalLink className="h-3 w-3" />{e.url.replace(/^https?:\/\//, "").slice(0, 70)}</a>;
  if (e.commit) return <EntityLink id={`commit:${String(e.commit).slice(0, 7)}`} label={`commit ${String(e.commit).slice(0, 7)}`} />;
  if (e.pypi) return <span className="mono text-xs">PyPI: {e.pypi}</span>;
  if (e.path) return <span className="text-xs">{(e.labels ?? e.path).join(" → ")}</span>;
  if (e.file) {
    const lines = e.lines ?? (e.line ? String(e.line) : "");
    const label = `${e.file}${lines ? `:${lines}` : ""}`;
    if (String(e.file).startsWith("pkg:")) return <span className="mono text-xs">{label}</span>;
    const a = String(lines).split("-");
    return <Link className="mono text-xs text-indigo-700 hover:underline dark:text-indigo-300" to={`/scans/${scanId}/files/${e.file}${lines ? `#L${a[0]}-L${a[1] ?? a[0]}` : ""}`}>{label}</Link>;
  }
  if (e.node) return <EntityLink id={e.node} />;
  return <span className="text-xs text-slate-500">{JSON.stringify(e)}</span>;
}

export function EvidenceList({ items }: { items: any[] }) {
  if (!items?.length) return <p className="text-sm text-slate-500">No evidence recorded.</p>;
  return <ul className="space-y-1">{items.map((e, i) => <li key={i} className="flex items-start gap-2 text-sm"><span className="mt-1 text-slate-400">⌖</span><EvidenceItem e={e} /></li>)}</ul>;
}

export function CodeSnippet({ file, start, lines, highlight, href }: { file: string; start: number; lines: string[]; highlight?: [number, number]; href?: string }) {
  return (
    <div className="overflow-hidden rounded-lg border border-slate-200 dark:border-slate-700">
      <div className="flex items-center justify-between bg-slate-100 px-3 py-1.5 text-xs dark:bg-slate-800">
        <span className="mono">{file}</span>
        {href && <Link to={href} className="inline-flex items-center gap-1 text-indigo-700 hover:underline dark:text-indigo-300">Open file <ExternalLink className="h-3 w-3" /></Link>}
      </div>
      <pre className="overflow-x-auto bg-white py-2 text-xs leading-5 dark:bg-slate-900">
        {lines.map((t, i) => {
          const n = start + i;
          const hot = highlight && n >= highlight[0] && n <= highlight[1];
          return <div key={i} className={cx("flex px-3", hot && "bg-amber-100 dark:bg-amber-900/40")}><span className="w-10 shrink-0 select-none pr-3 text-right text-slate-400">{n}</span><code>{t || " "}</code></div>;
        })}
      </pre>
    </div>
  );
}

// ---------------------------------------------------------------- states + layout pieces
export function Skeleton({ rows = 4 }: { rows?: number }) {
  return <div className="animate-pulse space-y-3" aria-label="Loading">{Array.from({ length: rows }).map((_, i) => <div key={i} className="h-5 rounded bg-slate-200 dark:bg-slate-800" style={{ width: `${90 - i * 12}%` }} />)}</div>;
}
export function ErrorState({ error, retry }: { error: unknown; retry?: () => void }) {
  return <div className="rounded-lg border border-red-200 bg-red-50 p-4 text-sm text-red-800 dark:border-red-900 dark:bg-red-950 dark:text-red-200">
    <div className="flex items-center gap-2 font-medium"><AlertTriangle className="h-4 w-4" />Could not load this page</div>
    <p className="mt-1 break-all opacity-80">{String((error as Error)?.message ?? error).slice(0, 300)}</p>
    {retry && <button onClick={retry} className="mt-2 rounded bg-red-700 px-2 py-1 text-white">Retry</button>}
  </div>;
}
export function EmptyState({ title, action }: { title: string; action?: ReactNode }) {
  return <div className="rounded-lg border border-dashed border-slate-300 p-8 text-center text-sm text-slate-500 dark:border-slate-700">{title}{action && <div className="mt-3">{action}</div>}</div>;
}
export function QueryState({ q, children, rows }: { q: { isLoading: boolean; error: unknown; refetch?: () => void; data?: unknown }; children: () => ReactNode; rows?: number }) {
  if (q.isLoading) return <Skeleton rows={rows} />;
  if (q.error) return <ErrorState error={q.error} retry={q.refetch} />;
  return <>{children()}</>;
}

export function PageHeader({ crumbs, title, icon, children }: { crumbs: { label: string; to?: string }[]; title: ReactNode; icon?: ReactNode; children?: ReactNode }) {
  return (
    <div className="mb-5">
      <nav aria-label="Breadcrumb" className="mb-1 flex flex-wrap items-center gap-1 text-xs text-slate-500">
        {crumbs.map((c, i) => <span key={i} className="inline-flex items-center gap-1">{i > 0 && <ChevronRight className="h-3 w-3" />}{c.to ? <Link to={c.to} className="hover:underline">{c.label}</Link> : <span>{c.label}</span>}</span>)}
      </nav>
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="flex items-center gap-2 text-2xl font-semibold">{icon}{title}</h1>
        <div className="flex items-center gap-2">{children}</div>
      </div>
    </div>
  );
}

export function Panel({ title, children, action, className }: { title?: ReactNode; children: ReactNode; action?: ReactNode; className?: string }) {
  return <section className={cx("rounded-xl border border-slate-200 bg-white p-4 shadow-sm dark:border-slate-800 dark:bg-slate-900", className)}>
    {(title || action) && <div className="mb-3 flex items-center justify-between gap-2"><h2 className="text-sm font-semibold uppercase tracking-wide text-slate-500">{title}</h2>{action}</div>}
    {children}
  </section>;
}

// ---------------------------------------------------------------- activity timeline (actions + results only)
export function ActivityTimeline({ steps }: { steps: Step[] }) {
  if (!steps?.length) return <p className="text-sm text-slate-500">No recorded activity.</p>;
  return (
    <ol className="relative space-y-3 border-l border-slate-200 pl-4 dark:border-slate-700">
      {steps.map((s, i) => (
        <li key={i} className="text-sm">
          <span className={cx("absolute -left-1.5 mt-1.5 h-3 w-3 rounded-full ring-2 ring-white dark:ring-slate-900", s.ok ? "bg-indigo-500" : "bg-red-500")} />
          <div className="flex flex-wrap items-baseline gap-2">
            <span className="font-medium">{s.action}</span>
            <span className="rounded bg-slate-100 px-1 text-[11px] uppercase text-slate-500 dark:bg-slate-800">{s.stage}</span>
            {s.tool && <code className="text-[11px] text-slate-500">{s.tool}({Object.entries(s.input ?? {}).map(([k, v]) => `${k}=${typeof v === "string" ? v : JSON.stringify(v)}`).join(", ").slice(0, 90)})</code>}
          </div>
          <p className="text-slate-600 dark:text-slate-300">{s.result}</p>
        </li>
      ))}
    </ol>
  );
}

// ---------------------------------------------------------------- peek drawer
const PeekCtx = createContext<{ open: (id: string) => void }>({ open: () => {} });
export const usePeek = () => useContext(PeekCtx);

export function PeekProvider({ children }: { children: ReactNode }) {
  const [id, setId] = useState<string | null>(null);
  useEffect(() => {
    const k = (e: KeyboardEvent) => { if (e.key === "Escape") setId(null); };
    window.addEventListener("keydown", k);
    return () => window.removeEventListener("keydown", k);
  }, []);
  return <PeekCtx.Provider value={{ open: setId }}>{children}{id && <PeekDrawer id={id} onClose={() => setId(null)} />}</PeekCtx.Provider>;
}

function PeekDrawer({ id, onClose }: { id: string; onClose: () => void }) {
  const { scanId = "" } = useParams();
  const q = useEntity(scanId, id);
  return (
    <aside className="fixed inset-y-0 right-0 z-40 w-full max-w-md overflow-y-auto border-l border-slate-200 bg-white p-5 shadow-2xl dark:border-slate-800 dark:bg-slate-900" role="dialog" aria-label="Entity preview">
      <div className="mb-3 flex items-start justify-between gap-2">
        <div className="flex items-center gap-2 font-semibold"><EntityIcon id={id} className="h-4 w-4" />{q.data?.entity?.label ?? shortLabel(id)}</div>
        <button onClick={onClose} aria-label="Close" className="rounded p-1 hover:bg-slate-100 dark:hover:bg-slate-800"><X className="h-4 w-4" /></button>
      </div>
      <Link to={entityHref(scanId, id)} onClick={onClose} className="mb-4 inline-flex items-center gap-1 rounded bg-indigo-600 px-2 py-1 text-xs text-white">Open full page <ExternalLink className="h-3 w-3" /></Link>
      <QueryState q={q}>{() => <EntitySummary data={q.data} />}</QueryState>
    </aside>
  );
}

export function EntitySummary({ data }: { data: any }) {
  const e = data.entity;
  return (
    <div className="space-y-4 text-sm">
      <div className="flex flex-wrap gap-1">
        <span className="rounded bg-slate-100 px-1.5 text-xs dark:bg-slate-800">{e.type}</span>
        {(e.tags ?? []).slice(0, 8).map((t: string) => <span key={t} className="rounded bg-slate-100 px-1.5 text-xs text-slate-600 dark:bg-slate-800 dark:text-slate-300">{t}</span>)}
      </div>
      {data.card?.purpose && <div><div className="mb-1 flex items-center gap-2"><AIBadge by={data.card.discovered_by} confidence={data.card.confidence} /></div><p>{data.card.purpose}</p></div>}
      {data.findings?.length > 0 && <div><h3 className="mb-1 text-xs font-semibold uppercase text-slate-500">Findings</h3>
        <ul className="space-y-1">{data.findings.map((f: any) => <li key={f.finding_id} className="flex items-center gap-2"><RiskChip risk={f.project_risk} /><EntityLink id={f.finding_id} label={`${f.finding_id} ${f.title.slice(0, 50)}`} /></li>)}</ul></div>}
      {data.blast_radius && <div><h3 className="mb-1 text-xs font-semibold uppercase text-slate-500">Blast radius: {data.blast_radius.radius}</h3><p className="text-slate-600 dark:text-slate-300">{data.blast_radius.reasons?.join("; ")}</p></div>}
      <div className="grid grid-cols-2 gap-3">
        <div><h3 className="mb-1 text-xs font-semibold uppercase text-slate-500">Uses →</h3><ul className="space-y-0.5">{data.out.slice(0, 12).map((x: any, i: number) => <li key={i} className="truncate"><span className="text-[10px] text-slate-400">{x.type} </span><EntityLink id={x.node} label={x.label} /></li>)}</ul></div>
        <div><h3 className="mb-1 text-xs font-semibold uppercase text-slate-500">← Used by</h3><ul className="space-y-0.5">{data.in.slice(0, 12).map((x: any, i: number) => <li key={i} className="truncate"><span className="text-[10px] text-slate-400">{x.type} </span><EntityLink id={x.node} label={x.label} /></li>)}</ul></div>
      </div>
    </div>
  );
}

export function Spinner() { return <Loader2 className="h-4 w-4 animate-spin" />; }
