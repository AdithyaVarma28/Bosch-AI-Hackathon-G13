// Cytoscape wrapper: legend, search, zoom-to-fit, focus mode, colour-by. Click = peek; double-click = onExpand.
import cytoscape, { Core } from "cytoscape";
import { useEffect, useMemo, useRef, useState } from "react";
import { Maximize2, Search } from "lucide-react";
import { GraphData } from "../api";

const RISK_COLOR: Record<string, string> = { critical: "#dc2626", high: "#ea580c", medium: "#d97706", low: "#64748b" };
const TYPE_COLOR: Record<string, string> = { Module: "#6366f1", File: "#0ea5e9", Function: "#8b5cf6", Route: "#16a34a", CLIEntry: "#16a34a",
  ExternalService: "#f59e0b", Table: "#14b8a6", EnvVar: "#e11d48", Package: "#475569", Class: "#a855f7" };
const STATUS_COLOR: Record<string, string> = { added: "#16a34a", removed: "#dc2626", changed: "#d97706", same: "#94a3b8" };

export type ColorBy = "risk" | "type" | "sensitivity" | "changed" | "status";

export default function GraphView({ data, onSelect, onExpand, layout = "cose", height = 520, colorBy = "type", statusOf }:
  { data: GraphData; onSelect?: (id: string) => void; onExpand?: (id: string) => void; layout?: "cose" | "breadthfirst";
    height?: number; colorBy?: ColorBy; statusOf?: (id: string) => string | undefined }) {
  const ref = useRef<HTMLDivElement>(null);
  const cy = useRef<Core | null>(null);
  const [q, setQ] = useState("");
  const [focus, setFocus] = useState<string | null>(null);

  const elements = useMemo(() => {
    const ids = new Set(data.nodes.map(n => n.id));
    return [
      ...data.nodes.slice(0, 150).map(n => {
        const color = colorBy === "risk" ? (n.risk ? RISK_COLOR[n.risk] : "#cbd5e1")
          : colorBy === "sensitivity" ? ({ high: "#dc2626", medium: "#d97706", low: "#94a3b8" } as any)[n.sensitivity ?? ""] ?? "#cbd5e1"
          : colorBy === "changed" ? (n.changed ? "#d97706" : "#cbd5e1")
          : colorBy === "status" ? STATUS_COLOR[statusOf?.(n.id) ?? "same"]
          : TYPE_COLOR[n.type] ?? "#94a3b8";
        const size = n.type === "Module" ? 30 + Math.min(40, (n.files ?? 1) * 6) : 22;
        return { data: { id: n.id, label: n.label, color, size, border: n.risk ? RISK_COLOR[n.risk] : "#ffffff", type: n.type } };
      }),
      ...data.edges.filter(e => ids.has(e.source) && ids.has(e.target)).map((e, i) => ({
        data: { id: `e${i}`, source: e.source, target: e.target, label: e.type === "DEPENDS_ON" ? (e.weight > 1 ? `${e.weight}` : "") : e.type.toLowerCase(), w: Math.min(6, 1 + e.weight) },
      })),
    ];
  }, [data, colorBy, statusOf]);

  useEffect(() => {
    if (!ref.current) return;
    const c = cytoscape({
      container: ref.current, elements, wheelSensitivity: 0.3,
      style: [
        { selector: "node", style: { "background-color": "data(color)", label: "data(label)", "font-size": 10, color: "#334155", "text-valign": "bottom", "text-margin-y": 4, width: "data(size)", height: "data(size)", "border-width": 3, "border-color": "data(border)", "text-wrap": "ellipsis", "text-max-width": "120px" } },
        { selector: "node[type = 'Module']", style: { shape: "round-rectangle", "font-weight": "bold", "font-size": 11 } },
        { selector: "edge", style: { width: "data(w)", "line-color": "#cbd5e1", "target-arrow-color": "#cbd5e1", "target-arrow-shape": "triangle", "curve-style": "bezier", label: "data(label)", "font-size": 8, color: "#94a3b8" } },
        { selector: ".dim", style: { opacity: 0.12 } },
        { selector: ".hit", style: { "border-color": "#4f46e5", "border-width": 5 } },
      ],
      layout: layout === "breadthfirst" ? { name: "breadthfirst", directed: true, spacingFactor: 1.2 } as any : { name: "cose", animate: false, nodeRepulsion: () => 9000, idealEdgeLength: () => 90 } as any,
    });
    c.on("tap", "node", ev => { setFocus(ev.target.id()); onSelect?.(ev.target.id()); });
    c.on("dbltap", "node", ev => onExpand?.(ev.target.id()));
    c.on("tap", ev => { if (ev.target === c) setFocus(null); });
    cy.current = c;
    return () => c.destroy();
  }, [elements, layout]);

  useEffect(() => {
    const c = cy.current;
    if (!c) return;
    c.elements().removeClass("dim hit");
    if (focus) {
      const n = c.getElementById(focus);
      const keep = n.closedNeighborhood();
      c.elements().difference(keep).addClass("dim");
    }
    if (q) c.nodes().filter(n => String(n.data("label")).toLowerCase().includes(q.toLowerCase())).addClass("hit");
  }, [focus, q]);

  const types = [...new Set(data.nodes.map(n => n.type))];
  return (
    <div className="relative rounded-xl border border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900">
      <div className="absolute left-2 top-2 z-10 flex items-center gap-2">
        <label className="flex items-center gap-1 rounded border border-slate-200 bg-white px-2 py-1 text-xs dark:border-slate-700 dark:bg-slate-900">
          <Search className="h-3 w-3" /><input aria-label="Search graph" value={q} onChange={e => setQ(e.target.value)} placeholder="Find node" className="w-28 bg-transparent outline-none" />
        </label>
        <button onClick={() => { setFocus(null); cy.current?.fit(undefined, 30); }} className="flex items-center gap-1 rounded border border-slate-200 bg-white px-2 py-1 text-xs dark:border-slate-700 dark:bg-slate-900"><Maximize2 className="h-3 w-3" />Fit</button>
        {focus && <span className="rounded bg-indigo-50 px-2 py-1 text-xs text-indigo-700">Focus mode · click background to exit</span>}
      </div>
      <div ref={ref} style={{ height }} />
      <div className="absolute bottom-2 left-2 z-10 flex flex-wrap gap-2 rounded bg-white/90 px-2 py-1 text-[11px] dark:bg-slate-900/90">
        {colorBy === "risk" ? Object.entries(RISK_COLOR).map(([k, v]) => <span key={k} className="flex items-center gap-1"><i className="inline-block h-2.5 w-2.5 rounded-full" style={{ background: v }} />{k}</span>)
          : colorBy === "status" ? Object.entries(STATUS_COLOR).map(([k, v]) => <span key={k} className="flex items-center gap-1"><i className="inline-block h-2.5 w-2.5 rounded-full" style={{ background: v }} />{k}</span>)
          : types.map(t => <span key={t} className="flex items-center gap-1"><i className="inline-block h-2.5 w-2.5 rounded-full" style={{ background: TYPE_COLOR[t] ?? "#94a3b8" }} />{t}</span>)}
        <span className="text-slate-400">· border = highest risk · click = peek · double-click = expand</span>
      </div>
    </div>
  );
}
