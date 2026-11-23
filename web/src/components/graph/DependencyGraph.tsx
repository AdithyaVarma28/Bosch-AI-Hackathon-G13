import { useEffect, useRef, useState } from "react"
import cytoscape, { Core } from "cytoscape"
import dagre from "cytoscape-dagre"
import { FocusGraph } from "../../model/graph"
import { tokens } from "../../theme/tokens"

let registered = false
function register() {
  if (registered) return
  try { cytoscape.use(dagre) } catch { /* already registered */ }
  registered = true
}

export function DependencyGraph({ graph, onSelect }: { graph: FocusGraph; onSelect: (id: string) => void }) {
  const el = useRef<HTMLDivElement>(null)
  const cy = useRef<Core | null>(null)
  const [zoom, setZoom] = useState(100)
  const onSelectRef = useRef(onSelect)
  onSelectRef.current = onSelect

  useEffect(() => {
    register()
    if (!el.current) return
    const inst = cytoscape({
      container: el.current,
      elements: [],
      style: [
        { selector: "node", style: { label: "data(label)", "text-valign": "center", "text-halign": "center", shape: "round-rectangle", width: 160, height: 48, "background-color": "#ffffff", "border-width": 1, "border-color": tokens.colors.border, "font-size": 10, color: tokens.colors.textPrimary, "text-wrap": "wrap" } },
        { selector: "node[sev = 'crit']", style: { "background-color": tokens.severity.Critical.bg, "border-color": tokens.severity.Critical.fg } },
        { selector: "node[sev = 'med']", style: { "background-color": tokens.severity.Medium.bg, "border-color": tokens.severity.Medium.fg } },
        { selector: "node[?dev]", style: { "border-style": "dashed" } },
        { selector: "node[?notObserved]", style: { opacity: 0.75 } },
        { selector: "node[?selected]", style: { "border-color": tokens.colors.link, "border-width": 2, "background-color": "#f8fafd" } },
        { selector: "node[?internal]", style: { "background-color": tokens.colors.subtle } },
        { selector: "edge", style: { width: 1, "line-color": tokens.colors.textFaint, "target-arrow-shape": "triangle", "target-arrow-color": tokens.colors.textFaint, "curve-style": "bezier" } },
        { selector: "edge[?onPath]", style: { "line-color": tokens.colors.link, "target-arrow-color": tokens.colors.link, width: 2 } },
      ],
    })
    inst.on("tap", "node", (e) => { if (!e.target.data("internal")) onSelectRef.current(e.target.id()) })
    inst.on("zoom", () => setZoom(Math.round(inst.zoom() * 100)))
    cy.current = inst
    return () => { inst.destroy(); cy.current = null }
  }, [])

  useEffect(() => {
    const inst = cy.current
    if (!inst) return
    inst.batch(() => {
      inst.elements().remove()
      inst.add([
        ...graph.nodes.map((n) => ({
          group: "nodes" as const,
          data: {
            id: n.id,
            label: n.internal ? n.label : [`${n.label}${n.version ? ` ${n.version}` : ""}`, n.vulnCount ? `${n.severity ?? ""} · ${n.vulnCount} vuln${n.vulnCount > 1 ? "s" : ""}` : "No known finding"].join("\n"),
            sev: n.severity === "Critical" || n.severity === "High" ? "crit" : n.severity ? "med" : "none",
            dev: n.scope === "Development", notObserved: !n.internal && n.usage === "Not observed",
            selected: n.id === graph.selected, internal: n.internal,
          },
        })),
        ...graph.edges.map((e) => ({ group: "edges" as const, data: { id: `${e.source}>${e.target}`, source: e.source, target: e.target, onPath: e.onSelectedPath } })),
      ])
    })
    inst.layout({ name: "dagre", rankDir: "LR", nodeSep: 20, rankSep: 70 } as any).run()
    inst.fit(undefined, 20)
  }, [graph])

  return (
    <div className="relative">
      <div ref={el} data-testid="graph-canvas" className="h-[420px] w-full rounded border border-border bg-surface" />
      <div className="absolute bottom-3 right-3 flex items-center gap-2 text-label bg-surface border border-border rounded px-2 py-1">
        <button aria-label="Zoom out" onClick={() => cy.current?.zoom(cy.current.zoom() / 1.2)}>−</button>
        <span>{zoom}%</span>
        <button aria-label="Zoom in" onClick={() => cy.current?.zoom(cy.current.zoom() * 1.2)}>+</button>
      </div>
      <ul className="mt-2 flex gap-5 text-label text-textMuted" aria-label="Legend">
        <li>→ Depends on</li>
        <li><span style={{ color: tokens.severity.Critical.fg }}>●</span> Critical / High</li>
        <li><span style={{ color: tokens.severity.Medium.fg }}>●</span> Medium</li>
        <li><span style={{ color: tokens.colors.textFaint }}>●</span> No known finding</li>
        <li><span style={{ color: tokens.colors.link }}>●</span> Selected path</li>
        <li>Dashed = development scope</li><li>Faded = Not observed in source</li><li>Referenced in source ≠ executed</li>
      </ul>
    </div>
  )
}
