import { Finding, Severity, VizGraph, VizNode } from "../api/types"
import { severityRank, splitPurl, toSeverity } from "./format"

export const MAX_NODES = 60

export type Usage = "Referenced" | "Not observed" | "Unknown"
export type Scope = "Production" | "Development"
export interface FocusNode { id: string; label: string; version: string | null; ecosystem: string; column: number; severity: Severity | null; vulnCount: number; internal: boolean; scope: Scope | null; usage: Usage }
export interface FocusEdge { source: string; target: string; onSelectedPath: boolean }
export interface GraphFilters { search: string; ecosystem: string | "All"; severity: Severity | "All"; depth: number | "All"; scope: "All" | Scope; vulnerableOnly: boolean; unreferencedOnly: boolean }
export interface FocusGraph { nodes: FocusNode[]; edges: FocusEdge[]; shown: number; total: number; selected: string | null }
export const NO_GRAPH_FILTER: GraphFilters = { search: "", ecosystem: "All", severity: "All", depth: "All", scope: "All", vulnerableOnly: false, unreferencedOnly: false }

// Real viz.json: artifact nodes (id = purl with version) carry depth/direct/vulns; DEPENDS_ON links artifact->artifact;
// the project reaches direct artifacts through DECLARES+HAS_ARTIFACT, so we join project -> {artifact.direct === true}.
function vulnIndex(findings: Finding[]) {
  const idx = new Map<string, { severity: Severity; count: number }>()
  for (const f of findings) {
    if (f.cls !== "vuln") continue
    const sev = toSeverity(f.signals?.severity_band)
    const cur = idx.get(f.subject)
    if (!cur) idx.set(f.subject, { severity: sev, count: 1 })
    else { cur.count++; if (severityRank(sev) < severityRank(cur.severity)) cur.severity = sev }
  }
  return idx
}

export function defaultSelection(findings: Finding[]): string | null {
  let best: { id: string; rank: number; cvss: number } | null = null
  for (const f of findings) {
    if (f.cls !== "vuln") continue
    const rank = severityRank(toSeverity(f.signals?.severity_band))
    const cvss = typeof f.signals?.cvss === "number" ? f.signals.cvss : -1
    if (!best || rank < best.rank || (rank === best.rank && cvss > best.cvss)) best = { id: f.subject, rank, cvss }
  }
  return best?.id ?? null
}

const scopeOf = (v: unknown): Scope | null => (v === "prod" ? "Production" : v === "dev" ? "Development" : null)

// Static references only: a source reference is not proof that the code runs.
function usageOf(viz: VizGraph, findings: Finding[], id: string): Usage {
  const b = viz.blast?.[id]
  if (!b) return "Unknown"
  const imported = findings.some((f) => f.subject === id && Array.isArray(f.signals?.imported_by) && f.signals.imported_by.length > 0)
  return (b.files?.length ?? 0) > 0 || imported ? "Referenced" : "Not observed"
}

/**
 * Components are the targets of HAS_ARTIFACT edges. A declared-only (unversioned) component has the same id as its
 * package, so the viz keeps it as a "package" node; counting only type "artifact" would drop those.
 */
export function componentNodes(viz: VizGraph): VizNode[] {
  const targets = new Set(viz.edges.filter((e) => e.rel === "HAS_ARTIFACT").map((e) => e.t))
  if (targets.size === 0) return viz.nodes.filter((n) => n.type === "artifact")
  return viz.nodes.filter((n) => targets.has(n.id) && (n.type === "artifact" || n.type === "package"))
}

function build(viz: VizGraph) {
  const project = viz.nodes.find((n) => n.type === "project") ?? null
  const artifacts = componentNodes(viz)
  const ids = new Set(artifacts.map((a) => a.id))
  const out = new Map<string, Set<string>>()
  const inn = new Map<string, Set<string>>()
  const link = (s: string, t: string) => {
    if (!out.has(s)) out.set(s, new Set())
    if (!inn.has(t)) inn.set(t, new Set())
    out.get(s)!.add(t); inn.get(t)!.add(s)
  }
  for (const e of viz.edges) if (e.rel === "DEPENDS_ON" && ids.has(e.s) && ids.has(e.t)) link(e.s, e.t)
  if (project) for (const a of artifacts) if (a.direct === true) link(project.id, a.id)
  return { project, artifacts, ids, out, inn }
}

function distances(start: string | undefined, out: Map<string, Set<string>>) {
  const dist = new Map<string, number>()
  if (!start) return dist
  dist.set(start, 0)
  const q = [start]
  while (q.length) {
    const cur = q.shift()!
    for (const n of out.get(cur) ?? []) if (!dist.has(n)) { dist.set(n, dist.get(cur)! + 1); q.push(n) }
  }
  return dist
}

function pathTo(start: string, target: string, out: Map<string, Set<string>>): string[] {
  const prev = new Map<string, string>()
  const seen = new Set([start])
  const q = [start]
  while (q.length) {
    const cur = q.shift()!
    if (cur === target) break
    for (const n of out.get(cur) ?? []) if (!seen.has(n)) { seen.add(n); prev.set(n, cur); q.push(n) }
  }
  if (!seen.has(target)) return []
  const p = [target]
  while (p[0] !== start) p.unshift(prev.get(p[0])!)
  return p
}

export function focusGraph(viz: VizGraph, findings: Finding[], selected: string | null, filters: GraphFilters): FocusGraph {
  const { project, artifacts, out, inn } = build(viz)
  const total = artifacts.length
  const vi = vulnIndex(findings)
  const dist = distances(project?.id, out)
  const byId = new Map(viz.nodes.map((n) => [n.id, n]))

  const path = project && selected ? pathTo(project.id, selected, out) : []
  const onPath = new Set(path)
  const ordered: string[] = []
  const add = (id: string) => { if (!ordered.includes(id) && byId.has(id)) ordered.push(id) }
  if (project) add(project.id)
  path.forEach(add)
  if (selected && !path.length && byId.has(selected)) add(selected)
  for (const id of path) { for (const n of out.get(id) ?? []) add(n); for (const n of inn.get(id) ?? []) add(n) }
  if (!path.length) {
    const direct = artifacts.filter((a) => a.direct === true).sort((a, b) => severityRank(vi.get(a.id)?.severity ?? "Unknown") - severityRank(vi.get(b.id)?.severity ?? "Unknown"))
    direct.forEach((a) => add(a.id))
    direct.forEach((a) => { for (const n of out.get(a.id) ?? []) add(n) })
  }

  if (filters.vulnerableOnly || filters.unreferencedOnly || filters.scope !== "All")
    for (const a of artifacts) add(a.id) // filters look across all components, not just the focused paths
  const needle = filters.search.trim().toLowerCase()
  const nodes: FocusNode[] = []
  for (const id of ordered) {
    const n = byId.get(id)!
    const internal = n.type === "project"
    const { name, version, ecosystem } = splitPurl(id)
    const v = vi.get(id)
    const node: FocusNode = {
      id, label: internal ? n.label : name, version: internal ? null : (n.version ?? version),
      ecosystem: internal ? "" : (n.ecosystem ?? ecosystem), column: dist.get(id) ?? (n.depth ?? 0) + 1,
      severity: v?.severity ?? null, vulnCount: v?.count ?? n.vulns ?? 0, internal,
      scope: internal ? null : scopeOf(n.scope), usage: internal ? "Unknown" : usageOf(viz, findings, id),
    }
    if (!internal) {
      if (filters.ecosystem !== "All" && node.ecosystem !== filters.ecosystem) continue
      if (filters.severity !== "All" && node.severity !== filters.severity) continue
      if (filters.depth !== "All" && node.column > filters.depth) continue
      if (filters.scope !== "All" && node.scope !== filters.scope) continue
      if (filters.vulnerableOnly && node.vulnCount === 0) continue
      if (filters.unreferencedOnly && node.usage === "Referenced") continue
      if (needle && !node.label.toLowerCase().includes(needle) && !id.toLowerCase().includes(needle)) continue
    }
    nodes.push(node)
    if (nodes.length >= MAX_NODES) break
  }
  const drawn = new Set(nodes.map((n) => n.id))
  const edges: FocusEdge[] = []
  for (const [s, ts] of out) for (const t of ts)
    if (drawn.has(s) && drawn.has(t)) edges.push({ source: s, target: t, onSelectedPath: onPath.has(s) && onPath.has(t) })
  return { nodes, edges, shown: nodes.filter((n) => !n.internal).length, total, selected }
}

export interface SecurityEntry { advisoryId: string; summary: string; severity: Severity; cvss: number | null; findingId: string; affected: string | null; fixed: string | null; reference: string }
export interface CodeUsage { usage: Usage; files: string[]; functions: string[]; routes: string[]; sensitiveCalls: string[]; note: string }
export interface ComponentDetails {
  purl: string; name: string; version: string | null; severity: Severity | null; ecosystem: string
  dependencyType: "Direct" | "Transitive" | "—"; parent: string | null; depth: number | null
  vulnerabilities: { advisoryId: string; summary: string; severity: Severity; cvss: number | null; findingId: string }[]
  path: string[]
  overview: { name: string; version: string | null; ecosystem: string; dependencyType: "Direct" | "Transitive" | "—"; scope: Scope | null; depth: number | null }
  security: SecurityEntry[]
  code: CodeUsage
  upstream: string[]
  downstream: string[]
}

const NOTE = "Referenced in source means a static import or call was found. It is not proof that the code runs."
const strip = (x: string, prefix: string) => (x.startsWith(prefix) ? x.slice(prefix.length) : x)
const nameVer = (purl: string) => { const p = splitPurl(purl); return p.version ? `${p.name}@${p.version}` : p.name }

export function componentDetails(viz: VizGraph, findings: Finding[], purl: string): ComponentDetails {
  const { project, out, inn } = build(viz)
  const node = viz.nodes.find((n) => n.id === purl)
  const { name, version, ecosystem } = splitPurl(purl)
  const own = findings.filter((f) => f.cls === "vuln" && f.subject === purl)
  const vulns = own
    .map((f) => ({ advisoryId: f.signals?.advisory_id ?? f.locator, summary: f.signals?.summary ?? f.title, severity: toSeverity(f.signals?.severity_band), cvss: typeof f.signals?.cvss === "number" ? f.signals.cvss : null, findingId: f.id }))
    .sort((a, b) => severityRank(a.severity) - severityRank(b.severity))
  const security: SecurityEntry[] = vulns.map((v) => {
    const f = own.find((x) => x.id === v.findingId)!
    const fx: string[] = Array.isArray(f.signals?.fixed_versions) ? f.signals.fixed_versions : []
    const ver = node?.version ?? version
    return { ...v, affected: ver ? `${ver} (installed)` : null, fixed: fx.length ? fx.join(", ") : null, reference: `https://osv.dev/vulnerability/${encodeURIComponent(v.advisoryId)}` }
  })
  const path = project && node ? pathTo(project.id, purl, out) : []
  const parents = [...(inn.get(purl) ?? [])].filter((p) => p !== project?.id)
  const dependencyType = node ? (node.direct === true ? "Direct" : node.direct === false ? "Transitive" : "—") : "—"
  const depth = node ? (path.length ? path.length - 1 : null) : null
  const b = viz.blast?.[purl]
  const funcs = (b?.functions ?? []).map((f) => strip(f, "func:"))
  const fnIds = new Set(b?.functions ?? [])
  const labels = new Map(viz.nodes.map((n) => [n.id, n.label]))
  const sensitive = [...new Set(viz.edges.filter((e) => e.rel === "SENSITIVE_CALL" && fnIds.has(e.s)).map((e) => labels.get(e.t) ?? e.t))]
  return {
    purl, name, version: node?.version ?? version, ecosystem: node?.ecosystem ?? ecosystem,
    severity: vulns[0]?.severity ?? null,
    dependencyType,
    parent: parents.length ? splitPurl(parents[0]).name : null,
    depth,
    vulnerabilities: vulns.map(({ advisoryId, summary, severity, cvss, findingId }) => ({ advisoryId, summary, severity, cvss, findingId })),
    path: path.slice(1),
    overview: { name, version: node?.version ?? version, ecosystem: node?.ecosystem ?? ecosystem, dependencyType, scope: scopeOf(node?.scope), depth },
    security,
    code: {
      usage: usageOf(viz, findings, purl),
      files: (b?.files ?? []).map((f) => strip(f, "file:")),
      functions: funcs,
      routes: (b?.routes ?? []).map((r) => strip(r, "route:")),
      sensitiveCalls: sensitive,
      note: NOTE,
    },
    upstream: parents.map(nameVer),
    downstream: [...(out.get(purl) ?? [])].map(nameVer),
  }
}
