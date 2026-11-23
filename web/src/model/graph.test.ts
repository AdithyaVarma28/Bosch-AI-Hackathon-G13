import report from "../fixtures/report.mini-shop.json"
import vizFx from "../fixtures/viz.mini-shop.json"
import { Report, VizGraph } from "../api/types"
import { componentDetails, componentNodes, defaultSelection, focusGraph, MAX_NODES, NO_GRAPH_FILTER as none } from "./graph"

const rep = report as unknown as Report
const viz = vizFx as unknown as VizGraph
const findings = rep.findings
const MINIMIST = "pkg:npm/minimist@0.0.8"

test("the default selection is the most severe vulnerable component", () => {
  expect(defaultSelection(findings)).toBe(MINIMIST)
})
test("no vulnerable component gives a null default selection", () => {
  expect(defaultSelection([])).toBeNull()
})
test("the focused graph contains the application node and the path to the selected component", () => {
  const g = focusGraph(viz, findings, MINIMIST, none)
  expect(g.nodes.map((n) => n.id)).toEqual(expect.arrayContaining(["project:guardian-fixture", "pkg:npm/mkdirp@0.5.1", MINIMIST]))
  expect(g.edges.filter((e) => e.onSelectedPath).map((e) => `${e.source}>${e.target}`).sort()).toEqual([
    `pkg:npm/mkdirp@0.5.1>${MINIMIST}`, "project:guardian-fixture>pkg:npm/mkdirp@0.5.1",
  ])
})
test("columns are the distance from the application node", () => {
  const g = focusGraph(viz, findings, MINIMIST, none)
  expect(g.nodes.find((n) => n.internal)!.column).toBe(0)
  expect(g.nodes.find((n) => n.id === "pkg:npm/mkdirp@0.5.1")!.column).toBe(1)
  expect(g.nodes.find((n) => n.id === MINIMIST)!.column).toBe(2)
})
test("severity and vulnerability count are joined from findings", () => {
  const g = focusGraph(viz, findings, MINIMIST, none)
  expect(g.nodes.find((n) => n.id === MINIMIST)).toMatchObject({ severity: "Critical", vulnCount: 2, label: "minimist", version: "0.0.8" })
})
test("with no selection the application and its direct dependencies are shown", () => {
  const g = focusGraph(viz, findings, null, none)
  expect(g.nodes.filter((n) => n.column === 1).length).toBe(11)
  expect(g.total).toBe(13)
})
test("the drawn set is capped and total is the full artifact count", () => {
  const nodes = [{ id: "project:p", type: "project", label: "p" }, ...Array.from({ length: 5000 }, (_, i) => ({ id: `pkg:npm/p${i}@1`, type: "artifact", label: `p${i}`, direct: true, ecosystem: "npm" }))]
  const g = focusGraph({ nodes, edges: [], blast: {} } as VizGraph, [], null, none)
  expect(g.nodes.length).toBeLessThanOrEqual(MAX_NODES)
  expect(g.total).toBe(5000)
  expect(g.shown).toBe(g.nodes.filter((n) => !n.internal).length)
})
test("severity and ecosystem filters narrow the drawn nodes", () => {
  const g = focusGraph(viz, findings, null, { ...none, severity: "High" })
  expect(g.nodes.filter((n) => !n.internal).every((n) => n.severity === "High")).toBe(true)
  const py = focusGraph(viz, findings, null, { ...none, ecosystem: "pypi" })
  expect(py.nodes.filter((n) => !n.internal).every((n) => n.ecosystem === "pypi")).toBe(true)
})
test("search matches name or package url, case-insensitively", () => {
  const g = focusGraph(viz, findings, null, { ...none, search: "REQUESTS" })
  expect(g.nodes.filter((n) => !n.internal).map((n) => n.label)).toEqual(["requests"])
})
test("the depth filter hides nodes beyond that distance", () => {
  const g = focusGraph(viz, findings, MINIMIST, { ...none, depth: 1 })
  expect(g.nodes.find((n) => n.id === MINIMIST)).toBeUndefined()
})
test("componentDetails returns type, depth, path, parent and associated vulnerabilities", () => {
  const d = componentDetails(viz, findings, MINIMIST)
  expect(d).toMatchObject({ name: "minimist", version: "0.0.8", dependencyType: "Transitive", parent: "mkdirp", depth: 2, severity: "Critical" })
  expect(d.vulnerabilities.length).toBe(2)
  expect(d.path).toEqual(["pkg:npm/mkdirp@0.5.1", MINIMIST])
})
test("an unknown purl gives null-safe details", () => {
  const d = componentDetails(viz, findings, "pkg:pypi/nope@1")
  expect(d.vulnerabilities).toEqual([])
  expect(d).toMatchObject({ dependencyType: "—", depth: null, parent: null })
})
test("an empty viz graph yields an empty focus without throwing", () => {
  expect(focusGraph({ nodes: [], edges: [], blast: {} }, [], null, none)).toMatchObject({ nodes: [], shown: 0, total: 0 })
})

// --- enriched nodes and details (scope, source usage, sections) ---------------
const FLASK = "pkg:pypi/flask@2.0.1"
const PYTEST = "pkg:pypi/pytest@7.0.0"

test("nodes carry production/development scope and source usage", () => {
  const g = focusGraph(viz, findings, null, none)
  expect(g.nodes.find((n) => n.id === FLASK)).toMatchObject({ scope: "Production", usage: "Referenced" })
  expect(g.nodes.find((n) => n.id === PYTEST)).toMatchObject({ scope: "Development", usage: "Not observed" })
})
test("scope, vulnerable-only and not-observed filters narrow the drawn nodes", () => {
  const dev = focusGraph(viz, findings, null, { ...none, scope: "Development" })
  expect(dev.nodes.filter((n) => !n.internal).every((n) => n.scope === "Development")).toBe(true)
  const vul = focusGraph(viz, findings, null, { ...none, vulnerableOnly: true })
  expect(vul.nodes.filter((n) => !n.internal).every((n) => n.vulnCount > 0)).toBe(true)
  const unref = focusGraph(viz, findings, null, { ...none, unreferencedOnly: true })
  expect(unref.nodes.filter((n) => !n.internal).every((n) => n.usage !== "Referenced")).toBe(true)
  expect(unref.nodes.length).toBeGreaterThan(1)
})
test("details have overview, security, code usage and dependency path sections", () => {
  const d = componentDetails(viz, findings, FLASK)
  expect(d.overview).toMatchObject({ scope: "Production", ecosystem: "pypi", dependencyType: "Direct" })
  expect(d.security.length).toBe(2)
  expect(d.security[0]).toMatchObject({ advisoryId: "GHSA-m2qf-hxjv-5gpq", fixed: "2.2.5, 2.3.2", affected: "2.0.1 (installed)" })
  expect(d.code.usage).toBe("Referenced")
  expect(d.code.files).toEqual(["app/__init__.py", "app/api/routes.py"])
  expect(d.code.functions).toContain("app/api/routes.py::checkout")
  expect(d.code.routes).toEqual(["POST /checkout"])
})
test("code usage never claims execution", () => {
  expect(componentDetails(viz, findings, FLASK).code.note).toMatch(/referenced in source/i)
  expect(componentDetails(viz, findings, FLASK).code.note).toMatch(/not (proof|evidence)/i)
})
test("a package with no source references says so without guessing", () => {
  const d = componentDetails(viz, findings, PYTEST)
  expect(d.code).toMatchObject({ usage: "Not observed", files: [], functions: [], routes: [] })
})
test("upstream and downstream relationships are listed", () => {
  const d = componentDetails(viz, findings, "pkg:npm/minimist@0.0.8")
  expect(d.upstream).toEqual(["mkdirp@0.5.1"])
  const m = componentDetails(viz, findings, "pkg:npm/mkdirp@0.5.1")
  expect(m.downstream).toEqual(["minimist@0.0.8"])
})
test("sensitive calls are those in functions that use the package", () => {
  const d = componentDetails(viz, findings, FLASK)
  expect(Array.isArray(d.code.sensitiveCalls)).toBe(true)
})
test("an unknown package has Unknown usage", () => {
  expect(componentDetails(viz, findings, "pkg:pypi/nope@1").code.usage).toBe("Unknown")
})

// --- unversioned components: package id == artifact id, so the viz keeps them as "package" nodes ---------
const declaredOnly = (): VizGraph => ({
  nodes: [
    { id: "project:app", type: "project", label: "app" },
    { id: "pkg:npm/express", type: "package", label: "express", ecosystem: "npm", scope: "prod", direct: true },
    { id: "pkg:npm/lodash@4.17.21", type: "artifact", label: "lodash@4.17.21", ecosystem: "npm", scope: "prod", direct: true, version: "4.17.21" },
    { id: "pkg:npm/lodash", type: "package", label: "lodash", ecosystem: "npm" },
  ],
  edges: [
    { s: "pkg:npm/express", t: "pkg:npm/express", rel: "HAS_ARTIFACT", status: "declared" },
    { s: "pkg:npm/lodash", t: "pkg:npm/lodash@4.17.21", rel: "HAS_ARTIFACT", status: "verified" },
  ],
  blast: {},
})
test("components are the targets of HAS_ARTIFACT edges, including unversioned package nodes", () => {
  expect(componentNodes(declaredOnly()).map((n) => n.id).sort()).toEqual(["pkg:npm/express", "pkg:npm/lodash@4.17.21"])
})
test("the total counts unversioned components and matches the drawn candidates", () => {
  const g = focusGraph(declaredOnly(), [], null, none)
  expect(g.total).toBe(2)
  expect(g.nodes.filter((n) => !n.internal).map((n) => n.id).sort()).toEqual(["pkg:npm/express", "pkg:npm/lodash@4.17.21"])
})
test("a declared-only component can be selected and shows details", () => {
  const d = componentDetails(declaredOnly(), [], "pkg:npm/express")
  expect(d).toMatchObject({ name: "express", dependencyType: "Direct", version: null })
})
test("a viz with no HAS_ARTIFACT edges falls back to artifact nodes", () => {
  const v = declaredOnly(); v.edges = []
  expect(componentNodes(v).map((n) => n.id)).toEqual(["pkg:npm/lodash@4.17.21"])
})
