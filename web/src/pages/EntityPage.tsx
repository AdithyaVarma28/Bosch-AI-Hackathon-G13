// Full page for modules, packages, functions, commits and any other graph entity (generic entity endpoint).
import { useParams, useSearchParams } from "react-router-dom";
import { useEntity, useGraph } from "../api";
import GraphView from "../components/GraphView";
import { AIBadge, EntityIcon, EntityLink, EntitySummary, EvidenceList, PageHeader, Panel, QueryState, RiskChip, cx, usePeek } from "../components/ui";

const KIND_LABEL: Record<string, string> = { modules: "Modules", packages: "Packages", functions: "Functions", commits: "Commits", entity: "Entities" };

export default function EntityPage() {
  const { scanId = "", kind = "entity", entityId = "" } = useParams();
  const id = decodeURIComponent(entityId);
  const q = useEntity(scanId, id);
  const [sp, setSp] = useSearchParams();
  const tab = sp.get("tab") ?? "overview";
  const isModule = id.startsWith("module:"), isPkg = id.startsWith("pkg:");
  const g = useGraph(scanId, "module", isModule ? id : undefined);
  const peek = usePeek();
  const tabs = isPkg ? ["overview", "dependency tree", "where used", "blast radius", "findings", "history"] : isModule ? ["overview", "graph", "findings"] : ["overview", "findings"];
  return (
    <div>
      <PageHeader crumbs={[{ label: "Overview", to: `/scans/${scanId}` }, { label: KIND_LABEL[kind] ?? kind, to: kind === "packages" ? `/scans/${scanId}/packages` : undefined }, { label: q.data?.entity?.label ?? id }]}
        icon={<EntityIcon id={id} className="h-6 w-6" />} title={q.data?.entity?.label ?? id}>
        {q.data?.findings?.length ? <RiskChip risk={q.data.findings[0].project_risk} /> : null}
      </PageHeader>
      <QueryState q={q} rows={8}>{() => {
        const d = q.data, e = d.entity;
        return (
          <>
            <div className="mb-3 flex flex-wrap gap-1">{(e.tags ?? []).map((t: string) => <span key={t} className="rounded bg-slate-100 px-1.5 text-xs dark:bg-slate-800">{t}</span>)}{isPkg && <span className="rounded bg-slate-100 px-1.5 text-xs dark:bg-slate-800">{e.direct ? "direct" : "transitive"} · {e.dev ? "dev" : "runtime"}</span>}</div>
            <div className="mb-4 flex gap-1 border-b border-slate-200 dark:border-slate-700">{tabs.map(t => <button key={t} onClick={() => { const n = new URLSearchParams(sp); n.set("tab", t); setSp(n); }} className={cx("px-3 py-1.5 text-sm capitalize", tab === t ? "border-b-2 border-indigo-600 font-medium" : "text-slate-500")}>{t}</button>)}</div>
            {tab === "overview" && <div className="grid gap-4 lg:grid-cols-2">
              <Panel title="Summary"><EntitySummary data={d} /></Panel>
              {d.card && <Panel title="AI card"><AIBadge by={d.card.discovered_by} confidence={d.card.confidence} /><p className="mt-2 text-sm">{d.card.purpose}</p>
                {["responsibilities", "inputs", "outputs", "data_touched", "external"].map(k => d.card[k]?.length ? <p key={k} className="mt-1 text-sm"><b className="capitalize">{k.replace("_", " ")}:</b> {d.card[k].join(", ")}</p> : null)}
                <div className="mt-2"><EvidenceList items={d.card.evidence ?? []} /></div></Panel>}
              {e.type === "Commit" && <Panel title="Commit"><p className="text-sm"><b>{e.message}</b></p><p className="text-xs text-slate-500">{e.author} · {e.date}</p>
                <p className="mt-2 text-sm">Added: {(e.added ?? []).join(", ") || "—"} · Changed: {(e.changed ?? []).map((c: any) => `${c.name} ${c.from}→${c.to}`).join(", ") || "—"}</p><p className="text-sm">Files: {(e.files_changed ?? []).join(", ")}</p></Panel>}
              {d.stage3_findings?.length > 0 && <Panel title="Investigator notes (Stage 3)"><ul className="space-y-2 text-sm">{d.stage3_findings.map((f: any) => <li key={f.id}><AIBadge by={f.discovered_by} confidence={f.confidence} /> {f.answer}</li>)}</ul></Panel>}
            </div>}
            {tab === "graph" && <QueryState q={g}>{() => <GraphView data={g.data!} onSelect={x => peek.open(x)} colorBy="type" />}</QueryState>}
            {tab === "dependency tree" && <div className="grid gap-4 lg:grid-cols-2">
              <Panel title="Pulled in by ↑"><ul className="space-y-1 text-sm">{d.in.filter((x: any) => x.type === "REQUIRES").map((x: any) => <li key={x.node}><EntityLink id={x.node} label={x.label} /></li>)}{e.direct && <li className="text-slate-500">declared directly: {e.evidence?.map((v: any) => `${v.file}:${v.line}`).join(", ")}</li>}</ul></Panel>
              <Panel title="Pulls in ↓"><ul className="space-y-1 text-sm">{d.out.filter((x: any) => x.type === "REQUIRES").map((x: any) => <li key={x.node}><EntityLink id={x.node} label={x.label} /></li>)}</ul></Panel></div>}
            {tab === "where used" && <Panel title="Files → functions → API calls"><ul className="space-y-1 text-sm">{d.in.filter((x: any) => ["USES_PACKAGE", "CALLS_API"].includes(x.type)).map((x: any, i: number) => <li key={i}><span className="text-xs text-slate-400">{x.type} </span><EntityLink id={x.node} label={x.label} /> <span className="text-xs text-slate-500">{x.evidence.map((v: any) => `${v.file}:${v.line ?? v.lines}`).join(", ")}</span></li>)}</ul></Panel>}
            {tab === "blast radius" && (d.blast_radius ? <Panel title={`Blast radius: ${d.blast_radius.radius}`}><p className="mb-2 text-sm">{d.blast_radius.reasons.join("; ")}</p>
              <p className="text-sm"><b>Routes:</b> {d.blast_radius.routes_reaching.map((r: string) => <span key={r} className="mr-2"><EntityLink id={r} /></span>)}</p>
              <p className="text-sm"><b>Functions:</b> {d.blast_radius.functions.map((f: string) => <span key={f} className="mr-2"><EntityLink id={f} /></span>)}</p>
              <p className="text-sm"><b>Nearby:</b> {[...d.blast_radius.secrets_nearby, ...d.blast_radius.tables_nearby, ...d.blast_radius.services_nearby].map((s: string) => <span key={s} className="mr-2"><EntityLink id={s} /></span>)}</p></Panel> : <p className="text-sm text-slate-500">No blast radius for this entity.</p>)}
            {tab === "findings" && <Panel title="Findings">{d.findings.length ? <ul className="space-y-1">{d.findings.map((f: any) => <li key={f.finding_id} className="flex items-center gap-2 text-sm"><RiskChip risk={f.project_risk} /><EntityLink id={f.finding_id} label={`${f.finding_id} ${f.title}`} /></li>)}</ul> : <p className="text-sm text-slate-500">No findings.</p>}</Panel>}
            {tab === "history" && <Panel title="Commits that changed it"><ul className="space-y-1 text-sm">{d.out.filter((x: any) => x.type === "CHANGED_IN").map((x: any) => <li key={x.node}><EntityLink id={x.node} label={x.label} /></li>)}</ul></Panel>}
          </>);
      }}</QueryState>
    </div>
  );
}
