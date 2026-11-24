import { useNavigate, useParams, useSearchParams } from "react-router-dom";
import { useGraph } from "../api";
import GraphView, { ColorBy } from "../components/GraphView";
import { PageHeader, QueryState, entityHref, usePeek } from "../components/ui";

export default function MapPage() {
  const { scanId = "" } = useParams();
  const [sp, setSp] = useSearchParams();
  const module = sp.get("module") ?? undefined;
  const colorBy = (sp.get("color") as ColorBy) ?? "risk";
  const q = useGraph(scanId, module ? "module" : "repo", module);
  const peek = usePeek();
  const nav = useNavigate();
  const set = (k: string, v?: string) => { const n = new URLSearchParams(sp); v ? n.set(k, v) : n.delete(k); setSp(n); };
  return (
    <div>
      <PageHeader crumbs={[{ label: "Overview", to: `/scans/${scanId}` }, { label: "Map", to: module ? `/scans/${scanId}/map` : undefined }, ...(module ? [{ label: module.replace("module:", "") }] : [])]}
        title={module ? `Module ${module.replace("module:", "")}` : "Architecture map"}>
        <label className="text-sm">Colour by{" "}
          <select value={colorBy} onChange={e => set("color", e.target.value)} className="rounded border border-slate-200 bg-transparent px-1 dark:border-slate-700">
            <option value="risk">risk</option><option value="type">type</option><option value="sensitivity">sensitivity</option><option value="changed">changed recently</option>
          </select></label>
        {module && <button onClick={() => set("module")} className="rounded border border-slate-200 px-2 py-1 text-sm dark:border-slate-700">Back to modules</button>}
      </PageHeader>
      <QueryState q={q} rows={10}>{() => <GraphView data={q.data!} colorBy={colorBy} height={600}
        onSelect={id => peek.open(id)}
        onExpand={id => id.startsWith("module:") ? set("module", id) : nav(entityHref(scanId, id))} />}</QueryState>
      <p className="mt-2 text-xs text-slate-500">Modules are boxes sized by file count; arrows are module dependencies (thickness = imports); routes, services and tables are side nodes. Double-click a module to see its files and functions.</p>
    </div>
  );
}
