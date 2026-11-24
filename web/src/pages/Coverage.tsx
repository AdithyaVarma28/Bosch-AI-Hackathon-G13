import { useParams } from "react-router-dom";
import { useCoverage } from "../api";
import { PageHeader, Panel, QueryState } from "../components/ui";

export default function Coverage() {
  const { scanId = "" } = useParams();
  const q = useCoverage(scanId);
  return (
    <div>
      <PageHeader crumbs={[{ label: "Overview", to: `/scans/${scanId}` }, { label: "Coverage" }]} title="What we did and didn't understand" />
      <QueryState q={q}>{() => {
        const s3 = q.data.stage3 ?? {}, s4 = q.data.stage4 ?? {}, s5 = q.data.stage5 ?? {};
        const c = s3.counts ?? {};
        return (
          <div className="grid gap-4 lg:grid-cols-2">
            <Panel title="Code understanding (Stages 2–3)"><ul className="space-y-1 text-sm">
              <li>Files parsed: {c.parsed}/{c.files}</li><li>Internal calls resolved: {c.calls_resolved}/{c.calls_total}</li>
              <li>Files carded: {c.files_carded}/{c.file_nodes}</li><li>Questions: {s3.questions?.resolved} resolved, {s3.questions?.unresolved} unresolved</li></ul>
              <h3 className="mt-3 text-xs font-semibold uppercase text-slate-500">Known unknowns</h3>
              <ul className="list-disc pl-5 text-sm">{(s3.known_unknowns ?? []).map((k: any, i: number) => <li key={i}>{typeof k === "string" ? k : JSON.stringify(k)}</li>)}</ul></Panel>
            <Panel title="Vulnerabilities (Stage 4)"><ul className="space-y-1 text-sm">
              <li>Packages checked: {s4.discovery?.packages} ({s4.discovery?.osv_mode}); unversioned: {(s4.discovery?.unversioned ?? []).join(", ") || "none"}</li>
              <li>Grype: {Object.entries(s4.discovery?.grype ?? {}).map(([k, v]) => `${k}: ${v}`).join("; ")}</li>
              <li>KEV: {s4.discovery?.kev?.loaded ? `${s4.discovery.kev.entries} entries` : "not loaded"} · EPSS scored {s4.discovery?.epss?.scored}/{s4.discovery?.epss?.cves}</li>
              <li>Deep investigations {s4.deep_investigations}, light pass {s4.light_pass} · workflow {s4.workflow} · review engine {s4.review_engine}</li>
              <li>LLM: {s4.llm?.provider} {s4.llm?.disabled_reason ? `(${s4.llm.disabled_reason})` : ""}</li>
              {(s4.discovery?.notes ?? []).map((n: string, i: number) => <li key={i} className="text-amber-700">{n}</li>)}</ul></Panel>
            <Panel title="Anomalies (Stage 5)"><ul className="space-y-1 text-sm"><li>PyPI metadata source: {s5.pypi_source}</li>
              {Object.entries(s5).filter(([k]) => k !== "pypi_source").map(([k, v]) => <li key={k}><b>{k}</b>: {(v as string[]).join("; ")}</li>)}</ul></Panel>
          </div>);
      }}</QueryState>
    </div>
  );
}
