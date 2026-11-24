// Finding evidence page: the five sections of slide step 5, the investigation timeline and review actions.
import { useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { Bug, ChevronDown, Radar } from "lucide-react";
import { Card, useFinding, useReview } from "../api";
import {
  AIBadge, ActivityTimeline, CodeSnippet, ConfidenceChip, EntityLink, EvidenceItem, EvidenceList, FactBadge, PageHeader,
  Panel, QueryState, ReviewBadge, RiskChip, SeverityChip, Spinner, cx,
} from "../components/ui";

const DISMISS = [["false_positive", "False positive"], ["not_used", "Not used"], ["accepted_risk", "Accepted risk"], ["mitigated_elsewhere", "Mitigated elsewhere"]];

function ReviewActions({ card }: { card: Card }) {
  const { scanId = "" } = useParams();
  const m = useReview(scanId);
  const [mode, setMode] = useState<null | "dismiss" | "override">(null);
  const [reason, setReason] = useState("");
  const [risk, setRisk] = useState("high");
  const [note, setNote] = useState("");
  const [by, setBy] = useState(() => localStorage.getItem("reviewer") ?? "");
  const submit = (action: string) => {
    localStorage.setItem("reviewer", by);
    m.mutate({ fid: card.finding_id, action, reason: reason || undefined, new_risk: action === "override" ? risk : undefined, note: note || undefined, by: by || undefined },
      { onSuccess: () => setMode(null) });
  };
  return (
    <div className="flex flex-wrap items-center gap-2">
      <ReviewBadge status={card.review?.status} />
      <button disabled={m.isPending} onClick={() => submit("confirm")} className="rounded bg-emerald-600 px-2.5 py-1 text-sm text-white">Confirm</button>
      <button onClick={() => { setMode("dismiss"); setReason(""); }} className="rounded border border-slate-300 px-2.5 py-1 text-sm dark:border-slate-600">Dismiss…</button>
      <button onClick={() => { setMode("override"); setReason(""); }} className="rounded border border-slate-300 px-2.5 py-1 text-sm dark:border-slate-600">Override…</button>
      {m.isPending && <Spinner />}
      {m.error && <span className="text-sm text-red-600">{String((m.error as Error).message)}</span>}
      {mode && (
        <div className="fixed inset-0 z-50 grid place-items-center bg-black/30" onClick={() => setMode(null)}>
          <form onClick={e => e.stopPropagation()} onSubmit={e => { e.preventDefault(); submit(mode); }} className="w-full max-w-md space-y-3 rounded-xl bg-white p-5 shadow-xl dark:bg-slate-900" role="dialog" aria-label={mode}>
            <h3 className="text-lg font-semibold capitalize">{mode} {card.finding_id}</h3>
            {mode === "dismiss" ? (
              <fieldset className="space-y-1"><legend className="text-sm font-medium">Reason (required)</legend>
                {DISMISS.map(([v, l]) => <label key={v} className="flex items-center gap-2 text-sm"><input type="radio" name="reason" required checked={reason === v} onChange={() => setReason(v)} />{l}</label>)}</fieldset>
            ) : (
              <>
                <label className="block text-sm">New project risk <select value={risk} onChange={e => setRisk(e.target.value)} className="ml-2 rounded border px-1">{["critical", "high", "medium", "low"].map(r => <option key={r}>{r}</option>)}</select></label>
                <label className="block text-sm">Reason (required)<input required value={reason} onChange={e => setReason(e.target.value)} className="mt-1 w-full rounded border px-2 py-1 dark:bg-slate-800" /></label>
              </>
            )}
            <label className="block text-sm">Note<textarea value={note} onChange={e => setNote(e.target.value)} className="mt-1 w-full rounded border px-2 py-1 dark:bg-slate-800" /></label>
            <label className="block text-sm">Reviewer<input value={by} onChange={e => setBy(e.target.value)} className="mt-1 w-full rounded border px-2 py-1 dark:bg-slate-800" /></label>
            <div className="flex justify-end gap-2"><button type="button" onClick={() => setMode(null)} className="rounded border px-3 py-1 text-sm">Cancel</button><button className="rounded bg-indigo-600 px-3 py-1 text-sm text-white">Submit</button></div>
          </form>
        </div>)}
    </div>
  );
}

function Section({ n, title, children, fact }: { n: number; title: string; children: React.ReactNode; fact?: boolean }) {
  return <section className="border-t border-slate-100 py-4 first:border-t-0 dark:border-slate-800">
    <h2 className="mb-2 flex items-center gap-2 text-sm font-semibold uppercase tracking-wide text-slate-500"><span className="grid h-5 w-5 place-items-center rounded-full bg-slate-900 text-[11px] text-white dark:bg-slate-700">{n}</span>{title}{fact && <FactBadge />}</h2>
    {children}</section>;
}

export default function Finding({ fid }: { fid?: string }) {
  const { scanId = "", findingId: routeId = "" } = useParams();
  const findingId = fid ?? routeId;
  const q = useFinding(scanId, findingId);
  const [sp, setSp] = useSearchParams();
  const tab = sp.get("tab") ?? "code";
  const [open, setOpen] = useState(true);
  return <QueryState q={q} rows={10}>{() => {
    const { card: c, trace, snippets } = q.data!;
    const vuln = c.type === "vulnerability";
    const tabs = vuln ? ["code", "flow", "advisory", "metadata"] : ["code", "signals", "metadata"];
    return (
      <div>
        <PageHeader crumbs={[{ label: "Overview", to: `/scans/${scanId}` }, { label: "Findings", to: `/scans/${scanId}/findings` }, { label: c.finding_id }]}
          icon={vuln ? <Bug className="h-6 w-6" /> : <Radar className="h-6 w-6" />} title={<span>{c.finding_id} <span className="font-normal">{vuln ? `${c.component_name} ${c.component_version ?? ""}: ${c.summary || c.vuln_id}` : c.title}</span></span>}>
        </PageHeader>
        <div className="mb-4 flex flex-wrap items-center gap-3 rounded-xl border border-slate-200 bg-white p-3 dark:border-slate-800 dark:bg-slate-900">
          <RiskChip risk={c.project_risk} prefix="Project" />
          {vuln ? <SeverityChip cvss={c.severity?.cvss} band={c.severity?.band} /> : <span className="rounded bg-slate-900 px-1.5 py-0.5 text-xs text-white capitalize">Suspicion {c.suspicion}</span>}
          {!vuln && <span className="rounded bg-slate-100 px-1.5 py-0.5 text-xs dark:bg-slate-800">Exposure: {c.exposure?.replaceAll("_", " ")}</span>}
          <ConfidenceChip c={c.confidence} />
          {c.kev && <span className="rounded bg-red-600 px-1.5 py-0.5 text-xs text-white">KEV: actively exploited</span>}
          {c.epss_percentile != null && <span className="text-xs text-slate-500">EPSS percentile {Math.round(c.epss_percentile * 100)}%</span>}
          <div className="ml-auto"><ReviewActions card={c} /></div>
        </div>
        {c.review?.reasons?.length ? <p className="mb-3 rounded bg-yellow-50 px-3 py-2 text-sm text-yellow-900 dark:bg-yellow-950 dark:text-yellow-200">Human review: {c.review.reasons.join("; ")}{c.review.reopened ? ` · ${c.review.reopened}` : ""}</p> : null}
        {c.review?.status && c.review.status !== "pending" && c.review.status !== "not_required" && <p className="mb-3 text-sm text-slate-600">Decision: <b>{c.review.status}</b>{c.review.by ? ` by ${c.review.by}` : ""}{c.review.reason ? ` · ${c.review.reason}` : ""}{c.review.note ? ` · “${c.review.note}”` : ""}{c.review.reused ? " (reused from an earlier scan: nothing changed)" : ""}</p>}

        <Panel>
          <Section n={1} title="What was detected">
            <div className="mb-1 flex items-center gap-2"><AIBadge by={c.explanation_by === "ai" ? "ai" : "rules"} confidence={c.confidence} /><a href="#evidence" className="text-xs text-indigo-700 underline">View evidence</a></div>
            <p className="text-sm leading-6">{c.explanation}</p>
            {!vuln && c.capability && <p className="mt-2 text-sm"><b>Capability:</b> {c.capability} · <b>Exposure:</b> {c.exposure_note}</p>}
            {!vuln && c.normal_explanation && <p className="mt-1 text-sm"><b>Normal explanation{c.normal_explanation_verified ? " (verified)" : " (not verified)"}:</b> {c.normal_explanation}</p>}
          </Section>
          <Section n={2} title="Which component" fact>
            <div className="flex flex-wrap items-center gap-3 text-sm"><EntityLink id={c.component} label={c.component_name ?? c.component} />
              {vuln && <span>{c.vuln_id} {c.aliases?.length ? <span className="text-slate-500">({c.aliases.join(", ")})</span> : null}</span>}
              {c.fix?.upgrade_to && <span className="rounded bg-emerald-50 px-1.5 text-emerald-800">fix: upgrade to {c.fix.upgrade_to}</span>}
              {vuln && <span className="text-slate-500">scope {c.scope} ({c.scope_reason})</span>}</div>
          </Section>
          <Section n={3} title="Dependency path" fact>
            {vuln ? <div className="flex flex-wrap items-center gap-1 text-sm">{(c.dependency_path ?? []).map((p: string, i: number) => <span key={i} className="flex items-center gap-1">{i > 0 && "→"}{p.startsWith("pkg:") ? <EntityLink id={p} /> : <code className="rounded bg-slate-100 px-1 text-xs dark:bg-slate-800">{p}</code>}</span>)}</div>
              : <div className="text-sm">{c.signals.map((s: any) => s.evidence.filter((e: any) => e.file && !e.package_file).slice(0, 1).map((e: any, i: number) => <div key={s.signal_id + i}><EvidenceItem e={e} /></div>))}</div>}
          </Section>
          <Section n={4} title="Supporting evidence">
            <div id="evidence" className="mb-3 flex gap-1 border-b border-slate-200 dark:border-slate-700">{tabs.map(t => <button key={t} onClick={() => { const n = new URLSearchParams(sp); n.set("tab", t); setSp(n, { replace: true }); }} className={cx("px-3 py-1.5 text-sm capitalize", tab === t ? "border-b-2 border-indigo-600 font-medium" : "text-slate-500")}>{t}</button>)}</div>
            {tab === "code" && (Object.keys(snippets).length ? <div className="space-y-3">{Object.values(snippets).map(s => <CodeSnippet key={s.file + s.start} file={s.file} start={s.start} lines={s.lines} highlight={s.highlight}
              href={s.file.startsWith("pkg:") ? undefined : `/scans/${scanId}/files/${s.file}#L${s.highlight[0]}-L${s.highlight[1]}`} />)}</div> : <EvidenceList items={c.evidence.filter((e: any) => e.file)} />)}
            {tab === "flow" && (c.paths?.length ? <div className="space-y-2">{c.paths.map((p: string[], i: number) => (
              <div key={i} className="flex flex-wrap items-center gap-1 rounded bg-slate-50 p-2 text-sm dark:bg-slate-800">{p.map((n, k) => <span key={k} className="flex items-center gap-1">{k > 0 && "→"}<EntityLink id={n} /></span>)}</div>))}
              <p className="text-xs text-slate-500">Reachability: {c.reachability?.replaceAll("_", " ")} (function-level; an input on a path does not prove it reaches the vulnerable argument).</p></div>
              : <p className="text-sm text-slate-600">No path found from a route, CLI or startup code. This is not proof that the code cannot run: dynamic imports, reflection and runtime configuration are invisible to static analysis.</p>)}
            {tab === "advisory" && <div className="space-y-2 text-sm">
              <p className="whitespace-pre-line text-slate-700 dark:text-slate-300">{c.details?.slice(0, 1500)}</p>
              <p><b>Affected:</b> {(c.affected_ranges ?? []).map((r: any) => `${r.introduced ?? "0"} ≤ v < ${r.fixed ?? r.last_affected ?? "?"}`).join("; ")} · <b>Fixed in:</b> {(c.fixed_versions ?? []).join(", ") || "none published"}</p>
              <p><b>Vector:</b> <code className="text-xs">{c.severity?.vector ?? "n/a"}</code></p>
              <EvidenceList items={(c.references ?? []).slice(0, 6)} /></div>}
            {tab === "signals" && <ul className="space-y-2">{c.signals.map((s: any) => (
              <li key={s.signal_id} className="rounded border border-slate-200 p-2 text-sm dark:border-slate-700"><div className="flex items-center gap-2"><b>{s.signal_id}</b><span className="rounded bg-slate-100 px-1 text-xs dark:bg-slate-800">{s.detector} · {s.check}</span><span className={cx("text-xs font-semibold", s.strength === "strong" ? "text-red-700" : s.strength === "medium" ? "text-amber-700" : "text-slate-500")}>{s.strength}</span>{s.metadata_only && <span className="text-xs text-slate-500">metadata only</span>}</div>
                <p>{s.text}</p><div className="mt-1"><EvidenceList items={s.evidence} /></div></li>))}</ul>}
            {tab === "metadata" && <pre className="max-h-80 overflow-auto rounded bg-slate-50 p-2 text-xs dark:bg-slate-800">{JSON.stringify(vuln ? { cvss: c.severity, kev: c.kev, epss: c.epss, epss_percentile: c.epss_percentile, sources: c.discovered_by, fingerprint: c.fingerprint, usage_sites: c.usage_sites, conditions: c.conditions, unknowns: c.unknowns } : { suspicion_reason: c.suspicion_reason, exposure_note: c.exposure_note, unknowns: c.unknowns, priority_band: c.priority_band, investigation: c.investigation }, null, 2)}</pre>}
            <h3 className="mb-1 mt-4 text-xs font-semibold uppercase text-slate-500">Claims (each verified against re-read lines)</h3>
            <ul className="space-y-1">{c.claims.map((cl: any, i: number) => <li key={i} className="text-sm"><span className={cl.verified === false ? "text-red-600" : "text-emerald-700"}>{cl.verified === false ? "✗" : "✓"}</span> {cl.text} <span className="text-xs text-slate-500">[{cl.evidence.map((e: any) => e.file ? `${e.file}:${e.lines ?? e.line ?? ""}` : e.commit ? `commit ${String(e.commit).slice(0, 7)}` : e.node).join(", ")}]</span></li>)}</ul>
          </Section>
          <Section n={5} title="Initial risk level">
            <p className="text-sm">{vuln ? <>Project risk <b>{c.project_risk}</b> from rule #{c.rule?.id}: {c.rule?.text}. CVSS {c.severity?.cvss ?? c.severity?.band} is shown separately (severity in general, not in this repo).</>
              : <>Project risk <b>{c.project_risk}</b> = suspicion <b>{c.suspicion}</b> ({c.suspicion_reason}) × exposure <b>{c.exposure?.replaceAll("_", " ")}</b>.</>}
              {c.project_risk_by_rules && <> The rules said <b>{c.project_risk_by_rules}</b>; a reviewer overrode it.</>}</p>
            <p className="mt-1 text-sm">Confidence <b>{c.confidence}</b>: {(c.confidence_reasons ?? []).join("; ")}</p>
            {vuln && <p className="mt-1 text-sm text-slate-600">Usage: {c.usage?.replaceAll("_", " ")} · Reachability: {c.reachability?.replaceAll("_", " ")}</p>}
          </Section>
        </Panel>

        <div className="mt-4 grid gap-4 lg:grid-cols-2">
          <Panel title={<button onClick={() => setOpen(o => !o)} className="flex items-center gap-1">How the agent investigated ({trace.length} steps) <ChevronDown className={cx("h-4 w-4 transition", !open && "-rotate-90")} /></button>}>
            {open && <ActivityTimeline steps={trace} />}
          </Panel>
          <Panel title="Recommendation (Day 2 acts on this)"><p className="text-sm">{c.recommendation}</p>
            {c.unknowns?.length > 0 && <><h3 className="mt-3 text-xs font-semibold uppercase text-slate-500">Not verified</h3><ul className="list-disc pl-5 text-sm">{c.unknowns.map((u: string, i: number) => <li key={i}>{u}</li>)}</ul></>}
            <p className="mt-3 text-xs"><Link className="underline" to={`/scans/${scanId}/report`}>Export report</Link></p>
          </Panel>
        </div>
      </div>
    );
  }}</QueryState>;
}
