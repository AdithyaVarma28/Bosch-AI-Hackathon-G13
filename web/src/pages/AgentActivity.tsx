import { Report } from "../api/types"
import { Card, EmptyState } from "../components/ui/ui"
import { tokens } from "../theme/tokens"
import { agentModel } from "../model/agents"
import { RunGate } from "./common"

function Body({ report }: { report: Report }) {
  const m = agentModel(report)
  return (
    <div className="space-y-4">
      <Card title="Pipeline stages" subtitle="What Guardian did, in order, for this scan. Per-stage timings are only available while a scan is running.">
        {m.stages.length === 0 ? <EmptyState title="No stage information was recorded" /> : (
          <ol className="divide-y divide-border text-body">
            {m.stages.map((s) => (
              <li key={s.node} className="flex items-start gap-3 py-3">
                <div className="flex-1">
                  <p className="font-medium">{s.label}</p>
                  <p className="font-mono text-label text-textMuted">{s.node}</p>
                  {s.reason && <p className="text-label" style={{ color: "#b54708" }}>{s.reason}</p>}
                </div>
                <span className="whitespace-nowrap rounded px-2 py-1 text-label font-medium"
                  style={{ color: s.status === "Failed" ? tokens.severity.Critical.fg : s.status === "Completed" ? tokens.colors.textSecondary : tokens.severity.High.fg,
                    backgroundColor: s.status === "Failed" ? tokens.severity.Critical.bg : s.status === "Completed" ? tokens.colors.subtle : tokens.severity.High.bg }}>{s.status}</span>
              </li>
            ))}
          </ol>
        )}
      </Card>
      <div className="grid grid-cols-2 gap-4">
        <Card title="Language models">
          <p className="text-body">{m.llm.text}</p>
          <p className="mt-1 text-label text-textMuted">{m.llm.configured ? "LLM agents were used for explanations." : "Explanations were produced by deterministic rules."}</p>
        </Card>
        <Card title="Pipeline errors">
          {m.errors.length === 0 ? <p className="text-body">No pipeline errors</p> : <ul className="list-disc pl-5 text-body">{m.errors.map((e) => <li key={e}>{e}</li>)}</ul>}
        </Card>
        <Card title="Code analysis coverage">
          <dl className="grid grid-cols-[160px_1fr] gap-y-1 text-body">
            <dt className="text-textMuted">Files parsed</dt><dd>{m.code.filesParsed} of {m.code.filesTotal}</dd>
            <dt className="text-textMuted">Files that failed</dt><dd>{m.code.filesFailed}</dd>
            <dt className="text-textMuted">Dynamic imports</dt><dd>{m.code.dynamicImports}</dd>
            <dt className="text-textMuted">Languages</dt><dd>{m.code.languages}</dd>
          </dl>
        </Card>
        <Card title="Application summary">
          {!m.dossier ? <p className="text-body text-textMuted">No application summary was produced.</p> : (
            <div className="space-y-2 text-body">
              <p>{m.dossier.summary}</p>
              <p className="text-label text-textMuted">Type: {m.dossier.appType} · Exposure: {m.dossier.exposure}</p>
              <ul className="space-y-1 text-label">
                {m.dossier.claims.slice(0, 8).map((c, i) => <li key={i}><span className="mr-2 rounded bg-subtle px-1.5 py-0.5 text-micro uppercase text-textMuted">{c.type}</span>{c.text}</li>)}
              </ul>
            </div>
          )}
        </Card>
      </div>
    </div>
  )
}

export default function AgentActivity() {
  return <RunGate title="Agent Activity" subtitle="Which analysis stages ran, and how they ended.">{({ report }) => <Body report={report} />}</RunGate>
}
