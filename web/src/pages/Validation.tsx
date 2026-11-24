import { Report } from "../api/types"
import { Card, EmptyState } from "../components/ui/ui"
import { validationModel } from "../model/validation"
import { RunGate } from "./common"

function Body({ report }: { report: Report }) {
  const v = validationModel(report)
  const hasFormal = report.validation !== null && report.validation !== undefined
  const tile = (n: number, l: string) => <div key={l} className="rounded-md border border-border bg-surface p-4"><span className="text-kpi font-semibold">{n}</span><span className="block text-body text-textMuted">{l}</span></div>
  return (
    <div className="space-y-4">
      {!hasFormal && <p className="text-body text-textMuted">No separate validation report was generated for this run. The checks below come from the scan itself.</p>}
      <Card title="Claim verification" subtitle="Every statement in an explanation is checked against evidence before it is shown as a fact.">
        <div data-testid="claim-summary" className="grid grid-cols-4 gap-4">
          {[tile(v.claims.total, "Claims"), tile(v.claims.verified, "Verified"), tile(v.claims.downgraded, "Downgraded"), tile(v.claims.other, "Other")]}
        </div>
        <p className="mt-3 text-label text-textMuted">Facts {v.claims.byType.fact} · Inferences {v.claims.byType.inference} · Unknowns {v.claims.byType.unknown}. A downgraded claim could not be fully supported and is shown with lower confidence.</p>
      </Card>
      <Card title="SBOM cross-check" subtitle="Comparing Guardian's own SBOM with an independent scanner.">
        <p className="text-body"><span className="font-semibold">{v.sbom.crossCheck}</span> · Confidence {v.sbom.confidence}</p>
        <ul className="mt-2 list-disc pl-5 text-body">{v.sbom.tools.map((t) => <li key={t.name}>{t.name}: {t.detail}</li>)}</ul>
        {v.sbom.tools.length === 0 && <p className="text-body text-textMuted">No scanner results were recorded.</p>}
      </Card>
      <Card title="Artifact integrity" subtitle="SHA-256 of each file this scan produced.">
        {v.integrity.length === 0 ? <EmptyState title="No integrity hashes were recorded" /> : (
          <table className="w-full text-left text-body"><tbody>
            {v.integrity.map((i) => <tr key={i.name} className="border-t border-border"><td className="py-2 pr-4 font-medium">{i.name}</td><td className="break-all font-mono text-label">{i.sha256}</td></tr>)}
          </tbody></table>
        )}
      </Card>
      <Card title="What Guardian cannot verify">
        {v.limits.length === 0 ? <p className="text-body text-textMuted">No limits were recorded.</p> : <ul className="list-disc space-y-1 pl-5 text-body">{v.limits.map((l) => <li key={l}>{l}</li>)}</ul>}
        {v.thresholds && <p className="mt-3 text-label text-textMuted">{v.thresholds}</p>}
      </Card>
      {hasFormal && <Card title="Validation report"><pre className="overflow-auto whitespace-pre-wrap text-label">{JSON.stringify(report.validation, null, 2)}</pre></Card>}
    </div>
  )
}

export default function Validation() {
  return <RunGate title="Validation" subtitle="How much of this report was checked, and what could not be.">{({ report }) => <Body report={report} />}</RunGate>
}
