import { RunSummary } from "../api/types"
import { shortCommit } from "./format"

export interface RunRow {
  id: string; name: string; target: string; status: "Completed" | "Failed" | "Running"; commit: string; finishedAt: string | null
  error: string | null; canOpen: boolean
}
export interface RunFilter { search: string; status: "All" | RunRow["status"] }

export function runRows(runs: RunSummary[]): RunRow[] {
  return runs.map((r) => ({
    id: r.run_id, name: r.repo_name, target: r.target, commit: shortCommit(r.commit),
    status: r.status === "done" ? "Completed" : r.status === "failed" ? "Failed" : "Running",
    finishedAt: r.status === "running" ? null : r.finished_at, error: r.error, canOpen: r.status === "done",
  }))
}

export function filterRuns(rows: RunRow[], q: RunFilter): RunRow[] {
  const n = q.search.trim().toLowerCase()
  return rows.filter((r) => (q.status === "All" || r.status === q.status) && (!n || [r.name, r.target, r.id].some((x) => x.toLowerCase().includes(n))))
}
