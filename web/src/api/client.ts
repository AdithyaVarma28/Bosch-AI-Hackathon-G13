import { ApiError, Evidence, Report, RunSummary, VizGraph } from "./types"

const BASE: string = (import.meta as any).env?.VITE_API_BASE ?? ""

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response
  try {
    res = await fetch(BASE + path, init)
  } catch (e) {
    throw new ApiError(path, null, e instanceof Error ? e.message : "network error")
  }
  if (!res.ok) throw new ApiError(path, res.status, `HTTP ${res.status}`)
  try {
    return (await res.json()) as T
  } catch {
    throw new ApiError(path, res.status, "invalid JSON in response")
  }
}

export const listRuns = () => request<RunSummary[]>("/runs")
export const getRun = (id: string) => request<RunSummary>(`/runs/${id}`)
export const getReport = (id: string) => request<Report>(`/runs/${id}/report`)
export const getViz = (id: string) => request<VizGraph>(`/runs/${id}/viz`)
export const getEvidence = (runId: string, evidenceId: string) => request<Evidence>(`/runs/${runId}/evidence/${evidenceId}`)
export const startScan = (repoUrl: string) =>
  request<{ run_id: string }>("/runs", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ repo_url: repoUrl }),
  })
