import { useCallback, useEffect, useRef, useState } from "react"
import { useSearchParams } from "react-router-dom"
import { getReport, getRun, getViz, listRuns, startScan } from "../api/client"
import { subscribeEvents } from "../api/events"
import { ApiError, Report, RunEvent, RunSummary, VizGraph } from "../api/types"

export type Async<T> = { state: "loading" } | { state: "error"; error: ApiError } | { state: "ready"; data: T }

const toApiError = (e: unknown, path: string) => (e instanceof ApiError ? e : new ApiError(path, null, e instanceof Error ? e.message : String(e)))

function useAsync<T>(load: (() => Promise<T>) | null, key: string): Async<T> {
  const [st, setSt] = useState<{ key: string; value: Async<T> }>({ key, value: { state: "loading" } })
  useEffect(() => {
    if (!load) return
    let live = true
    setSt({ key, value: { state: "loading" } })
    load().then(
      (data) => live && setSt({ key, value: { state: "ready", data } }),
      (e) => live && setSt({ key, value: { state: "error", error: toApiError(e, key) } }),
    )
    return () => { live = false }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key])
  // Data that belongs to a previous key is never returned, not even for one render.
  return st.key === key ? st.value : { state: "loading" }
}

export const useRuns = (): Async<RunSummary[]> => useAsync(listRuns, "/runs")

export function useCurrentRun() {
  const [params, setParams] = useSearchParams()
  const runs = useRuns()
  const explicit = params.get("run")
  let runId: string | null = explicit
  if (!runId && runs.state === "ready") runId = runs.data.find((r) => r.status === "done")?.run_id ?? null
  const setRunId = useCallback((id: string) => setParams((p) => { const n = new URLSearchParams(p); n.set("run", id); return n }), [setParams])
  return { runId, setRunId, runs }
}

export function useRunData(runId: string | null) {
  const report = useAsync<Report>(runId ? () => getReport(runId) : null, `report:${runId}`)
  const viz = useAsync<VizGraph>(runId ? () => getViz(runId) : null, `viz:${runId}`)
  const notAvailable = report.state === "error" && report.error.status === 404
  return { report, viz, notAvailable }
}

export function useScan() {
  const [runId, setRunId] = useState<string | null>(null)
  const [events, setEvents] = useState<RunEvent[]>([])
  const [status, setStatus] = useState<"idle" | "running" | "done" | "failed">("idle")
  const [error, setError] = useState<ApiError | null>(null)
  const [report, setReport] = useState<Async<Report> | null>(null)
  const [runError, setRunError] = useState<string | null>(null)
  const off = useRef<(() => void) | null>(null)
  useEffect(() => () => off.current?.(), [])

  const start = useCallback(async (repoUrl: string) => {
    off.current?.()
    setError(null); setRunError(null); setEvents([]); setReport(null); setStatus("running")
    try {
      const { run_id } = await startScan(repoUrl)
      setRunId(run_id)
      const seen = new Set<string>()
      off.current = subscribeEvents(
        run_id,
        (e) => {
          const k = JSON.stringify(e)
          if (seen.has(k)) return // the stream replays from the start; never double count
          seen.add(k)
          setEvents((p) => [...p, e])
        },
        (fin) => {
          const ok = fin.status === "done"
          setStatus(ok ? "done" : "failed")
          if (!ok) getRun(run_id).then((r) => setRunError(r.error ?? "The scan failed."), () => setRunError("The scan failed."))
          if (ok) {
            setReport({ state: "loading" })
            getReport(run_id).then((data) => setReport({ state: "ready", data }), (e) => setReport({ state: "error", error: toApiError(e, `/runs/${run_id}/report`) }))
          }
        },
        (e) => { setError(e); setStatus("failed") },
      )
    } catch (e) {
      setError(toApiError(e, "/runs")); setStatus("failed")
    }
  }, [])

  return { start, runId, events, status, error, runError, report }
}
