import { ApiError, RunEvent } from "./types"

const BASE: string = (import.meta as any).env?.VITE_API_BASE ?? ""

export function subscribeEvents(
  runId: string,
  onEvent: (e: RunEvent) => void,
  onEnd: (final: { status: string }) => void,
  onError: (e: ApiError) => void,
): () => void {
  const path = `/runs/${runId}/events`
  const es = new EventSource(BASE + path)
  let closed = false
  const close = () => { closed = true; es.close() }
  es.onmessage = (m) => {
    if (closed) return
    let e: RunEvent
    try { e = JSON.parse(m.data) } catch { return }
    if (e.node === "run") { close(); onEnd({ status: e.status }) } else onEvent(e)
  }
  es.onerror = () => { if (!closed) { close(); onError(new ApiError(path, null, "event stream failed")) } }
  return close
}
