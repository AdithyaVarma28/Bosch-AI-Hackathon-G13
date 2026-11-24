// API client + types for the Guardian backend (guardian/webapp/server.py). One hook per endpoint.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

export type Risk = "critical" | "high" | "medium" | "low";
export type Evidence = { type?: string; file?: string; lines?: string; line?: number; snippet?: string; url?: string; path?: string[]; labels?: string[]; commit?: string; pypi?: string; detail?: string; claim?: string; function?: string };
export type Step = { stage: string; action: string; tool?: string | null; input?: Record<string, unknown>; result: string; ok: boolean; at?: string };

export type ScanMeta = {
  scan_id: string; repo: string; commit?: string; created_at?: string; status: string; label?: string; demo?: boolean;
  findings: Record<Risk, number>; pending_reviews: number;
  stages?: Record<string, { name: string; status: string; summary?: string; duration_s?: number }>;
};

export type FindingRow = {
  finding_id: string; type: "vulnerability" | "anomaly"; title: string; component: string; component_name?: string;
  project_risk: Risk; severity?: { cvss: number | null; band: string; vector?: string } | null; suspicion?: string | null;
  confidence: "high" | "medium" | "low"; usage?: string | null; reachability?: string | null; exposure?: string | null;
  review_status?: string; scope?: string; vuln_id?: string | null; detectors?: string[] | null; commit?: string | null;
  reasons?: string[];
};

export type Card = Record<string, any> & FindingRow & {
  explanation: string; recommendation: string; evidence: Evidence[]; claims: { text: string; evidence: Evidence[]; verified?: boolean | null; graph_backed?: boolean }[];
  review: { status: string; reasons?: string[]; by?: string; reason?: string; note?: string; new_risk?: string; downgrade_guard?: boolean; reused?: boolean; reopened?: string };
};

export type GraphNode = { id: string; type: string; label: string; files?: number; risk?: Risk | null; changed?: boolean; parent?: string | null; purpose?: string; sensitivity?: string; tags?: string[] };
export type GraphData = { level: string; nodes: GraphNode[]; edges: { source: string; target: string; type: string; weight: number }[] };

async function get<T>(url: string): Promise<T> {
  const r = await fetch(url);
  if (!r.ok) throw new Error((await r.text()) || r.statusText);
  return r.json();
}
async function post<T>(url: string, body: unknown): Promise<T> {
  const r = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  if (!r.ok) {
    let msg = r.statusText;
    try { msg = (await r.json()).detail ?? msg; } catch { /* keep status */ }
    throw new Error(typeof msg === "string" ? msg : JSON.stringify(msg));
  }
  return r.json();
}
const enc = (s: string) => s.split("/").map(encodeURIComponent).join("/");

export const useScans = () => useQuery({ queryKey: ["scans"], queryFn: () => get<ScanMeta[]>("/api/scans"), refetchInterval: 5000 });
export const useScan = (id: string) => useQuery({ queryKey: ["scan", id], queryFn: () => get<ScanMeta>(`/api/scans/${id}`) });
export const useOverview = (id: string) => useQuery({ queryKey: ["overview", id], queryFn: () => get<any>(`/api/scans/${id}/overview`) });
export const useGraph = (id: string, level = "repo", node?: string) =>
  useQuery({ queryKey: ["graph", id, level, node], queryFn: () => get<GraphData>(`/api/scans/${id}/graph?level=${level}${node ? `&id=${encodeURIComponent(node)}` : ""}`) });
export const useEntity = (id: string, entity?: string) =>
  useQuery({ queryKey: ["entity", id, entity], enabled: !!entity, queryFn: () => get<any>(`/api/scans/${id}/entity/${enc(entity!)}`) });
export const useFindings = (id: string) => useQuery({ queryKey: ["findings", id], queryFn: () => get<FindingRow[]>(`/api/scans/${id}/findings`) });
export const useFinding = (id: string, fid: string) =>
  useQuery({ queryKey: ["finding", id, fid], queryFn: () => get<{ card: Card; row: FindingRow; trace: Step[]; snippets: Record<string, { file: string; start: number; highlight: [number, number]; lines: string[] }> }>(`/api/scans/${id}/findings/${fid}`) });
export const useReviewQueue = (id: string) => useQuery({ queryKey: ["review", id], queryFn: () => get<FindingRow[]>(`/api/scans/${id}/review`) });
export const useCompare = (from?: string, to?: string) =>
  useQuery({ queryKey: ["compare", from, to], enabled: !!from && !!to, queryFn: () => get<any>(`/api/compare?from=${from}&to=${to}`) });
export const useChanges = (id: string) => useQuery({ queryKey: ["changes", id], queryFn: () => get<any>(`/api/scans/${id}/changes`) });
export const useFlows = (id: string) => useQuery({ queryKey: ["flows", id], queryFn: () => get<any[]>(`/api/scans/${id}/flows`) });
export const usePackages = (id: string) => useQuery({ queryKey: ["packages", id], queryFn: () => get<any[]>(`/api/scans/${id}/packages`) });
export const useFile = (id: string, path: string) => useQuery({ queryKey: ["file", id, path], queryFn: () => get<any>(`/api/scans/${id}/files/${enc(path)}`) });
export const useCoverage = (id: string) => useQuery({ queryKey: ["coverage", id], queryFn: () => get<any>(`/api/scans/${id}/coverage`) });
export const useSearch = (id: string, q: string) =>
  useQuery({ queryKey: ["search", id, q], enabled: q.length > 0, queryFn: () => get<{ id: string; type: string; label: string }[]>(`/api/scans/${id}/search?q=${encodeURIComponent(q)}`) });

export function useStartScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: { path: string; offline: boolean; llm?: string }) => post<{ scan_id: string }>("/api/scans", body),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["scans"] }),
  });
}

export function useReview(id: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ fid, ...body }: { fid: string; action: string; reason?: string; new_risk?: string; note?: string; by?: string }) =>
      post<Card>(`/api/scans/${id}/review/${fid}`, body),
    onSuccess: () => qc.invalidateQueries(),
  });
}
