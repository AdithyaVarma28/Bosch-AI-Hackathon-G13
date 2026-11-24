// Ctrl/Cmd+K global search: packages, files, functions, routes, CVEs, commits, findings.
import { useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { Search } from "lucide-react";
import { useSearch } from "../api";
import { EntityIcon, entityHref } from "./ui";

export default function CommandPalette() {
  const { scanId = "" } = useParams();
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState("");
  const [sel, setSel] = useState(0);
  const nav = useNavigate();
  const res = useSearch(scanId, open ? q : "");
  useEffect(() => {
    const k = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") { e.preventDefault(); setOpen(o => !o); }
      if (e.key === "Escape") setOpen(false);
    };
    window.addEventListener("keydown", k);
    return () => window.removeEventListener("keydown", k);
  }, []);
  if (!scanId) return null;
  const hits = res.data ?? [];
  const go = (id: string) => { setOpen(false); setQ(""); nav(entityHref(scanId, id)); };
  return (
    <>
      <button onClick={() => setOpen(true)} className="flex items-center gap-2 rounded-md border border-slate-200 bg-white px-3 py-1.5 text-sm text-slate-500 dark:border-slate-700 dark:bg-slate-900">
        <Search className="h-4 w-4" />Search<kbd className="ml-4 rounded bg-slate-100 px-1 text-[10px] dark:bg-slate-800">Ctrl K</kbd>
      </button>
      {open && (
        <div className="fixed inset-0 z-50 flex items-start justify-center bg-black/30 pt-24" onClick={() => setOpen(false)}>
          <div className="w-full max-w-xl overflow-hidden rounded-xl bg-white shadow-2xl dark:bg-slate-900" onClick={e => e.stopPropagation()} role="dialog" aria-label="Search">
            <input autoFocus value={q} onChange={e => { setQ(e.target.value); setSel(0); }} placeholder="Package, file, function, route, CVE, commit, finding…"
              onKeyDown={e => {
                if (e.key === "ArrowDown") setSel(s => Math.min(s + 1, hits.length - 1));
                if (e.key === "ArrowUp") setSel(s => Math.max(s - 1, 0));
                if (e.key === "Enter" && hits[sel]) go(hits[sel].id);
              }}
              className="w-full border-b border-slate-200 bg-transparent px-4 py-3 outline-none dark:border-slate-700" />
            <ul className="max-h-80 overflow-y-auto py-1">
              {hits.map((h, i) => (
                <li key={h.id}><button onClick={() => go(h.id)} className={`flex w-full items-center gap-2 px-4 py-2 text-left text-sm ${i === sel ? "bg-indigo-50 dark:bg-slate-800" : ""}`}>
                  <EntityIcon id={h.id} /><span className="truncate">{h.label}</span><span className="ml-auto text-xs text-slate-400">{h.type}</span></button></li>
              ))}
              {q && !res.isLoading && hits.length === 0 && <li className="px-4 py-3 text-sm text-slate-500">No matches.</li>}
            </ul>
          </div>
        </div>
      )}
    </>
  );
}
