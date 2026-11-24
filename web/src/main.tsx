import { StrictMode, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Link, NavLink, Outlet, Route, Routes, useParams } from "react-router-dom";
import { Activity, ClipboardCheck, FileText, GitCompare, LayoutDashboard, Map, Moon, Package, Radar, Route as RouteIcon, ShieldAlert, Sun, Workflow } from "lucide-react";
import "./index.css";
import { useScan, useScans } from "./api";
import CommandPalette from "./components/CommandPalette";
import { PeekProvider, cx } from "./components/ui";
import Start from "./pages/Start";
import Progress from "./pages/Progress";
import Overview from "./pages/Overview";
import MapPage from "./pages/MapPage";
import Changes from "./pages/Changes";
import Findings from "./pages/Findings";
import Finding from "./pages/Finding";
import Review from "./pages/Review";
import Packages from "./pages/Packages";
import Flows from "./pages/Flows";
import FileView from "./pages/FileView";
import EntityPage from "./pages/EntityPage";
import SupplyChain from "./pages/SupplyChain";
import Report from "./pages/Report";
import Coverage from "./pages/Coverage";

const qc = new QueryClient({ defaultOptions: { queries: { staleTime: 10_000, retry: 1 } } });

function Layout() {
  const { scanId = "" } = useParams();
  const scan = useScan(scanId);
  const scans = useScans();
  const [dark, setDark] = useState(() => localStorage.getItem("theme") === "dark");
  useEffect(() => { document.documentElement.classList.toggle("dark", dark); localStorage.setItem("theme", dark ? "dark" : "light"); }, [dark]);
  const f = scan.data?.findings;
  const open = f ? f.critical + f.high + f.medium + f.low : undefined;
  const nav = [
    { to: "", label: "Overview", icon: LayoutDashboard, end: true },
    { to: "map", label: "Map", icon: Map },
    { to: "flows", label: "Flows", icon: RouteIcon },
    { to: "packages", label: "Packages", icon: Package },
    { to: "supply-chain", label: "Supply chain", icon: Workflow },
    { to: "changes", label: "Changes", icon: GitCompare },
    { to: "findings", label: "Findings", icon: ShieldAlert, badge: open },
    { to: "review", label: "Review", icon: ClipboardCheck, badge: scan.data?.pending_reviews || undefined },
    { to: "report", label: "Report", icon: FileText },
    { to: "coverage", label: "Coverage", icon: Radar },
    { to: "progress", label: "Scan progress", icon: Activity },
  ];
  const others = (scans.data ?? []).filter(s => s.repo === scan.data?.repo && s.scan_id !== scanId);
  return (
    <div className="flex min-h-screen">
      <aside className="sticky top-0 flex h-screen w-56 shrink-0 flex-col border-r border-slate-200 bg-white px-3 py-4 dark:border-slate-800 dark:bg-slate-900">
        <Link to="/" className="mb-6 flex items-center gap-2 px-2 text-lg font-bold"><span className="grid h-7 w-7 place-items-center rounded bg-indigo-600 text-white">◆</span>Guardian</Link>
        <nav className="space-y-0.5" aria-label="Sections">
          {nav.map(n => (
            <NavLink key={n.to} to={`/scans/${scanId}/${n.to}`} end={n.end}
              className={({ isActive }) => cx("flex items-center gap-2 rounded-md px-2 py-1.5 text-sm", isActive ? "bg-indigo-50 font-medium text-indigo-700 dark:bg-slate-800 dark:text-indigo-300" : "text-slate-600 hover:bg-slate-100 dark:text-slate-300 dark:hover:bg-slate-800")}>
              <n.icon className="h-4 w-4" />{n.label}{n.badge ? <span className="ml-auto rounded-full bg-slate-200 px-1.5 text-[11px] dark:bg-slate-700">{n.badge}</span> : null}
            </NavLink>
          ))}
        </nav>
        <div className="mt-auto px-2 text-[11px] text-slate-400">AI text is badged; facts are marked. Nothing in the repo is executed.</div>
      </aside>
      <div className="min-w-0 flex-1">
        <header className="sticky top-0 z-30 flex items-center gap-3 border-b border-slate-200 bg-white/90 px-6 py-2 backdrop-blur dark:border-slate-800 dark:bg-slate-950/90">
          <span className="text-sm text-slate-500">repo</span><b className="text-sm">{scan.data?.repo ?? "…"}</b>
          <span className="text-sm text-slate-500">commit</span>
          <select aria-label="Snapshot" value={scanId} onChange={e => { window.location.href = `/scans/${e.target.value}`; }} className="rounded border border-slate-200 bg-transparent px-1 py-0.5 text-sm dark:border-slate-700">
            <option value={scanId}>{(scan.data?.commit ?? "").slice(0, 7)} {scan.data?.label ?? ""}</option>
            {others.map(s => <option key={s.scan_id} value={s.scan_id}>{(s.commit ?? "").slice(0, 7)} {s.label ?? s.scan_id}</option>)}
          </select>
          <div className="ml-auto flex items-center gap-2"><CommandPalette />
            <button aria-label="Toggle dark mode" onClick={() => setDark(d => !d)} className="rounded p-1.5 hover:bg-slate-100 dark:hover:bg-slate-800">{dark ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}</button></div>
        </header>
        {scan.data?.label && scan.data.label !== "HEAD" && <div className="bg-amber-50 px-6 py-1.5 text-sm text-amber-900 dark:bg-amber-950 dark:text-amber-200">Viewing snapshot {scan.data.commit?.slice(0, 7)} ({scan.data.label}). {others[0] && <Link className="underline" to={`/scans/${others[0].scan_id}`}>Return to the latest snapshot.</Link>}</div>}
        <main className="mx-auto max-w-7xl px-6 py-6"><PeekProvider><Outlet /></PeekProvider></main>
      </div>
    </div>
  );
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={qc}>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Start />} />
          <Route path="/scans/:scanId" element={<Layout />}>
            <Route index element={<Overview />} />
            <Route path="progress" element={<Progress />} />
            <Route path="map" element={<MapPage />} />
            <Route path="changes" element={<Changes />} />
            <Route path="findings" element={<Findings />} />
            <Route path="findings/:findingId" element={<Finding />} />
            <Route path="review" element={<Review />} />
            <Route path="packages" element={<Packages />} />
            <Route path="flows" element={<Flows />} />
            <Route path="supply-chain" element={<SupplyChain />} />
            <Route path="report" element={<Report />} />
            <Route path="coverage" element={<Coverage />} />
            <Route path="files/*" element={<FileView />} />
            <Route path=":kind/:entityId" element={<EntityPage />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  </StrictMode>,
);
