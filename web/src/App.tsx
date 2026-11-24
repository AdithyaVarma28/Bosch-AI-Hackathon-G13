import { Route, Routes } from "react-router-dom"
import { PageHeader, Shell } from "./components/layout/Shell"
import { Card } from "./components/ui/ui"
import { ErrorBoundary } from "./components/ErrorBoundary"
import Overview from "./pages/Overview"
import DependencyIntelligence from "./pages/DependencyIntelligence"
import Vulnerabilities from "./pages/Vulnerabilities"
import AnomalyDetection from "./pages/AnomalyDetection"
import RepositoryScanning from "./pages/RepositoryScanning"
import Repositories from "./pages/Repositories"
import SbomExplorer from "./pages/SbomExplorer"
import EvidenceCenter from "./pages/EvidenceCenter"
import AgentActivity from "./pages/AgentActivity"
import RiskPrioritization from "./pages/RiskPrioritization"
import Remediation from "./pages/Remediation"
import Validation from "./pages/Validation"
import Settings from "./pages/Settings"

function NotFound() {
  return <><PageHeader title="Page not found" showNewScan={false} /><Card><p className="text-body text-textMuted">This page does not exist.</p></Card></>
}

export default function App() {
  return (
    <Shell>
      <ErrorBoundary><Routes>
        <Route path="/" element={<Overview />} />
        <Route path="/dependencies" element={<DependencyIntelligence />} />
        <Route path="/vulnerabilities" element={<Vulnerabilities />} />
        <Route path="/anomalies" element={<AnomalyDetection />} />
        <Route path="/scan" element={<RepositoryScanning />} />
        <Route path="/repositories" element={<Repositories />} />
        <Route path="/sbom" element={<SbomExplorer />} />
        <Route path="/evidence" element={<EvidenceCenter />} />
        <Route path="/agents" element={<AgentActivity />} />
        <Route path="/risk" element={<RiskPrioritization />} />
        <Route path="/remediation" element={<Remediation />} />
        <Route path="/validation" element={<Validation />} />
        <Route path="/settings" element={<Settings />} />
        <Route path="*" element={<NotFound />} />
      </Routes></ErrorBoundary>
    </Shell>
  )
}
