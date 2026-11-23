// Simple 16px line icons (24-unit grid, 1.6 stroke), drawn for this project. They inherit the text colour.
const PATHS: Record<string, string> = {
  overview: "M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4zM14 14h6v6h-6z",
  repositories: "M6 3h12v18H6zM6 17h12M10 7h4M10 11h4",
  dependencies: "M12 5v5M12 10H6v4M12 10h6v4M4 14h4v5H4zM16 14h4v5h-4zM9.5 3h5v4h-5z",
  vulnerabilities: "M12 3 4 6v5c0 5 3.4 8.6 8 10 4.6-1.4 8-5 8-10V6zM12 8v5M12 16v.5",
  anomalies: "M3 12h4l3-7 4 14 3-7h4",
  sbom: "M12 3 4 7v10l8 4 8-4V7zM4 7l8 4 8-4M12 11v10",
  evidence: "M6 3h9l4 4v14H6zM14 3v5h5M9 13h7M9 17h7",
  agents: "M9 3h6v4H9zM5 11h14v8H5zM9 15h.01M15 15h.01M12 7v4",
  risk: "M3 20h18M6 20v-6M11 20V9M16 20v-9M21 20V5",
  remediation: "M14 6l4 4-9 9H5v-4zM12 8l4 4",
  validation: "M12 3 4 6v5c0 5 3.4 8.6 8 10 4.6-1.4 8-5 8-10V6zM8.5 12l2.5 2.5L16 9.5",
  settings: "M4 7h10M18 7h2M4 17h2M10 17h10M14 4v6M6 14v6",
  brand: "M12 2.5 4 5.5v6c0 5 3.4 9 8 10.5 4.6-1.5 8-5.5 8-10.5v-6zM9 12l2.2 2.2L15.5 10",
}

export const ICON_FOR: Record<string, string> = {
  Overview: "overview", Repositories: "repositories", "Dependency Intelligence": "dependencies", Vulnerabilities: "vulnerabilities",
  "Anomaly Detection": "anomalies", "SBOM Explorer": "sbom", "Evidence Center": "evidence", "Agent Activity": "agents",
  "Risk Prioritization": "risk", Remediation: "remediation", Validation: "validation", Settings: "settings",
}

export function Icon({ name, size = 16 }: { name: string; size?: number }) {
  return (
    <svg data-icon={name} width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d={PATHS[name] ?? PATHS.overview} />
    </svg>
  )
}
