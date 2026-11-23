// Values read from the Figma file (frames 2:196 and siblings) via get_design_context.
// Font is Inter (Regular/Medium/Semi Bold/Bold). Small type: 9-11.5px labels, 14px card titles, 18px page titles.
export const tokens = {
  colors: {
    page: "#f7f8fa",
    surface: "#ffffff",
    subtle: "#f2f4f7",
    border: "#e5e7eb",
    textPrimary: "#182230",
    textSecondary: "#475467",
    textMuted: "#667085",
    textFaint: "#98a2b3",
    accent: "#b42318",
    accentSoft: "#fdeeee",
    accentSolid: "#e60000",
    link: "#2563a6",
    warnSoft: "#fffaeb",
  },
  severity: {
    Critical: { bg: "#fef3f2", fg: "#b42318" },
    High: { bg: "#fffaeb", fg: "#b54708" },
    Medium: { bg: "#fffaeb", fg: "#854a0e" },
    Low: { bg: "#f2f4f7", fg: "#475467" },
    Unknown: { bg: "#f2f4f7", fg: "#667085" },
  },
  status: {
    Open: { bg: "#f2f4f7", fg: "#475467" },
    "In review": { bg: "#fffaeb", fg: "#b54708" },
    New: { bg: "#fdeeee", fg: "#b42318" },
    Accepted: { bg: "#f2f4f7", fg: "#475467" },
    Completed: { bg: "#f2f4f7", fg: "#475467" },
    Complete: { bg: "#f2f4f7", fg: "#475467" },
  },
  layout: { sidebar: 224, topbar: 56, gutter: 32, frame: 1440 },
  font: {
    family: "Inter, ui-sans-serif, system-ui, sans-serif",
    sizes: { micro: "9px", label: "10px", body: "11px", nav: "11.5px", title: "14px", page: "18px", kpi: "26px" },
  },
} as const

export type SeverityName = keyof typeof tokens.severity
