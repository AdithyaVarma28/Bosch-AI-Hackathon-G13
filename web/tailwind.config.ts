import type { Config } from "tailwindcss"
import { tokens } from "./src/theme/tokens"

const sev = Object.fromEntries(
  Object.entries(tokens.severity).flatMap(([k, v]) => [[`sev-${k.toLowerCase()}-bg`, v.bg], [`sev-${k.toLowerCase()}-fg`, v.fg]]),
)
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: { ...tokens.colors, ...sev },
      fontFamily: { sans: [tokens.font.family] },
      fontSize: { micro: "9px", label: "10px", body: "11px", nav: "11.5px", title: "14px", page: "18px", kpi: "26px" },
    },
  },
  plugins: [],
} satisfies Config
