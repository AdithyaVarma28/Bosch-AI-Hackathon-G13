import { tokens } from "./tokens"
import config from "../../tailwind.config"

function flat(o: unknown): string[] {
  if (typeof o === "string") return [o]
  if (o && typeof o === "object") return Object.values(o).flatMap(flat)
  return []
}

test("every colour token is a valid hex or rgb value", () => {
  for (const v of flat({ c: tokens.colors, s: tokens.severity, st: tokens.status }))
    expect(v).toMatch(/^(#[0-9a-f]{6}([0-9a-f]{2})?|rgba?\(.+\))$/i)
})
test("severity has foreground and background for all five levels", () => {
  expect(Object.keys(tokens.severity)).toEqual(["Critical", "High", "Medium", "Low", "Unknown"])
  expect(tokens.severity.Critical.fg).not.toBe(tokens.severity.Low.fg)
})
test("layout constants match the Figma frame", () => {
  expect(tokens.layout).toEqual({ sidebar: 224, topbar: 56, gutter: 32, frame: 1440 })
})
test("tailwind theme exposes the severity colours", () => {
  const colors = (config.theme as any).extend.colors
  expect(colors["sev-critical-fg"]).toBe(tokens.severity.Critical.fg)
})
