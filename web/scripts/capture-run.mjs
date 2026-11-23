// Usage: node scripts/capture-run.mjs <apiBase> <repoUrlOrPath> [name]
// Starts a scan, records every SSE message, saves report/viz/events/runs fixtures.
import { writeFileSync } from "node:fs"
const [base, target, name = "mini-shop"] = process.argv.slice(2)
const dir = new URL("../src/fixtures/", import.meta.url)
const j = async (p, init) => { const r = await fetch(base + p, init); if (!r.ok) throw new Error(`${p} ${r.status}`); return r.json() }
const { run_id } = await j("/runs", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ repo_url: target }) })
const events = []
const res = await fetch(`${base}/runs/${run_id}/events`)
const dec = new TextDecoder(); let buf = ""
for await (const chunk of res.body) {
  buf += dec.decode(chunk, { stream: true })
  let i
  while ((i = buf.indexOf("\n\n")) >= 0) {
    const line = buf.slice(0, i).replace(/^data: /, ""); buf = buf.slice(i + 2)
    if (line) events.push(JSON.parse(line))
  }
}
const save = (f, v) => writeFileSync(new URL(f, dir), JSON.stringify(v, null, 1))
save(`events.${name}.json`, events)
save(`report.${name}.json`, await j(`/runs/${run_id}/report`))
save(`viz.${name}.json`, await j(`/runs/${run_id}/viz`))
save("runs.json", await j("/runs"))
console.log(run_id, events.length, "events; last:", events.at(-1))
