# Guardian web dashboard

React + TypeScript + Vite + Tailwind front end for the Guardian API. It shows real scan data (Overview, Dependency Intelligence,
Vulnerabilities, Anomaly Detection) and can start and follow a scan (Repository Scanning).

## Run it

One process (serves the API and the built site):

```powershell
cd web
npm install
npm run build
cd ..
$env:PYTHONPATH = "src"; python -m guardian.cli serve --out output
```

Open http://127.0.0.1:8000/. Finished runs found under `--out` appear automatically; start a new one from **New Scan**.

Development with hot reload (API on 8000, site on 5173; `/runs` is proxied):

```powershell
$env:PYTHONPATH = "src"; python -m guardian.cli serve --out output
cd web; npm run dev
```

## Test

```powershell
cd web; npm test -- --run; npm run typecheck
cd ..; $env:PYTHONPATH = "src"; python -m pytest -q
```

Tests use fixtures captured from a real run (`src/fixtures/*.mini-shop.json`, made by `scripts/capture-run.mjs`).

## Layout

- `src/api` typed client and event stream; `src/model` pure functions that turn API payloads into what pages show;
  `src/hooks` data loading; `src/pages` the five pages; `src/theme/tokens.ts` colours and sizes read from the Figma file.

## Known limitations

- Runs still in flight, or that failed, are lost when the server restarts (only finished runs are on disk).
- Sidebar items other than the five live pages are shown disabled ("Coming soon"). Finding status is read-only.
- Designed for 1280 px and wider. Sidebar icons are simple placeholders, not the Figma icon set.
- Only checked on Windows and in the in-app browser.
