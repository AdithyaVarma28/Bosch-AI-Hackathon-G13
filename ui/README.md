# Stage 3 dashboard

Open `index.html` in a browser to view the mini-shop mentor demo. The UI is static and has no install or build step. The fixture is illustrative; it is not output from a real scan.

## Live scan

`guardian serve output/<repo>` serves this folder at http://127.0.0.1:8000/ together with the Stage 3 API; the page then loads the scan from `/ui-bundle` and the header shows **LIVE SCAN**.

## Importing a scan

Every Stage 3 run writes `output/<repo>/ui_bundle.json` (built by `guardian/stage3_knowledge/export.py` from the other Stage 3 files). Load it with **Import scan**. A bundle must include these top-level fields:

```json
{
  "repo": { "name": "my-repo", "language": "Python", "branch": "main", "commit": "abc123", "scannedAt": "Nov 23, 2026", "summary": "...", "files": 10, "functions": 20, "routes": 2, "packages": 4, "modules": 3 },
  "coverage": {
    "files": { "parsed": 9, "total": 10 },
    "calls": { "resolved": 8, "total": 9 },
    "modules": { "carded": 3, "total": 3 },
    "filesCarded": { "carded": 2, "total": 10 },
    "questions": { "resolved": 1, "total": 2 },
    "knownUnknowns": []
  },
  "modules": [], "edges": [], "paths": [], "packages": [], "changes": [], "findings": []
}
```

The object fields within each array follow the examples in `data/demo-data.js`. Optional fields the Stage 3 export adds: `repo.tags`, `repo.baselineLabel`, `repo.changeSummary` (used by the overview and change-history pages; the demo values are the fallback), and `paths[].kind` (`network`, `external`, `data`, `internal`).
