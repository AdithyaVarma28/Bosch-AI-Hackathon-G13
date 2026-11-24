---
name: replace-unsafe-api
description: Replace a call to a vulnerable or dangerous API in the application code with its safe equivalent at the exact call sites (for example yaml.load with FullLoader → yaml.safe_load), when upgrading is not wanted or not enough.
allowed_files: *.py, tests/guardian/*
---
# Replace an unsafe API call

## When to use
- The evidence shows the code calls the vulnerable function (usage `symbol_called`).
- The advisory or a human names a safe alternative, or the human asked to keep the current version.

## Steps
1. Call `get_evidence` for each finding and read every call site with `read_file`.
2. Replace only the vulnerable call, keeping the arguments that still apply:
   - `yaml.load(x, Loader=yaml.FullLoader)` / `yaml.load(x, Loader=yaml.Loader)` / `yaml.unsafe_load(x)` → `yaml.safe_load(x)`
   - `pickle.load(s)` on untrusted data → `json.load(s)` only if the data is JSON; otherwise escalate.
   - `subprocess.*(..., shell=True)` with input → pass an argument list and `shell=False`.
3. Use the exact source line as `old_text` so the edit applies once.

## Patch rules
- Change only the call sites cited in the evidence. No refactors, no new dependencies.

## Compatibility notes to give
- What input the safe API no longer accepts (e.g. safe_load does not build arbitrary Python objects).

## Expected risk after
"reduced": the vulnerable code path is no longer used, but the package version still matches the advisory, so
an upgrade should still be scheduled. Say so.

## Rollback
`git revert` of the fix commit.
