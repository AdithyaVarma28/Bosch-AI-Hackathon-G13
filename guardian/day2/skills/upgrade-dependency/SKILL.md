---
name: upgrade-dependency
description: Move a vulnerable or suspicious Python package to a safe version (upgrade to a fixed release, or pin back to the last trusted one) in requirements files and poetry.lock.
allowed_files: requirements*.txt, poetry.lock, pyproject.toml, setup.cfg, setup.py
---
# Upgrade (or pin back) a dependency

## When to use
- A known vulnerability is fixed in a later release of the package.
- A suspicious update must be rolled back to the last version the project trusted.

## Steps
1. Call `list_candidates` and prefer a candidate whose checks all pass. Prefer the same major version.
2. For any other version, call `check_version` first. Never propose a version that is affected, unavailable,
   yanked, or that breaks a constraint of a package that depends on it.
3. Change the exact pin in every requirements file that declares the package (`name==old` → `name==new`).
4. In `poetry.lock`, change the package block's `version`. If the block lists file hashes, replace them with
   `files = []` and add the compatibility note "regenerate lockfile hashes with poetry lock".
5. If the package is transitive (not declared), add `name>=new` to requirements.txt instead of editing an
   existing line.

## Patch rules
- Touch only the manifests and the lockfile. Never edit application code in this skill.
- Keep the edit minimal: one line per manifest, one block per lockfile.

## Compatibility notes to give
- Major version change → "check the release notes for breaking changes".
- Name the symbols the code uses from the package (from `get_evidence`).

## Rollback
`git revert` of the fix commit, or pin the previous version again.

## Example
`PyYAML==5.3.1` → `PyYAML==5.4` in requirements.txt and `version = "5.4"` in the PyYAML block of poetry.lock.
