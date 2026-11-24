---
name: remove-or-block-package
description: Remove a malicious, typosquatted or unused package from the manifests and lockfile, or restore a tampered lockfile entry to the hashes published on the official index.
allowed_files: requirements*.txt, poetry.lock, pyproject.toml, setup.cfg, setup.py
---
# Remove or block a package

## When to use
- Typosquat or package with malicious install behaviour.
- A runtime package that the code never imports and no other package requires.
- A lockfile hash that differs from the hashes published for that exact version.

## Steps
1. Call `get_evidence`; confirm from the evidence that nothing imports the package (or that it is malicious).
2. Delete its line from every requirements file. If no other locked package depends on it, delete its
   `[[package]]` block from poetry.lock as well; otherwise keep the lock block and say why.
3. Typosquat: if the intended package is not already declared, replace the name instead of deleting the line.
4. Tampered hash: replace only the wrong `sha256:` value with the published one from the evidence.

## Patch rules
- Manifests and lockfile only. Never remove a package that the code imports.

## Notes to give
- Block the name in the package proxy / allow-list (outside this repository).
- For packages with install hooks: rotate secrets on machines that installed it.

## Rollback
Re-add the line (not recommended for malicious packages).
