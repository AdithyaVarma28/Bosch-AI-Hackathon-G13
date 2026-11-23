# Guardian's Eyes: Multi-Layer Dependency Graph Approach

## 1. Overview

Guardian's Eyes should construct a **multi-layer, version-aware dependency graph** from a supplied software repository.

The goal is to understand three complementary views of the same application:

1. **Declared dependency layer** — what developers explicitly declare in manifests.
2. **Resolved dependency layer** — what the package manager resolves, including exact versions and transitive dependencies.
3. **Source-code usage layer** — which external packages are statically referenced by application source files.

These should not be treated as three unrelated graphs. They should be stored as one unified graph with distinct node and relationship types, allowing the system to compare the layers and identify discrepancies.

> Important: Static source-code imports are evidence of referenced packages, not proof of runtime usage. Dynamic imports, reflection, plugins, configuration-driven loading and runtime code generation may not be captured by static analysis.

---

## 2. High-Level Architecture

```text
                         GitHub Repository
                                  |
                                  v
                       Repository Analysis
                (clone, commit SHA, manifests, lockfiles)
                                  |
             +--------------------+--------------------+
             |                    |                    |
             v                    v                    v
      Declared Layer        Resolved Layer          Usage Layer
      Manifest Parser       cdxgen + native         AST / Tree-sitter
                           package-manager resolver    analysis
             |                    |                    |
             +--------------------+--------------------+
                                  |
                                  v
                         Unified Graph Builder
              (identity mapping, relationship mapping,
                       metadata and evidence)
                                  |
                                  v
                         Neo4j Knowledge Graph
                                  |
                                  v
                  Interactive Dependency Explorer
                     (React + Cytoscape.js)
                                  |
                                  v
                  Cross-Layer Discrepancy Analysis
```

### Recommended technology stack

| Layer | Recommended technology | Purpose |
|---|---|---|
| Repository ingestion | Git / GitPython | Clone repository and record commit snapshot |
| Declared dependencies | Ecosystem-specific manifest parsers | Extract declared packages and constraints |
| Resolved dependencies | cdxgen + native package managers | Generate SBOM and obtain resolved dependency relationships |
| SBOM format | CycloneDX | Standardized component and dependency representation |
| Source-code analysis | Python AST / Tree-sitter | Extract static import references |
| Package identity | Package URL (PURL) | Normalize package identities across sources |
| Graph construction | Python | Merge and normalize nodes and edges |
| Graph database | Neo4j | Persist version-aware graph |
| Visualization | React + Cytoscape.js | Interactive graph exploration |

---

## 3. Stage 1 — Repository Analysis

### Input

A Git repository URL, ZIP archive or local repository path.

Example:

```text
https://github.com/example/sample-project
```

### Processing

1. Clone or extract the repository into an isolated workspace.
2. Record the repository URL, branch and exact commit SHA.
3. Recursively identify projects, workspaces, manifests and lockfiles.
4. Detect the ecosystem for each project root.
5. Keep multiple projects/workspaces separate where appropriate.

### Common files to detect

| Ecosystem | Manifest / project file | Lockfile / resolution file |
|---|---|---|
| Python | `requirements.txt`, `pyproject.toml`, `Pipfile`, `setup.py` | `poetry.lock`, `Pipfile.lock`, `uv.lock`, other ecosystem-specific lock data |
| JavaScript | `package.json` | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` |
| Java | `pom.xml`, `build.gradle` | Maven/Gradle resolution data and lockfiles where used |
| Go | `go.mod` | `go.sum` |
| Rust | `Cargo.toml` | `Cargo.lock` |

### Example repository inventory

```json
{
  "repository": "sample-project",
  "commit_sha": "abc123",
  "ecosystems": ["npm", "python"],
  "manifests": ["package.json", "pyproject.toml"],
  "lockfiles": ["package-lock.json", "poetry.lock"]
}
```

This inventory is illustrative. The actual detector should record the path and owning project/workspace for every manifest and lockfile.

---

## 4. Layer 1 — Declared Dependency Graph

### What it represents

The declared layer shows what the developer explicitly specifies in dependency manifests.

Examples include:

- Python: `requirements.txt`, `pyproject.toml`, `Pipfile`.
- JavaScript: `package.json`.
- Java: `pom.xml`, `build.gradle`.
- Rust: `Cargo.toml`.
- Go: `go.mod`.

### Example

Given:

```text
fastapi
requests
pandas
pytest
```

The declared graph is conceptually:

```text
sample-project
  ├── FastAPI
  ├── Requests
  ├── Pandas
  └── Pytest
```

### Metadata to retain

For each declaration, store:

- Package name.
- Ecosystem.
- Requested version or version constraint.
- Dependency scope/type, when available (runtime, development, test, optional, build, etc.).
- Source manifest path.
- Project/workspace that owns the declaration.
- Declaration evidence and extraction method.

### Why this layer matters

It enables the system to identify:

- Newly declared packages.
- Unpinned or broadly constrained dependencies.
- Suspicious or unexpected dependency declarations.
- Differences between manifests and lockfiles.
- Packages declared for development or testing separately from runtime dependencies.

A declaration does not prove that the package was resolved, installed, or used by application code. That is why the other layers are required.

---

## 5. Layer 2 — Resolved Dependency Graph

### What it represents

The resolved layer represents the dependency tree selected by the package manager for a particular repository state and dependency configuration. It should include exact resolved versions and direct/transitive dependency relationships where the ecosystem provides that information.

This is the primary layer for software supply-chain analysis.

### Example

```text
sample-project
  ├── FastAPI
  │    ├── Starlette
  │    │    └── AnyIO
  │    └── Pydantic
  │         └── Pydantic-Core
  │
  └── Requests
       ├── urllib3
       └── certifi
```

The example is illustrative; exact versions and relationships must come from the repository's resolved dependency data.

### How to generate it

1. Prefer the repository's lockfile when it represents the intended dependency resolution.
2. Use the relevant native package manager to inspect or reproduce resolution when needed.
3. Generate a CycloneDX SBOM using cdxgen.
4. Extract component records and dependency relationships from the SBOM.
5. Cross-check the SBOM relationship data against native package-manager output where practical.
6. Record the source and confidence of each relationship.

Example commands:

```bash
# Generate a CycloneDX SBOM recursively
cdxgen -r -o bom.json --spec-version 1.7 .

# Node.js dependency tree
npm ls --all --json

# Maven dependency tree
mvn dependency:tree
```

The appropriate command and resolution strategy depend on the package manager and repository configuration. Do not assume a generated environment is identical to the repository's original environment if no lockfile is present.

### SBOM sections used

- `components`: component records, including identity and version information.
- `dependencies`: dependency relationships, represented through component references such as `bom-ref` and `dependsOn`.

Example simplified CycloneDX fragment:

```json
{
  "components": [
    {
      "type": "library",
      "bom-ref": "pkg:npm/express@4.18.2",
      "name": "express",
      "version": "4.18.2",
      "purl": "pkg:npm/express@4.18.2"
    },
    {
      "type": "library",
      "bom-ref": "pkg:npm/accepts@1.3.8",
      "name": "accepts",
      "version": "1.3.8",
      "purl": "pkg:npm/accepts@1.3.8"
    }
  ],
  "dependencies": [
    {
      "ref": "pkg:npm/express@4.18.2",
      "dependsOn": ["pkg:npm/accepts@1.3.8"]
    },
    {
      "ref": "pkg:npm/accepts@1.3.8",
      "dependsOn": []
    }
  ]
}
```

This is a simplified example, not a complete SBOM document.

### Important validation rule

Do not invent edges for components that are absent from the dependency section. A component may have unknown or incomplete dependency relationships. Mark these cases as unknown and investigate using lockfiles or native package-manager information.

---

## 6. Layer 3 — Source-Code Usage Graph

### What it represents

The usage layer links source-code modules to external packages that they statically reference through import statements or equivalent language constructs.

Example project:

```text
src/
  main.py
  payment.py
  analytics.py
  authentication.py
```

Example source files:

```python
# main.py
import fastapi

# payment.py
import requests

# analytics.py
import pandas

# authentication.py
import jwt
```

The usage graph can represent:

```text
main.py           ──IMPORTS──> FastAPI
payment.py        ──IMPORTS──> Requests
analytics.py      ──IMPORTS──> Pandas
authentication.py ──IMPORTS──> JWT
```

### How to implement it

1. Detect source files belonging to each project/workspace.
2. Parse source code with a language-specific AST parser or Tree-sitter.
3. Extract import declarations and package/module references.
4. Map imported module names to ecosystem package identities.
5. Connect source modules to matching Package or Artifact nodes.
6. Record the source file, line/column when available, parser and mapping evidence.

For Python, the built-in `ast` module can extract import declarations. For multiple languages, Tree-sitter or language-specific parsers can be used.

Example Python snippet:

```python
import ast

source = """
import requests
import pandas
from fastapi import FastAPI
"""

tree = ast.parse(source)

for node in ast.walk(tree):
    if isinstance(node, ast.Import):
        for alias in node.names:
            print(alias.name)
    elif isinstance(node, ast.ImportFrom):
        print(node.module)
```

### Important limitation

Static imports are not proof of runtime use. Dynamic imports, reflection, plugins, configuration-based loading and runtime code generation may not be detected. An imported module may also be part of the application's own code rather than an external package. Module-to-package mapping therefore requires ecosystem-aware logic.

---

## 7. How the Three Layers Work Together

The layers should be stored in one unified graph, with different relationship types.

### Recommended relationship types

| Relationship | Source → Target | Meaning |
|---|---|---|
| `DECLARES` | Project → Package | The project manifest explicitly declares the package |
| `HAS_ARTIFACT` | Package → Artifact | The package has a specific version/artifact |
| `DEPENDS_ON` | Artifact → Artifact | One resolved artifact depends on another resolved artifact |
| `IMPORTS` | SourceModule → Package/Artifact | A source module statically imports or references a package |

### Example unified model

```text
Project: sample-project
    |
    | DECLARES
    v
Package: Requests
    |
    | HAS_ARTIFACT
    v
Artifact: Requests@2.31.0
    |
    | DEPENDS_ON
    v
Artifact: urllib3@2.2.1

SourceModule: payment.py
    |
    | IMPORTS
    v
Package: Requests
```

The exact edge directions should be applied consistently throughout the application. In particular, `DEPENDS_ON` should point from the dependent artifact to the artifact it depends on.

---

## 8. Cross-Layer Analysis: What Makes This Approach Valuable?

Once all three layers are connected, Guardian's Eyes can identify useful discrepancies and security-relevant relationships.

| Observation | Possible interpretation / action |
|---|---|
| Declared but not resolved | The package may be excluded by a selected environment, marker, optional group or resolution failure; investigate before classifying |
| Resolved but not directly imported | The package may be transitive, dynamically loaded, plugin-provided or not observed in static imports |
| Imported but not declared | Potential undeclared dependency, import-to-package mapping issue or package supplied transitively; investigate |
| Declared, resolved and imported | The package is declared, resolved and statically observed in source code |
| Vulnerable and imported | A known vulnerable package is statically referenced by application source code; assess reachability and exploitability separately |
| Vulnerable but not directly imported | A vulnerable transitive dependency is present in the resolved graph and may still affect the application |

This creates a more informative view than a single dependency tree.

---

## 9. Unified Graph Data Model

A practical Neo4j model can use the following node labels:

- `Project`
- `Package`
- `Artifact`
- `SourceModule`

Optional labels can be added later for `Vulnerability`, `RepositoryCommit`, `Manifest` and `ContainerImage`.

### Suggested node properties

**Project**

- `project_id`
- `name`
- `repository_url`
- `commit_sha`
- `scan_id`

**Package**

- `package_id`
- `name`
- `ecosystem`
- `purl_base` where applicable

**Artifact**

- `artifact_id`
- `name`
- `version`
- `purl`
- `bom_ref`
- `scope`
- `hashes` where available

**SourceModule**

- `module_id`
- `path`
- `language`

### Suggested edge properties

For `DECLARES`:

- `requested_range`
- `scope`
- `source_file`
- `evidence_source`

For `DEPENDS_ON`:

- `requested_range` when known
- `scope`
- `snapshot_id`
- `evidence_source`
- `resolution_method`
- `verification_status`

For `IMPORTS`:

- `source_file`
- `line_number` when available
- `parser`
- `mapping_status`

Use PURLs for package identity across sources and `bom-ref` for references within a specific SBOM. Store a scan or snapshot identifier so different repository commits are not accidentally merged into one indistinguishable graph.

---

## 10. Graph Quality and Validation Engine

A multi-layer graph should also explain how much evidence supports its nodes and relationships.

### Recommended validation checks

| Check | Purpose |
|---|---|
| Unique component identity | Detect duplicate package/artifact identities |
| PURL validation | Check package identity formatting and ecosystem mapping |
| BOM reference validation | Ensure dependency references point to known components |
| Dangling edge detection | Identify edges with missing endpoints |
| Missing relationship investigation | Identify components with unknown/incomplete dependency records |
| Orphan analysis | Find nodes with no known path from a project root; investigate rather than automatically treating them as errors |
| Cycle detection | Identify cycles where relevant to the ecosystem/model |
| Version consistency | Detect conflicting or unresolved version data |
| Layer discrepancy analysis | Compare declared, resolved and source-observed relationships |

### Evidence status for nodes and edges

Use internal classifications such as:

- `verified`: confirmed by lockfile or native package-manager resolution.
- `declared`: extracted from a manifest but not resolved to an exact artifact.
- `registry-derived`: obtained from external package metadata.
- `statically-observed`: found in source-code imports.
- `unknown`: insufficient evidence to establish the relationship.

These are proposed internal labels, not official CycloneDX fields.

Avoid presenting a single confidence percentage unless its calculation is documented and validated. A quality report should show actual counts and reasons for uncertainty.

---

## 11. Interactive Graph Explorer

Use React and Cytoscape.js to display and explore the unified graph.

### Layer controls

Provide a selector for:

- All layers.
- Declared only.
- Resolved only.
- Source-code usage only.

### Useful graph interactions

1. **Expand dependency:** Show the next dependency level.
2. **Collapse subtree:** Hide nested dependencies.
3. **Trace path:** Show how a package connects to a project root.
4. **Search package:** Find and focus a node.
5. **Filter by scope:** Runtime, development, test, build or optional where available.
6. **Filter by ecosystem:** Python, npm, Maven, Go, Rust, etc.
7. **Show evidence:** Display the manifest, lockfile, SBOM reference or source file supporting a relationship.
8. **Show discrepancy:** Highlight declared/resolved/usage mismatches.

Use distinct edge styles or colors for `DECLARES`, `DEPENDS_ON` and `IMPORTS`. Include a legend so the relationships are understandable. Avoid relying only on colors; labels and line styles should also distinguish relationships.

---

## 12. Recommended Implementation Order

Build the layers incrementally rather than implementing all of them simultaneously.

### Phase 1 — Resolved layer (foundation)

- Clone a repository at a fixed commit.
- Detect manifests and lockfiles.
- Generate CycloneDX SBOM using cdxgen.
- Validate the SBOM.
- Extract components and dependency relationships.
- Store version-specific nodes and edges in Neo4j.
- Display the resolved dependency graph.

### Phase 2 — Declared layer

- Parse dependency manifests.
- Extract package names, requested ranges and scopes.
- Map declarations to package identities and resolved artifacts.
- Add `DECLARES` relationships.
- Highlight declared-but-unresolved and resolved-but-not-directly-declared cases for investigation.

### Phase 3 — Usage layer

- Parse source files using language-specific ASTs or Tree-sitter.
- Extract import references.
- Map imports to external package identities.
- Add `IMPORTS` relationships.
- Identify potential undeclared dependencies and packages not observed in direct source imports.

### Phase 4 — Graph intelligence

- Add graph completeness checks.
- Calculate dependency depth and breadth.
- Calculate fan-in, fan-out and selected centrality metrics.
- Identify high-impact dependency nodes.
- Add evidence panels and path explanations.

### Phase 5 — Security integration

- Map vulnerability findings to exact Package/Artifact nodes.
- Highlight vulnerable transitive dependencies.
- Trace paths from the project to affected artifacts.
- Correlate source-code observations with dependency paths, without treating static imports as proof of exploitability.

---

## 13. Expected Final Output

For every submitted repository, Guardian's Eyes should produce:

1. **CycloneDX SBOM:** A portable inventory of software components and available dependency relationships.
2. **Declared dependency view:** What the developer explicitly declared.
3. **Resolved dependency view:** Exact resolved versions and transitive dependency paths where supported.
4. **Source-code usage view:** Which modules statically reference external packages.
5. **Unified Neo4j graph:** One connected model containing all available layers and their evidence.
6. **Graph quality report:** Missing or uncertain relationships, unresolved components and validation findings.
7. **Interactive explorer:** Searchable, filterable, expandable visualization with relationship explanations.

## 14. Key Design Principle

The main differentiator is not simply generating three separate dependency graphs. It is **cross-referencing the declared, resolved and source-observed layers to explain discrepancies**.

Guardian's Eyes should be able to answer:

- Why is this package present?
- Which direct dependency introduced it?
- Is it directly or transitively resolved?
- Which application modules statically import it?
- Which manifest or lockfile supports the relationship?
- Is its resolved version known?
- Does it have a known vulnerability?
- Which dependency paths connect it to the application?

The resulting system is a repository-grounded, version-aware and evidence-backed Dependency Intelligence Graph rather than a conventional package dependency tree.

---

## References and Tools

- [DGMF — Dependency Graph Mining Framework (paper)](https://sse.cs.tu-dortmund.de/storages/sse-cs/r/Publications/Preprints/dgmf.pdf)
- [DGMF implementation](https://github.com/sse-labs/dgmf)
- [cdxgen — CycloneDX SBOM generator](https://github.com/CycloneDX/cdxgen)
- [CycloneDX specification](https://cyclonedx.org/specification/overview/)
- [CycloneDX CLI](https://github.com/CycloneDX/cyclonedx-cli)
- [Neo4j](https://neo4j.com/)
- [Cytoscape.js](https://js.cytoscape.org/)
- [Tree-sitter](https://tree-sitter.github.io/tree-sitter/)
