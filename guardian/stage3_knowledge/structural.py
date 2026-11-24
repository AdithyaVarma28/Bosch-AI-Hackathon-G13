"""3A Structural Mapper: package linking, modules, module dependencies, declared-vs-used,
function tags and centrality. Algorithms only, no AI."""
from __future__ import annotations

import itertools
import math
import posixpath
from collections import Counter, defaultdict
from typing import Optional

import networkx as nx

from .graph_builder import add_edge, add_node, ev, nodes_of, out_edges, pred, succ, tag
from .schema import module_id, normalize_name, repo_id

# Fallback import-name -> distribution table (Stage 2 provides the main one).
FALLBACK_DIST = {
    "yaml": "PyYAML", "cv2": "opencv-python", "sklearn": "scikit-learn", "PIL": "Pillow",
    "bs4": "beautifulsoup4", "dateutil": "python-dateutil", "dotenv": "python-dotenv", "jwt": "PyJWT",
    "Crypto": "pycryptodome", "attr": "attrs", "magic": "python-magic", "serial": "pyserial",
    "OpenSSL": "pyOpenSSL", "git": "GitPython", "docx": "python-docx", "pptx": "python-pptx",
    "multipart": "python-multipart", "jose": "python-jose", "slugify": "python-slugify",
    "fitz": "PyMuPDF", "zmq": "pyzmq", "psycopg2": "psycopg2-binary", "MySQLdb": "mysqlclient",
    "google.protobuf": "protobuf", "jinja2": "Jinja2", "markupsafe": "MarkupSafe",
}

# Fallback sensitive-call categories from API targets (Stage 2 sensitive_calls is primary).
CALL_PREFIX_CATEGORY = {
    "requests.": "network", "httpx.": "network", "urllib.request.": "network", "urllib3.": "network",
    "aiohttp.": "network", "socket.": "network", "http.client.": "network",
    "subprocess.": "subprocess", "os.system": "subprocess", "os.popen": "subprocess",
    "os.exec": "subprocess", "os.spawn": "subprocess",
}
CALL_EXACT_CATEGORY = {
    "eval": "code_exec", "exec": "code_exec", "compile": "code_exec", "builtins.eval": "code_exec",
    "builtins.exec": "code_exec", "pickle.load": "deserialize", "pickle.loads": "deserialize",
    "cPickle.loads": "deserialize", "marshal.loads": "deserialize", "marshal.load": "deserialize",
    "yaml.load": "deserialize", "yaml.unsafe_load": "deserialize", "yaml.load_all": "deserialize",
    "dill.loads": "deserialize", "shelve.open": "deserialize",
}


def call_category(target: str) -> Optional[str]:
    if not target:
        return None
    if target in CALL_EXACT_CATEGORY:
        return CALL_EXACT_CATEGORY[target]
    for prefix, cat in CALL_PREFIX_CATEGORY.items():
        if target.startswith(prefix):
            return cat
    return None


def module_of(G: nx.MultiDiGraph, node: str) -> Optional[str]:
    d = G.nodes.get(node, {})
    if d.get("type") == "File":
        return d.get("module")
    if d.get("file"):
        return G.nodes.get(f"file:{d['file']}", {}).get("module")
    return None


# --------------------------------------------------------------------------- 1. packages

def link_packages(G: nx.MultiDiGraph, code_index: dict) -> None:
    dist_map: dict[str, str] = dict(FALLBACK_DIST)
    dist_map.update(code_index.get("import_name_to_distribution", {}) or {})
    lower_map = {k.lower(): v for k, v in dist_map.items()}

    pkg_by_name: dict[str, str] = {}
    for p in nodes_of(G, "Package"):
        n = normalize_name(G.nodes[p].get("name", ""))
        # prefer the resolved (versioned) node over an unversioned declared one
        if n not in pkg_by_name or G.nodes[p].get("version"):
            pkg_by_name[n] = p

    def resolve(import_name: str) -> Optional[str]:
        if not import_name:
            return None
        parts = import_name.split(".")
        for i in range(len(parts), 0, -1):  # longest dotted prefix first (google.protobuf)
            key = ".".join(parts[:i])
            dist = dist_map.get(key) or lower_map.get(key.lower())
            if dist and normalize_name(dist) in pkg_by_name:
                return pkg_by_name[normalize_name(dist)]
        return pkg_by_name.get(normalize_name(parts[0]))

    G.graph["unresolved_imports"] = []
    for f in nodes_of(G, "File"):
        data = G.nodes[f]
        for imp in data.get("external_imports", []):
            pkg = resolve(imp.get("name") or "")
            if pkg:
                add_edge(G, f, pkg, "USES_PACKAGE", "ast", [ev(data["path"], imp.get("line"))],
                         import_name=imp.get("name"))
            else:
                tag(G, f, "unresolved_import")
                G.graph["unresolved_imports"].append({"file": data["path"], "line": imp.get("line"),
                                                      "import": imp.get("name")})

    for fn in nodes_of(G, "Function", "Class"):
        data = G.nodes[fn]
        for c in data.get("external_calls", []):
            target = c.get("target") or ""
            pkg = resolve(c.get("import_name") or target)
            if pkg:
                # ``api`` repeats ``target``: node-link JSON reuses "target" for the edge end, so the
                # API name would be lost when graph.json is reloaded (Stage 4 matches on it)
                add_edge(G, fn, pkg, "CALLS_API", "ast", [ev(data.get("file"), c.get("line"))],
                         key=f"CALLS_API:{target}", target=target, api=target)


# --------------------------------------------------------------------------- 2. modules

def _seed_modules(G: nx.MultiDiGraph, files: list[str]) -> dict[str, tuple[str, str, str]]:
    """file node -> (module path, display name, kind) from the folder structure."""
    paths = {G.nodes[f]["path"] for f in files}
    pkg_dirs = {posixpath.dirname(p) for p in paths if posixpath.basename(p) == "__init__.py"}
    for f in files:  # Stage 2 package_dir also counts
        pd = G.nodes[f].get("package_dir")
        if pd and pd in {posixpath.dirname(p) for p in paths}:
            if f"{pd}/__init__.py" in paths:
                pkg_dirs.add(pd)
    root_pkgs = {d for d in pkg_dirs if posixpath.dirname(d) not in pkg_dirs}

    out: dict[str, tuple[str, str, str]] = {}
    for f in files:
        p = G.nodes[f]["path"]
        d = posixpath.dirname(p)
        base = posixpath.basename(p)
        if d in pkg_dirs:
            if d in root_pkgs and base != "__init__.py":
                mod = p[:-3] if p.endswith(".py") else p          # loose file under the app root
                out[f] = (mod, posixpath.basename(mod), "file")
            else:
                out[f] = (d, posixpath.basename(d) or d, "package")
        else:
            out[f] = (d or ".", posixpath.basename(d) or "(root)", "folder")
    return out


def detect_modules(G: nx.MultiDiGraph) -> dict:
    rid = repo_id(G.graph.get("repo", "repo"))
    files = nodes_of(G, "File")
    tests = [f for f in files if G.nodes[f].get("is_test")]
    src = [f for f in files if not G.nodes[f].get("is_test")]

    # b. Louvain clusters over the undirected internal import graph
    U = nx.Graph()
    U.add_nodes_from(src)
    for u, v, d in G.edges(data=True):
        if d.get("type") == "IMPORTS" and u in U and v in U:
            w = d.get("weight", 1)
            U.add_edge(u, v, weight=U[u][v]["weight"] + w if U.has_edge(u, v) else w)
    if U.number_of_edges():
        communities = nx.community.louvain_communities(U, weight="weight", seed=42)
    else:
        communities = [{n} for n in U.nodes]
    cluster_of = {f: i for i, c in enumerate(communities) for f in c}

    seeds = _seed_modules(G, src)
    flat = all(kind == "folder" for _, _, kind in seeds.values())

    assignment: dict[str, tuple[str, str, str]] = {}
    if flat and src:
        # c. flat repo (no packages): clusters become modules
        for i, comm in enumerate(communities):
            members = sorted(G.nodes[f]["path"] for f in comm)
            common = posixpath.commonpath(members) if len(members) > 1 else posixpath.dirname(members[0])
            hub = max(comm, key=lambda f: (U.degree(f, weight="weight"), G.nodes[f]["path"]))
            stem = posixpath.basename(G.nodes[hub]["path"])[:-3]
            path = f"{common}/{stem}" if common and common != "." else stem
            for f in comm:
                assignment[f] = (path, stem, "cluster")
    else:
        assignment = dict(seeds)
        # c. a folder that splits into >=2 clusters of >=3 files each -> submodules
        by_mod: dict[str, list[str]] = defaultdict(list)
        for f, (m, _, _) in assignment.items():
            by_mod[m].append(f)
        for m, fs in by_mod.items():
            groups: dict[int, list[str]] = defaultdict(list)
            for f in fs:
                groups[cluster_of.get(f, -1)].append(f)
            if len(groups) >= 2 and all(len(g) >= 3 for g in groups.values()):
                for idx, (_, g) in enumerate(sorted(groups.items())):
                    sub = f"{m}/{chr(ord('a') + idx)}"
                    for f in g:
                        assignment[f] = (sub, posixpath.basename(m) + f"/{chr(ord('a') + idx)}", "submodule")

    # d. tests go to their own module
    if tests:
        tdirs = sorted({G.nodes[f]["path"].split("/")[0] for f in tests})
        tpath = tdirs[0] if len(tdirs) == 1 and "/" in G.nodes[tests[0]]["path"] else "tests"
        for f in tests:
            assignment[f] = (tpath, "tests", "tests")

    # names must be unique for the UI; fall back to the path when they clash
    name_count = Counter(n for _, n, _ in set(assignment.values()))
    modules: dict[str, dict] = {}
    for f, (path, name, kind) in assignment.items():
        mid = module_id(path)
        if mid not in modules:
            modules[mid] = {"path": path, "name": name if name_count[name] == 1 else path, "kind": kind, "files": []}
        modules[mid]["files"].append(G.nodes[f]["path"])

    for mid, m in modules.items():
        add_node(G, mid, "Module", "algorithm", [ev(p) for p in sorted(m["files"])[:3]], name=m["name"],
                 path=m["path"], kind=m["kind"], files=sorted(m["files"]), centrality=0.0)
        add_edge(G, rid, mid, "CONTAINS", "algorithm")
        for p in m["files"]:
            fid = f"file:{p}"
            G.nodes[fid]["module"] = mid
            add_edge(G, mid, fid, "CONTAINS", "algorithm")

    # c. a cluster spanning several folders -> tightly_coupled_with (+ a 3D question later)
    coupled: dict[str, set[str]] = defaultdict(set)
    for comm in communities:
        mods = {assignment[f][0] for f in comm if f in assignment}
        if len(mods) < 2:
            continue
        for a, b in itertools.combinations(sorted(comm), 2):
            ma, mb = G.nodes[a].get("module"), G.nodes[b].get("module")
            if ma and mb and ma != mb and U.has_edge(a, b):
                coupled[ma].add(mb)
                coupled[mb].add(ma)
    for mid, others in coupled.items():
        G.nodes[mid]["tightly_coupled_with"] = sorted(others)
        tag(G, mid, "tightly_coupled")

    G.graph["louvain"] = {"seed": 42, "communities": len(communities)}
    return {"modules": len(modules), "communities": len(communities), "flat": flat}


# --------------------------------------------------------------------------- 3. module deps

def module_dependencies(G: nx.MultiDiGraph) -> list[list[str]]:
    for u, v, d in list(G.edges(data=True)):
        if d.get("type") != "IMPORTS":
            continue
        mu, mv = G.nodes[u].get("module"), G.nodes[v].get("module")
        if mu and mv and mu != mv:
            add_edge(G, mu, mv, "DEPENDS_ON", "algorithm", d.get("evidence", [])[:3], weight=d.get("weight", 1))
    D = module_graph(G)
    cycles = [c for c in itertools.islice(nx.simple_cycles(D), 50) if len(c) > 1]
    for c in cycles:
        for m in c:
            tag(G, m, "in_cycle")
            G.nodes[m].setdefault("cycles", []).append(c)
    G.graph["module_cycles"] = cycles
    return cycles


def module_graph(G: nx.MultiDiGraph, include_tests: bool = True) -> nx.DiGraph:
    D = nx.DiGraph()
    for m in nodes_of(G, "Module"):
        if include_tests or G.nodes[m].get("kind") != "tests":
            D.add_node(m)
    for u, v, d in G.edges(data=True):
        if d.get("type") == "DEPENDS_ON" and u in D and v in D:
            D.add_edge(u, v, weight=d.get("weight", 1))
    return D


# --------------------------------------------------------------------------- 4. declared vs used

def declared_vs_used(G: nx.MultiDiGraph) -> None:
    for p in nodes_of(G, "Package"):
        d = G.nodes[p]
        users = pred(G, p, "USES_PACKAGE")
        runtime = [f for f in users if not G.nodes[f].get("is_test")]
        test = [f for f in users if G.nodes[f].get("is_test")]
        d["used_by_files"] = sorted(G.nodes[f]["path"] for f in users)
        if d.get("direct") and not d.get("dev"):
            if not runtime and test:
                tag(G, p, "test_only")
            elif not runtime:
                tag(G, p, "declared_unused")
        if d.get("dev") and runtime:
            tag(G, p, "dev_used_in_runtime")
        if users and not d.get("direct"):
            tag(G, p, "undeclared_import")       # imported directly but only arrives transitively
            for f in users:
                tag(G, f, "undeclared_import")
    for u in G.graph.get("unresolved_imports", []):
        u["undeclared"] = True                   # no package at all: transitive, vendored or missing


# --------------------------------------------------------------------------- 5. tags

def tag_functions(G: nx.MultiDiGraph) -> None:
    for fn in nodes_of(G, "Function", "Class"):
        d = G.nodes[fn]
        if pred(G, fn, "HANDLES"):
            tag(G, fn, "entry_point")
        if d.get("inputs") or out_edges(G, fn, "RECEIVES_INPUT"):
            tag(G, fn, "receives_user_input")
        for e in succ(G, fn, "READS_ENV"):
            if G.nodes[e].get("secret_like"):
                tag(G, fn, "reads_secret_env")
        if succ(G, fn, "WRITES"):
            tag(G, fn, "writes_db")
        if succ(G, fn, "READS"):
            tag(G, fn, "reads_db")
        if succ(G, fn, "CONTACTS"):
            tag(G, fn, "contacts_external")
        for s in d.get("sensitive", []):
            if s.get("category"):
                tag(G, fn, s["category"])
        for _, _, e in out_edges(G, fn, "CALLS_API"):
            cat = call_category(e.get("target", ""))
            if cat:
                tag(G, fn, cat)
        for c in d.get("external_calls", []):
            cat = call_category(c.get("target") or "")
            if cat:
                tag(G, fn, cat)
                if not any(s.get("target") == c.get("target") for s in d.get("sensitive", [])):
                    d["sensitive"].append({"category": cat, "target": c.get("target"), "line": c.get("line")})

    # propagate: function -> file -> module
    for f in nodes_of(G, "File"):
        for child in succ(G, f, "CONTAINS"):
            tag(G, f, *[t for t in G.nodes[child].get("tags", []) if t != "module_level"])
        if G.nodes[f].get("dynamic_imports"):
            tag(G, f, "dynamic_import")
    for m in nodes_of(G, "Module"):
        for f in succ(G, m, "CONTAINS"):
            tag(G, m, *[t for t in G.nodes[f].get("tags", []) if t not in ("not_indexed",)])


# --------------------------------------------------------------------------- 6. centrality

def centrality(G: nx.MultiDiGraph) -> dict[str, float]:
    D = module_graph(G, include_tests=False)
    if D.number_of_nodes() == 0:
        return {}
    pr = nx.pagerank(D, weight="weight") if D.number_of_edges() else {n: 1 / D.number_of_nodes() for n in D}
    for m, score in pr.items():
        G.nodes[m]["centrality"] = round(score, 4)
    if D.number_of_edges():
        k = max(1, math.ceil(0.2 * len(pr)))
        for m, _ in sorted(pr.items(), key=lambda x: -x[1])[:k]:
            tag(G, m, "core")
    return pr


def run_structural(G: nx.MultiDiGraph, code_index: dict) -> dict:
    link_packages(G, code_index)
    summary = detect_modules(G)
    summary["cycles"] = module_dependencies(G)
    declared_vs_used(G)
    tag_functions(G)
    summary["centrality"] = centrality(G)
    return summary
