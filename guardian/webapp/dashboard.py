"""The dashboard bundle (``ui/``): the Stage 3 ``ui_bundle.json`` plus everything the dashboard needs to explain a
repository and its security picture, built from the scan files on request (old scans work without a re-scan):

* ``about`` / ``stack``: what the repo is and what it is built with (languages, frameworks, services, CI, images)
* ``security``: Stage 4 known vulnerabilities, Stage 5 supply-chain anomalies, and code hotspots (risky calls in
  the repo's own code that no vulnerability database can know about)
* ``sbom``: every package with version, purl, how it got in, and its known vulnerabilities
* ``explorer``: modules, files, functions, routes, packages, services and secrets with the edges between them,
  for the interactive security graph
* ``flows``: a short, evidence-based explanation of how requests move through the code
"""
from __future__ import annotations

import ast
import json
import os
import re
from pathlib import Path
from typing import Any, Optional

RISK_ORDER = {"critical": 3, "high": 2, "medium": 1, "low": 0}
TAG_LABELS = {
    "entry_point": "entry point", "receives_user_input": "user input", "reads_secret_env": "secret access",
    "writes_db": "database write", "reads_db": "database read", "contacts_external": "external service",
    "network": "network", "deserialize": "deserialization", "code_exec": "code execution",
    "subprocess": "subprocess", "core": "core", "in_cycle": "dependency cycle", "crypto": "cryptography",
    "tightly_coupled": "tightly coupled", "dynamic_import": "dynamic import", "file_write": "file write",
    "reachable_from_route": "reachable from a route",
}

# ------------------------------------------------------------------------------------------- languages

LANG_EXT = {
    ".py": "Python", ".pyi": "Python", ".pyx": "Python", ".js": "JavaScript", ".mjs": "JavaScript",
    ".cjs": "JavaScript", ".jsx": "JavaScript", ".ts": "TypeScript", ".tsx": "TypeScript", ".html": "HTML",
    ".htm": "HTML", ".jinja": "HTML", ".jinja2": "HTML", ".j2": "HTML", ".css": "CSS", ".scss": "CSS",
    ".sass": "CSS", ".less": "CSS", ".sh": "Shell", ".bash": "Shell", ".go": "Go", ".java": "Java",
    ".kt": "Kotlin", ".rb": "Ruby", ".php": "PHP", ".rs": "Rust", ".c": "C", ".h": "C", ".cpp": "C++",
    ".cc": "C++", ".hpp": "C++", ".cs": "C#", ".swift": "Swift", ".sql": "SQL", ".vue": "Vue",
    ".svelte": "Svelte", ".dart": "Dart", ".scala": "Scala", ".lua": "Lua", ".pl": "Perl",
    ".ps1": "PowerShell", ".tf": "Terraform", ".ipynb": "Jupyter",
}
SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "env", "__pycache__", "dist", "build", ".tox", ".mypy_cache",
             ".pytest_cache", "site-packages", ".idea", ".vscode", "vendor", "bower_components", ".next", "coverage",
             ".guardian_cache", "output"}
PY_MANIFESTS = ("requirements.txt", "pyproject.toml", "setup.py", "setup.cfg", "Pipfile", "Pipfile.lock",
                "poetry.lock", "requirements.in", "uv.lock")
MAX_WALK = 60000


def detect_languages(repo: Optional[Path]) -> list[dict]:
    """Source files per language (by extension), largest first."""
    if not repo or not Path(repo).is_dir():
        return []
    counts: dict[str, int] = {}
    seen = 0
    for root, dirs, files in os.walk(repo):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
        for f in files:
            lang = LANG_EXT.get(os.path.splitext(f)[1].lower())
            if lang:
                counts[lang] = counts.get(lang, 0) + 1
            seen += 1
        if seen > MAX_WALK:
            break
    total = sum(counts.values()) or 1
    return [{"name": k, "files": v, "pct": round(v * 100 / total, 1)}
            for k, v in sorted(counts.items(), key=lambda kv: -kv[1])]


def python_manifests(repo: Path) -> list[str]:
    found = []
    for base in (repo, *[p for p in repo.iterdir() if p.is_dir() and p.name not in SKIP_DIRS]):
        try:
            for f in base.iterdir():
                if f.is_file() and (f.name in PY_MANIFESTS or re.fullmatch(r"requirements[\w.-]*\.(txt|in)", f.name)):
                    found.append(str(f.relative_to(repo)).replace("\\", "/"))
        except OSError:
            continue
    return found


def not_python_reason(repo: Path) -> Optional[str]:
    """Why Guardian cannot analyse ``repo`` (it reads Python manifests and Python source), or None if it can."""
    langs = detect_languages(repo)
    py = next((l for l in langs if l["name"] == "Python"), None)
    code_langs = [l for l in langs if l["name"] not in ("HTML", "CSS", "SQL", "Shell", "PowerShell")]
    main = code_langs[0]["name"] if code_langs else (langs[0]["name"] if langs else None)
    if python_manifests(repo) or (py and main == "Python"):
        return None
    if py and py["files"] >= 20:
        return None
    what = f"mainly {main} ({code_langs[0]['files']} files)" if main and code_langs else "has no recognised source code"
    return (f"This repository is {what} and has {py['files'] if py else 0} Python file(s) and no Python dependency "
            f"manifest (requirements.txt, pyproject.toml, setup.py, Pipfile, poetry.lock). Guardian analyses Python "
            f"repositories, so a scan would find almost nothing. Try a Python project, for example "
            f"https://github.com/miguelgrinberg/microblog.")


# ------------------------------------------------------------------------------------------- tech stack

STACK_GROUPS: list[tuple[str, tuple[str, ...]]] = [
    ("Web framework", ("flask", "django", "fastapi", "starlette", "tornado", "bottle", "pyramid", "sanic", "quart",
                       "falcon", "aiohttp", "werkzeug", "djangorestframework", "flask-restful", "flask-restx")),
    ("Database & ORM", ("sqlalchemy", "flask-sqlalchemy", "psycopg2", "psycopg2-binary", "psycopg", "pymysql",
                        "mysqlclient", "alembic", "flask-migrate", "peewee", "pymongo", "motor", "tortoise-orm",
                        "sqlmodel", "asyncpg", "aiosqlite", "mongoengine")),
    ("Search, cache & queues", ("elasticsearch", "redis", "rq", "celery", "kombu", "dramatiq", "apscheduler",
                                "pika", "kafka-python", "confluent-kafka", "opensearch-py", "pymemcache")),
    ("Auth & security", ("pyjwt", "flask-login", "flask-httpauth", "passlib", "bcrypt", "cryptography", "authlib",
                         "oauthlib", "itsdangerous", "flask-jwt-extended", "python-jose", "argon2-cffi",
                         "flask-cors", "flask-talisman", "pyotp", "defusedxml")),
    ("Email & messaging", ("flask-mail", "aiosmtpd", "sendgrid", "twilio", "email-validator", "slack-sdk")),
    ("HTTP & APIs", ("requests", "httpx", "urllib3", "grpcio", "boto3", "botocore", "google-cloud-storage")),
    ("Templates, forms & i18n", ("jinja2", "wtforms", "flask-wtf", "markupsafe", "flask-babel", "babel",
                                 "flask-moment", "langdetect", "markdown", "bleach")),
    ("Data & ML", ("numpy", "pandas", "scikit-learn", "scipy", "joblib", "torch", "tensorflow", "matplotlib",
                   "transformers", "pillow")),
    ("Config & serialization", ("pyyaml", "python-dotenv", "marshmallow", "pydantic", "toml", "ujson", "orjson",
                                "simplejson", "msgpack")),
    ("Servers", ("gunicorn", "uwsgi", "uvicorn", "waitress", "hypercorn", "gevent", "eventlet")),
    ("Testing & tooling", ("pytest", "coverage", "flake8", "black", "mypy", "tox", "pylint", "ruff", "isort",
                           "pytest-cov", "nose", "mock", "faker", "factory-boy")),
]
GROUP_OF = {name: grp for grp, names in STACK_GROUPS for name in names}


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", (name or "").lower())


# ------------------------------------------------------------------------------------------- helpers

def _read(p: Path, default=None):
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return default


def _lst(v) -> list:
    """Node attributes of some node types come back from graph.json as Python-literal strings."""
    if isinstance(v, list):
        return v
    if isinstance(v, str) and v.startswith("["):
        try:
            r = ast.literal_eval(v)
            return r if isinstance(r, list) else []
        except (ValueError, SyntaxError):
            return []
    return []


def _int(v) -> Optional[int]:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _risk_max(a: Optional[str], b: Optional[str]) -> Optional[str]:
    if not a:
        return b
    if not b:
        return a
    return a if RISK_ORDER.get(a, -1) >= RISK_ORDER.get(b, -1) else b


def _clean_md(text: str) -> str:
    t = re.sub(r"!\[[^\]]*\]\([^)]*\)", "", text or "")
    t = re.sub(r"\[\s*\]\([^)]*\)", "", t)
    t = re.sub(r"\[([^\]]+)\]\([^)]*$", r"\1", t)          # link cut off by the excerpt
    t = re.sub(r"^\s*>\s?", "", t, flags=re.M)
    t = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", t)
    t = re.sub(r"<[^>]+>", "", t)
    t = re.sub(r"[`*_]{1,3}", "", t)
    lines = [l.strip() for l in t.splitlines()]
    paras, cur = [], []
    for l in lines:
        if not l or l.startswith("#") or l.startswith("[!") or set(l) <= set("=-|: "):
            if cur:
                paras.append(" ".join(cur))
                cur = []
            continue
        cur.append(l)
    if cur:
        paras.append(" ".join(cur))
    paras = [p for p in paras if len(p) > 30]
    return " ".join(paras[:2])[:600]


def _sentences(text: str, n: int) -> str:
    parts = re.split(r"(?<=[.!?])\s+", (text or "").strip())
    return " ".join(parts[:n])


# ------------------------------------------------------------------------------------------- build

_CACHE: dict[str, tuple[tuple, dict]] = {}


def build_dashboard(out: str | Path, meta: Optional[dict] = None) -> dict:
    out = Path(out)
    key_files = ("graph.json", "ui_bundle.json", "vuln_findings.json", "anomaly_findings.json", "triage.json",
                 "scan.json")
    stamp = tuple((out / f).stat().st_mtime if (out / f).exists() else 0 for f in key_files)
    hit = _CACHE.get(str(out.resolve()))
    if hit and hit[0] == stamp:
        return hit[1]
    bundle = _build(out, meta or {})
    _CACHE[str(out.resolve())] = (stamp, bundle)
    return bundle


def _build(out: Path, meta: dict) -> dict:
    from guardian.stage3_knowledge.api import load_context
    from guardian.stage3_knowledge.graph_builder import nodes_of, pred, succ
    from guardian.stage3_knowledge.schema import short_label

    ctx = load_context(out)
    G = ctx.G
    bundle = _read(out / "ui_bundle.json")
    if bundle is None:
        from guardian.stage3_knowledge.export import ui_bundle
        bundle = ui_bundle(ctx, _read(out / "coverage.json", {}))
    vcards = _read(out / "vuln_findings.json", []) or []
    acards = _read(out / "anomaly_findings.json", []) or []
    facts = ctx.facts or {}
    repo_node = G.nodes[nodes_of(G, "Repo")[0]] if nodes_of(G, "Repo") else {}
    repo_path = G.graph.get("repo_path") or meta.get("repo_path")
    repo_dir = Path(repo_path) if repo_path and Path(repo_path).is_dir() else None

    # ---------------------------------------------------------------- structure maps
    mod_of_file: dict[str, str] = {}
    for m in nodes_of(G, "Module"):
        for f in succ(G, m, "CONTAINS"):
            mod_of_file[f] = m
    file_of: dict[str, str] = {}
    for f in nodes_of(G, "File"):
        for c in succ(G, f, "CONTAINS"):
            file_of[c] = f
    mod_of = lambda n: mod_of_file.get(file_of.get(n, n))
    handler_of = {r: (succ(G, r, "HANDLES") or [None])[0] for r in nodes_of(G, "Route") + nodes_of(G, "CLIEntry")}
    routes_of_fn: dict[str, list[str]] = {}
    for r, h in handler_of.items():
        if h:
            routes_of_fn.setdefault(h, []).append(r)

    # ---------------------------------------------------------------- risk on nodes
    risk: dict[str, str] = {}
    fids: dict[str, list[str]] = {}

    def mark(n: Optional[str], r: str, fid: str):
        if not n:
            return
        risk[n] = _risk_max(risk.get(n), r)
        fids.setdefault(n, [])
        if fid not in fids[n]:
            fids[n].append(fid)

    for c in vcards:
        mark(c.get("component"), c["project_risk"], c["finding_id"])
        for s in c.get("usage_sites") or []:
            mark(s.get("function"), c["project_risk"], c["finding_id"])
        for e in c.get("entries") or []:
            mark(e.get("id"), c["project_risk"], c["finding_id"])
    for c in acards:
        mark(c.get("component"), c["project_risk"], c["finding_id"])
        for s in c.get("signals") or []:
            fn = (s.get("data") or {}).get("function") if isinstance(s, dict) else None
            if fn in G:
                mark(fn, c["project_risk"], c["finding_id"])
    for n in list(risk):  # roll up to file and module
        if n.startswith(("fn:", "class:")):
            mark(file_of.get(n), risk[n], fids[n][0])
            mark(mod_of(n), risk[n], fids[n][0])
        elif n.startswith("file:"):
            mark(mod_of_file.get(n), risk[n], fids[n][0])

    # ---------------------------------------------------------------- code hotspots (first-party code)
    HOT = {
        "subprocess": ("Runs an operating-system command", "Command injection if request data or other untrusted "
                       "input can reach the command string."),
        "code_exec": ("Executes code dynamically (eval/exec)", "Code injection if untrusted input reaches it."),
        "deserialize": ("Deserializes data (pickle, yaml, marshal)", "Unsafe with untrusted data: it can run code."),
        "network": ("Makes an outbound network request", "Server-side request forgery (SSRF) if the URL or host comes "
                    "from user input; data leaves the system."),
        "file_write": ("Writes to the file system", "Path traversal or overwrite if the path comes from user input."),
        "crypto": ("Uses cryptography or hashing", "Check algorithm choice, key handling and randomness."),
        "dynamic_import": ("Imports code chosen at run time", "Arbitrary module loading if the name is untrusted."),
        "sql_raw": ("Builds raw SQL", "SQL injection if strings are concatenated with user input."),
    }
    hotspots = []
    for n, d in G.nodes(data=True):
        if d.get("type") != "Function":
            continue
        cats: dict[str, list] = {}
        for s in _lst(d.get("sensitive")):
            if isinstance(s, dict) and s.get("category") in HOT:
                cats.setdefault(s["category"], []).append(s)
        for cat, calls in cats.items():
            reach = _lst(d.get("reachable_from")) or routes_of_fn.get(n, [])
            public = [r for r in reach if str(r).startswith("route:")]
            inputs = "receives_user_input" in (d.get("tags") or [])
            level = "high" if public and cat in ("subprocess", "code_exec", "deserialize", "sql_raw") else \
                "medium" if public or inputs else "low"
            hotspots.append({
                "id": f"H-{len(hotspots) + 1:03d}", "function": n,
                "label": f"{d.get('file')} (top-level code)" if str(n).endswith("::<module>") else short_label(n), "file": d.get("file"),
                "line": _int(calls[0].get("line")) or _int(d.get("line")), "category": cat, "what": HOT[cat][0],
                "why": HOT[cat][1], "calls": sorted({c.get("target") for c in calls if c.get("target")})[:5],
                "lines": sorted({_int(c.get("line")) for c in calls if _int(c.get("line"))}),
                "reachableFrom": [str(r).split(":", 1)[1] for r in reach][:8], "public": bool(public),
                "userInput": inputs, "level": level, "module": mod_of(n),
            })
    hotspots.sort(key=lambda h: (-RISK_ORDER[h["level"]], h["file"] or "", h["line"] or 0))
    for i, h in enumerate(hotspots, 1):
        h["id"] = f"H-{i:03d}"
        if h["level"] != "low":
            mark(h["function"], "medium" if h["level"] == "high" else "low", h["id"])

    # ---------------------------------------------------------------- explorer graph
    nodes: list[dict] = []
    seen: set[str] = set()
    bundle_mods = {m["id"]: m for m in bundle.get("modules", [])}

    def add(n: str, **extra):
        if n in seen or n not in G:
            return
        seen.add(n)
        d = G.nodes[n]
        node = {"id": n, **extra}
        if risk.get(n):
            node["risk"] = risk[n]
            node["findings"] = fids.get(n, [])[:12]
        nodes.append(node)

    for m in sorted(nodes_of(G, "Module")):
        d, bm = G.nodes[m], bundle_mods.get(m, {})
        card = d.get("card") if isinstance(d.get("card"), dict) else {}
        add(m, t="module", l=d.get("name") or m, path=d.get("path"), purpose=bm.get("purpose") or card.get("purpose"),
            tags=bm.get("tags") or [TAG_LABELS[t] for t in _lst(d.get("tags")) if t in TAG_LABELS],
            color=bm.get("color", "violet"), files=len(_lst(d.get("files"))), tests=d.get("kind") == "tests",
            sensitivity=bm.get("sensitivity"))
    for f in sorted(nodes_of(G, "File")):
        d = G.nodes[f]
        card = d.get("card") if isinstance(d.get("card"), dict) else {}
        add(f, t="file", l=d.get("path") or f, m=mod_of_file.get(f), loc=_int(d.get("loc")),
            purpose=card.get("purpose"), test=bool(d.get("is_test")))
    score_of: dict[str, int] = {}
    for n, d in G.nodes(data=True):
        if d.get("type") not in ("Function", "Class"):
            continue
        tags = _lst(d.get("tags"))
        card = d.get("card") if isinstance(d.get("card"), dict) else {}
        score = (8 if n in routes_of_fn else 0) + 6 * (RISK_ORDER.get(risk.get(n), -1) + 1) + \
            3 * len(set(tags) & {"contacts_external", "subprocess", "code_exec", "deserialize", "writes_db",
                                 "network", "file_write", "crypto"}) + G.in_degree(n) + G.out_degree(n) // 3
        score_of[n] = score
        doc = d.get("docstring") if isinstance(d.get("docstring"), str) and d.get("docstring") != "None" else None
        label = f"{d.get('file')} (top-level code)" if str(n).endswith("::<module>") else short_label(n)
        add(n, t="function" if d.get("type") == "Function" else "class", l=label, f=d.get("file"),
            ln=_int(d.get("line")), end=_int(d.get("end_line")), m=mod_of(n), file=file_of.get(n),
            tags=[TAG_LABELS[t] for t in tags if t in TAG_LABELS], purpose=card.get("purpose"),
            doc=(doc or "").strip().split("\n")[0][:200] or None, score=score, top=bool(d.get("module_level")),
            params=[p if isinstance(p, str) else p.get("name") for p in _lst(d.get("params"))][:8])
    for r in sorted(nodes_of(G, "Route")) + sorted(nodes_of(G, "CLIEntry")):
        d = G.nodes[r]
        add(r, t="route" if r.startswith("route:") else "cli", l=r.split(":", 1)[1], h=handler_of.get(r),
            method=d.get("method"), framework=d.get("framework"), f=d.get("file"), ln=_int(d.get("line")),
            m=mod_of(handler_of.get(r)) if handler_of.get(r) else None)
    for p in sorted(nodes_of(G, "Package")):
        d = G.nodes[p]
        add(p, t="package", l=d.get("name") or short_label(p), v=d.get("version") or d.get("checked_version"),
            direct=bool(d.get("direct")), used=bool(_lst(d.get("used_by_files"))), dev=bool(d.get("dev")))
    for s in sorted(nodes_of(G, "ExternalService")):
        d = G.nodes[s]
        add(s, t="service", l=d.get("name") or short_label(s), via=d.get("via"))
    for e in sorted(nodes_of(G, "EnvVar")):
        d = G.nodes[e]
        add(e, t="env", l=d.get("name") or short_label(e), secret=bool(d.get("secret_like")))
    for tb in sorted(nodes_of(G, "Table")):
        add(tb, t="table", l=short_label(tb))

    edges: list[list] = []
    uses: dict[tuple[str, str], list[str]] = {}
    for u, v, e in G.edges(data=True):
        t = e.get("type")
        if u not in seen or v not in seen:
            continue
        if t == "CALLS_API":
            uses.setdefault((u, v), [])
            api = e.get("api")
            if api and api not in uses[(u, v)]:
                uses[(u, v)].append(api)
        elif t in ("CALLS", "HANDLES", "CONTACTS", "READS_ENV", "WRITES", "READS"):
            edges.append([u, v, t])
        elif t == "DEPENDS_ON":
            edges.append([u, v, t, e.get("weight", 1)])
        elif t == "CONTAINS" and not u.startswith("repo:"):
            edges.append([u, v, t])
    for (u, v), apis in uses.items():
        edges.append([u, v, "USES", apis[:6]])
    # a file that imports a package without a recorded call still uses it
    called = {(file_of.get(u), v) for (u, v) in uses}
    for f in nodes_of(G, "File"):
        for p in succ(G, f, "USES_PACKAGE"):
            if (f, p) not in called and p in seen:
                edges.append([f, p, "IMPORTS_PKG"])

    # ---------------------------------------------------------------- flows: one explanation per entry point
    paths_by_entry: dict[str, list[dict]] = {}
    for p in ctx.paths or []:
        paths_by_entry.setdefault(p["entry"], []).append(p)
    vuln_by_route: dict[str, list[str]] = {}
    for c in vcards:
        for e in c.get("entries") or []:
            vuln_by_route.setdefault(e.get("id"), []).append(c["finding_id"])
    routes_out = []
    for r, h in handler_of.items():
        ps = paths_by_entry.get(r, [])
        steps = list(dict.fromkeys(s for p in ps for s in p.get("steps", [])))
        if h and h not in steps:
            steps.insert(0, h)
        sinks = list(dict.fromkeys(s for p in ps for s in p.get("sinks", [])))
        pk = [G.nodes[s].get("name") for s in sinks if s.startswith("pkg:") and s in G] +             [G.nodes[v].get("name") for (u, v) in uses if u in steps[:6] and v in G]
        svcs = [G.nodes[s].get("name") for s in sinks if s.startswith("svc:") and s in G] +             [G.nodes[v].get("name") for s in steps[:6] if s in G for v in succ(G, s, "CONTACTS")]
        envs = sorted({short_label(v) for s in steps if s in G for v in succ(G, s, "READS_ENV")})
        tags = {t for s in steps if s in G for t in _lst(G.nodes[s].get("tags"))}
        inp = next((p.get("input") for p in ps if p.get("input")), None)
        label = r.split(":", 1)[1]
        parts = []
        if h:
            hf = G.nodes[h].get("file")
            parts.append(f"{label} is handled by {short_label(h)} in {hf}" + (f", which reads {inp}" if inp else "") + ".")
        inner = [short_label(s) for s in steps[1:6]]
        if inner:
            parts.append(f"It goes on to call {', '.join(inner)}" + (" and more" if len(steps) > 6 else "") + ".")
        does = []
        if "writes_db" in tags:
            does.append("writes to the database")
        elif "reads_db" in tags:
            does.append("reads the database")
        if svcs:
            does.append(f"contacts {', '.join(dict.fromkeys(svcs))}")
        if envs:
            does.append(f"reads configuration {', '.join(envs[:4])}")
        if does:
            parts.append(f"Along the way it {', '.join(does)}.")
        if pk:
            parts.append(f"Libraries used: {', '.join(list(dict.fromkeys(pk))[:6])}.")
        vf = vuln_by_route.get(r, [])
        routes_out.append({"id": r, "label": label, "handler": h, "steps": steps, "sinks": sinks, "input": inp,
                           "text": " ".join(parts) or f"{label}: no handler was resolved.", "findings": vf,
                           "risk": risk.get(r)})

    # ---------------------------------------------------------------- narrative: the whole app in a few steps
    narrative = []
    real_routes = [r for r in handler_of if r.startswith("route:")]
    clis = [r for r in handler_of if not r.startswith("route:")]
    entry_mods: dict[str, int] = {}
    for r in handler_of:
        m = mod_of(handler_of[r]) if handler_of[r] else None
        if m:
            entry_mods[m] = entry_mods.get(m, 0) + 1
    fw = sorted({G.nodes[r].get("framework") for r in real_routes if G.nodes[r].get("framework")})
    if handler_of:
        mods_txt = ", ".join(f"{G.nodes[m].get('name')} ({k})" for m, k in sorted(entry_mods.items(), key=lambda kv: -kv[1]))
        narrative.append({"title": "Entry points", "text":
                          f"Requests enter through {len(real_routes)} HTTP route(s)"
                          + (f" ({', '.join(f.capitalize() for f in fw)})" if fw else "")
                          + (f" and {len(clis)} command-line entry point(s)" if clis else "")
                          + (f", handled in {mods_txt}." if mods_txt else "."), "refs": list(entry_mods)})
    else:
        narrative.append({"title": "Entry points", "text": "No HTTP routes or CLI commands were detected; the code is "
                          "used as a library or through scripts.", "refs": []})
    called_mods: dict[str, int] = {}
    for m in entry_mods:
        for v in succ(G, m, "DEPENDS_ON"):
            if v not in entry_mods:
                called_mods[v] = called_mods.get(v, 0) + 1
    if called_mods:
        top = sorted(called_mods, key=lambda m: (-called_mods[m], G.nodes[m].get("name", "")))[:6]
        desc = []
        for m in top:
            purpose = _sentences((bundle_mods.get(m) or {}).get("purpose", ""), 1)
            desc.append(f"{G.nodes[m].get('name')}" + (f" ({purpose.rstrip('.')})" if purpose and len(purpose) < 90 else ""))
        narrative.append({"title": "Core logic", "text": "Handlers rely on " + "; ".join(desc) + ".", "refs": top})
    data_mods: dict[str, set] = {}
    for n, d in G.nodes(data=True):
        if d.get("type") in ("Function", "Class"):
            tg = set(_lst(d.get("tags")))
            if tg & {"writes_db", "reads_db"} and mod_of(n):
                data_mods.setdefault(mod_of(n), set()).update(tg & {"writes_db", "reads_db"})
    orm = [G.nodes[p].get("name") for p in nodes_of(G, "Package") if _norm(G.nodes[p].get("name", "")) in
           ("sqlalchemy", "flask-sqlalchemy", "django", "peewee", "pymongo", "psycopg2", "psycopg2-binary", "pymysql",
            "sqlmodel", "tortoise-orm", "mongoengine")]
    if data_mods:
        top = sorted(data_mods, key=lambda m: -len(data_mods[m]))[:5]
        narrative.append({"title": "Data", "text": "Database access happens in " + ", ".join(
            G.nodes[m].get("name") for m in top) + (f" using {', '.join(orm[:3])}" if orm else "") + ".", "refs": top})
    svc_mods: dict[str, set] = {}
    for u, v, e in G.edges(data=True):
        if e.get("type") == "CONTACTS" and mod_of(u):
            svc_mods.setdefault(v, set()).add(G.nodes[mod_of(u)].get("name"))
    if svc_mods:
        narrative.append({"title": "Outside systems", "text": "The code talks to " + "; ".join(
            f"{G.nodes[s].get('name')} (from {', '.join(sorted(ms))})" for s, ms in sorted(svc_mods.items())) + ".",
            "refs": sorted(svc_mods)})
    secrets = [e for e in nodes_of(G, "EnvVar") if G.nodes[e].get("secret_like")]
    if secrets:
        readers = sorted({G.nodes[mod_of(u)].get("name") for e in secrets for u in pred(G, e, "READS_ENV") if mod_of(u)})
        narrative.append({"title": "Secrets & configuration", "text":
                          f"{len(secrets)} secret-like setting(s) are read from the environment"
                          + (f" in {', '.join(readers)}" if readers else "") + ": "
                          + ", ".join(G.nodes[e].get("name") for e in secrets[:8]) + ".", "refs": secrets[:8]})
    reach_v = [c for c in vcards if c.get("usage") == "symbol_called" and RISK_ORDER[c["project_risk"]] >= 1]
    if reach_v:
        c = sorted(reach_v, key=lambda c: -RISK_ORDER[c["project_risk"]])[0]
        site = (c.get("usage_sites") or [{}])[0]
        narrative.append({"title": "Where security matters most", "text":
                          f"{c['component_name']} {c['component_version']} ({c['vuln_id']}, {c['project_risk']} risk) "
                          f"is called from {short_label(site.get('function', ''))} in {site.get('file')}"
                          + (f", reachable from {', '.join(e['label'] for e in (c.get('entries') or [])[:3])}"
                             if c.get("entries") else "") + ".",
                          "refs": [x for x in [site.get("function"), c.get("component")] if x],
                          "finding": c["finding_id"]})
    elif hotspots:
        h = hotspots[0]
        narrative.append({"title": "Where security matters most", "text":
                          f"{h['label']} in {h['file']} {h['what'].lower()} ({', '.join(h['calls'][:2])}). {h['why']}",
                          "refs": [h["function"]], "finding": h["id"]})

    # ---------------------------------------------------------------- SBOM
    vulns_of_pkg: dict[str, list[dict]] = {}
    for c in vcards:
        vulns_of_pkg.setdefault(c["component"], []).append(
            {"id": c["finding_id"], "vulnId": c["vuln_id"], "risk": c["project_risk"], "cvss": (c.get("severity") or {}).get("cvss"),
             "band": (c.get("severity") or {}).get("band"), "fix": c.get("recommendation")})
    anom_of_pkg: dict[str, list[str]] = {}
    for c in acards:
        anom_of_pkg.setdefault(c["component"], []).append(c["finding_id"])
    br_of = {p["name"]: p for p in bundle.get("packages", [])}
    sbom = []
    for p in sorted(nodes_of(G, "Package"), key=lambda p: (G.nodes[p].get("name") or p).lower()):
        d = G.nodes[p]
        ev = next((e for e in _lst(d.get("evidence")) if isinstance(e, dict) and e.get("file")), None)
        users = _lst(d.get("used_by_files"))
        fns_using = sorted({u for u, v in uses if v == p})
        vl = sorted(vulns_of_pkg.get(p, []), key=lambda x: (-RISK_ORDER[x["risk"]], -(x["cvss"] or 0)))
        br = br_of.get(d.get("name")) or {}
        sbom.append({
            "id": p, "name": d.get("name"), "version": d.get("version") or d.get("checked_version") or "?",
            "purl": d.get("purl") or p, "direct": bool(d.get("direct")), "dev": bool(d.get("dev")),
            "scope": "dev" if d.get("dev") else (d.get("scope") or "prod"), "kind": d.get("dep_kind") or "registry",
            "declaredIn": f"{ev['file']}:{ev.get('line')}" if ev and ev.get("line") else (ev or {}).get("file"),
            "spec": ", ".join(_lst(d.get("declared_spec"))), "requiredBy": [short_label(x) for x in pred(G, p, "REQUIRES")][:6]
            or _lst(d.get("required_by"))[:6],
            "requires": len(_lst(d.get("requires"))), "hashes": bool(_lst(d.get("hashes"))), "usedByFiles": len(users),
            "functions": fns_using[:40], "vulns": vl, "anomalies": anom_of_pkg.get(p, []),
            "risk": _risk_max(vl[0]["risk"] if vl else None, risk.get(p) if p in risk else None),
            "group": GROUP_OF.get(_norm(d.get("name"))), "radius": br.get("radius"), "reasons": br.get("reasons", []),
            "routes": br.get("routes", []), "nearby": br.get("nearby", []),
        })

    # ---------------------------------------------------------------- tech stack
    langs = detect_languages(repo_dir)
    if not langs:
        n_py = (ctx.code_index or {}).get("files") or []
        langs = [{"name": "Python", "files": len(n_py), "pct": 100.0}] if n_py else []
    groups: dict[str, list[dict]] = {}
    for s in sbom:
        if s["group"]:
            groups.setdefault(s["group"], []).append({"name": s["name"], "version": s["version"], "id": s["id"],
                                                      "kind": "package", "risk": s["risk"]})
    prio = {name: i for _, names in STACK_GROUPS for i, name in enumerate(names)}
    for items in groups.values():
        items.sort(key=lambda x: prio.get(_norm(x["name"]), 99))
    others = [s for s in sbom if not s["group"] and s["direct"]]
    services = [{"name": G.nodes[s].get("name"), "id": s, "kind": "service", "via": G.nodes[s].get("via")}
                for s in sorted(nodes_of(G, "ExternalService"))]
    images = [{"name": b.get("ref"), "kind": "image", "file": c.get("file")} for c in facts.get("containers", [])
              for b in c.get("base_images", [])]
    ci = [{"name": w.get("file"), "kind": "ci"} for w in facts.get("ci_workflows", [])]
    order = [g for g, _ in STACK_GROUPS]
    frameworks = sorted({G.nodes[r].get("framework") for r in nodes_of(G, "Route") if G.nodes[r].get("framework")})
    headline = [l["name"] for l in langs[:1]] + [f.capitalize() for f in frameworks] + \
        [x["name"] for x in groups.get("Database & ORM", [])[:1]] + [x["name"] for x in services[:2]]
    stack = {
        "languages": langs[:8], "headline": list(dict.fromkeys(h for h in headline if h)),
        "groups": [{"name": g, "items": groups[g]} for g in order if g in groups]
        + ([{"name": "Other libraries", "items": [{"name": s["name"], "version": s["version"], "id": s["id"],
                                                    "kind": "package", "risk": s["risk"]} for s in others]}] if others else []),
        "services": services, "images": images, "ci": ci, "frameworks": frameworks,
    }

    # ---------------------------------------------------------------- about
    readme = _clean_md(repo_node.get("readme_excerpt") or "")
    purpose = (bundle.get("repo") or {}).get("summary") or ""
    first = _sentences(purpose, 1)
    about = readme or first
    py_share = next((l["pct"] for l in langs if l["name"] == "Python"), 0)
    warning = None
    if repo_dir and (not langs or py_share < 15) and not python_manifests(repo_dir):
        warning = not_python_reason(repo_dir)

    # ---------------------------------------------------------------- security
    def vrow(c):
        sites = c.get("usage_sites") or []
        return {"id": c["finding_id"], "kind": "vulnerability", "title": c["title"], "risk": c["project_risk"],
                "package": c.get("component_name"), "version": c.get("component_version"), "component": c["component"],
                "vulnId": c.get("vuln_id"), "aliases": c.get("aliases") or [], "cvss": (c.get("severity") or {}).get("cvss"),
                "band": (c.get("severity") or {}).get("band"), "vector": (c.get("severity") or {}).get("vector"),
                "kev": c.get("kev"), "epss": c.get("epss_percentile"), "scope": c.get("scope"), "usage": c.get("usage"),
                "reachability": c.get("reachability"), "confidence": c.get("confidence"),
                "sites": [{"function": s.get("function"), "label": short_label(s.get("function") or ""), "file": s.get("file"),
                           "lines": s.get("lines"), "code": s.get("code"), "symbol": s.get("symbol")} for s in sites][:8],
                "entries": [e.get("label") or e.get("id") for e in c.get("entries") or []][:10],
                "entryIds": [e.get("id") for e in c.get("entries") or []][:10],
                "path": c.get("dependency_path") or [], "explanation": c.get("explanation"),
                "recommendation": c.get("recommendation"), "unknowns": c.get("unknowns") or [],
                "rule": (c.get("rule") or {}).get("text"), "review": (c.get("review") or {}).get("status")}

    def arow(c):
        ev = [{"file": e.get("file"), "lines": e.get("lines"), "detail": e.get("detail") or e.get("snippet")}
              for e in c.get("evidence") or [] if isinstance(e, dict)]
        fn = next(((s.get("data") or {}).get("function") for s in c.get("signals") or []
                   if isinstance(s, dict) and (s.get("data") or {}).get("function") in G), None)
        return {"id": c["finding_id"], "kind": "anomaly", "title": c["title"], "risk": c["project_risk"],
                "component": c["component"], "componentName": c.get("component_name"), "suspicion": c.get("suspicion"),
                "exposure": c.get("exposure"), "exposureNote": c.get("exposure_note"), "capability": c.get("capability"),
                "detectors": c.get("detectors") or [], "explanation": c.get("explanation"),
                "recommendation": c.get("recommendation"), "evidence": ev[:8], "confidence": c.get("confidence"),
                "normal": c.get("normal_explanation"), "review": (c.get("review") or {}).get("status"), "function": fn}

    # ---- commits that touched a node (CHANGED_IN edges), newest first
    def commit_info(cid: str) -> dict:
        d = G.nodes[cid]
        return {"sha": (d.get("sha") or cid.split(":", 1)[-1])[:7], "date": str(d.get("date") or "")[:10],
                "message": (d.get("message") or "").split("\n")[0][:120]}

    def commits_of(*ids) -> list[dict]:
        seen_c, res = set(), []
        for n in ids:
            if n and n in G:
                for cid in succ(G, n, "CHANGED_IN"):
                    if cid not in seen_c:
                        seen_c.add(cid)
                        res.append(commit_info(cid))
        return sorted(res, key=lambda c: c["date"], reverse=True)

    # ---- how sure we are that a database vulnerability is really present in this code base
    USAGE_PTS = {"symbol_called": (70, "the vulnerable function is called in your code"),
                 "package_used_symbol_unknown": (50, "the package is used; the advisory names no specific function"),
                 "package_used_symbol_not_found": (40, "the package is used, but the vulnerable function was not found"),
                 "package_imported": (45, "the package is imported"),
                 "package_not_imported": (15, "the package is installed but never imported"),
                 "installed_unused": (10, "the package is installed but never imported")}
    REACH_PTS = {"public_path": (20, "a public route reaches the code that uses it"),
                 "internal_only": (8, "only internal code (jobs, CLI, startup) reaches it"),
                 "no_path_found": (0, "no entry point reaches it")}

    def presence(c) -> dict:
        base, why = USAGE_PTS.get(c.get("usage"), (30, f"usage: {str(c.get('usage')).replace('_', ' ')}"))
        rp, rwhy = REACH_PTS.get(c.get("reachability"), (0, f"reachability: {c.get('reachability')}"))
        factors = [{"points": base, "text": why}]
        if c.get("usage") not in ("package_not_imported", "installed_unused"):
            factors.append({"points": rp, "text": rwhy})
        else:
            rp = 0
        ver = c.get("verification") if isinstance(c.get("verification"), dict) else {}
        vp = 5 if ver.get("verified") else 0
        if vp:
            factors.append({"points": vp, "text": "a second check re-read the cited lines and confirmed them"})
        cp = {"low": -5, "high": 5}.get(c.get("confidence"), 0)
        if cp:
            factors.append({"points": cp, "text": f"investigator confidence is {c.get('confidence')}"})
        if c.get("scope") == "dev":
            factors.append({"points": -10, "text": "development-only dependency"})
        score = max(0, min(100, base + rp + vp + cp - (10 if c.get("scope") == "dev" else 0)))
        label = "Confirmed in code" if score >= 80 else "Likely present" if score >= 55 else \
            "Possible" if score >= 35 else "Installed only"
        return {"score": score, "label": label, "factors": factors}

    traces = {**(_read(out / "vuln_traces.json", {}) or {}), **(_read(out / "anomaly_traces.json", {}) or {})}

    def trace_of(fid):
        return [{"stage": t.get("stage"), "action": t.get("action"), "tool": t.get("tool"),
                 "input": json.dumps(t.get("input"), ensure_ascii=False)[:220] if t.get("input") else "",
                 "result": str(t.get("result") or "")[:400], "ok": t.get("ok", True)} for t in traces.get(fid, [])][:40]

    def claims_of(c):
        ver = c.get("verification") if isinstance(c.get("verification"), dict) else {}
        checks = {k.get("text"): k for k in ver.get("checks") or [] if isinstance(k, dict)}
        res = []
        for cl in c.get("claims") or []:
            if not isinstance(cl, dict):
                continue
            chk = checks.get(cl.get("text")) or {}
            ev = [f"{e.get('file')}:{e.get('lines') or e.get('line') or ''}".rstrip(":") for e in cl.get("evidence") or []
                  if isinstance(e, dict) and e.get("file")]
            res.append({"text": cl.get("text"), "verified": bool(cl.get("verified", chk.get("ok"))), "evidence": ev[:4],
                        "lines": [str(x)[:160] for x in (chk.get("lines") or [])][:3], "reason": chk.get("reason")})
        return res[:10]

    vrows, arows = [], []
    for c in vcards:
        r = vrow(c)
        r.update({"presence": presence(c), "fixed": (c.get("fixed_versions") or [])[:4], "summary": c.get("summary"),
                  "details": (c.get("details") or "")[:1200], "published": str(c.get("published") or "")[:10],
                  "references": [x if isinstance(x, str) else x.get("url") for x in (c.get("references") or [])][:5],
                  "claims": claims_of(c), "trace": trace_of(c["finding_id"]), "confidenceReasons": c.get("confidence_reasons") or [],
                  "commits": commits_of(c["component"], *[s.get("file") and f"file:{s['file']}" for s in c.get("usage_sites") or []])[:4],
                  "files": sorted({s.get("file") for s in c.get("usage_sites") or [] if s.get("file")})})
        vrows.append(r)
    for c in acards:
        r = arow(c)
        r.update({"claims": claims_of(c), "trace": trace_of(c["finding_id"]), "commit": c.get("commit"),
                  "signals": [{"detector": s.get("detector"), "check": (s.get("check") or "").replace("_", " "),
                               "strength": s.get("strength"), "text": s.get("text")} for s in c.get("signals") or []
                              if isinstance(s, dict)][:8],
                  "confidenceReasons": c.get("confidence_reasons") or [],
                  "commits": commits_of(c["component"])[:4]})
        arows.append(r)

    # ---- connections between the vulnerability report and the suspicious report
    by_comp: dict[str, list[str]] = {}
    for x in vrows + arows:
        by_comp.setdefault(x["component"], []).append(x["id"])
    for x in vrows + arows:
        others = [i for i in by_comp[x["component"]] if i != x["id"]]
        conn = [{"kind": "anomaly", "id": i} for i in others if i.startswith("A-")]
        conn += [{"kind": "commit", "label": f"{cm['sha']} {cm['message']}", "date": cm["date"]} for cm in x.get("commits", [])[:3]]
        if x["kind"] == "vulnerability":
            conn += [{"kind": "hotspot", "id": h["id"]} for h in hotspots if h["function"] in {s["function"] for s in x["sites"]}]
        conn += [{"kind": "vulnerability", "id": i} for i in others if i.startswith("F-")][:3]
        x["connections"] = conn
        x["siblings"] = len([i for i in others if i.startswith("F-")])

    # ---- suspicious report: recent changes worth a look (from the time-travel diff)
    FLAG = {("package", "Package"): "new dependency", ("network", "ExternalService"): "new outbound destination",
            ("network", "CONTACTS"): "new network call", ("entry", "Route"): "new HTTP route",
            ("module", "Module"): "new module", ("ci", "Image"): "new container image", ("ci", "Action"): "new CI action",
            ("secret", "EnvVar"): "new secret read"}
    flagged_by_commit: dict[str, list[dict]] = {}
    for it in (ctx.changes or {}).get("items", []):
        f = FLAG.get((it.get("category"), it.get("type")))
        if f and it.get("op") == "+":
            flagged_by_commit.setdefault(str(it.get("commit"))[:7], []).append(
                {"flag": f, "label": it.get("label", "").lstrip("+ ").strip(), "id": it.get("id") if it.get("id") in G else None})
    recent = []
    for cm in sorted((ctx.changes or {}).get("commits", []), key=lambda c: str(c.get("date") or ""), reverse=True):
        fl = flagged_by_commit.get(cm.get("short"), [])
        related = [x["id"] for x in vrows + arows if any(c["sha"] == cm.get("short") for c in x.get("commits", []))]
        recent.append({"sha": cm.get("short"), "date": str(cm.get("date") or "")[:10], "title": cm.get("title"),
                       "author": cm.get("author"), "type": cm.get("type"), "changes": cm.get("item_count", 0),
                       "files": (cm.get("files_changed") or [])[:8], "flags": fl[:12], "findings": related[:8]})
    dep_notes = [{"id": f"N-{i + 1:02d}", **{k: f.get(k) for k in ("title", "category", "text", "evidence", "confidence",
                                                                     "status", "severity")}}
                 for i, f in enumerate(bundle.get("findings", []))]

    allr = vrows + arows
    security = {
        "vulnerabilities": vrows, "anomalies": arows, "hotspots": hotspots, "recent": recent[:12], "notes": dep_notes,
        "byRisk": {r: sum(1 for x in allr if x["risk"] == r) for r in ("critical", "high", "medium", "low")},
        "reachable": sum(1 for v in vrows if v["usage"] == "symbol_called"),
        "pendingReview": sum(1 for x in allr if x.get("review") == "pending"),
        "vulnDbRan": (out / "vuln_findings.json").exists(), "anomalyRan": (out / "anomaly_findings.json").exists(),
        "packagesChecked": len(sbom),
    }

    bundle = dict(bundle)
    repo = dict(bundle.get("repo") or {})
    repo.update({"about": about, "purpose": purpose, "readme": readme, "url": meta.get("repo_url"),
                 "language": langs[0]["name"] if langs else repo.get("language", "Python"),
                 "entryPoints": len(handler_of), "cli": len(clis), "secrets": len(secrets),
                 "services": [s["name"] for s in services], "packagesTotal": len(sbom),
                 "transitive": sum(1 for s in sbom if not s["direct"])})
    bundle.update({"repo": repo, "warning": warning, "stack": stack, "security": security, "sbom": sbom,
                   "explorer": {"nodes": nodes, "edges": edges}, "flows": {"routes": routes_out, "narrative": narrative},
                   "scan": {k: meta.get(k) for k in ("scan_id", "status", "repo_url", "created_at", "error")}
                   if meta else None})
    return bundle
