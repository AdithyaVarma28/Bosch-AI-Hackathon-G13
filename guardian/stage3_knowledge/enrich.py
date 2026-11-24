"""Facts the spec expects from Stage 2 that code_index.json does not carry yet, derived for Stage 3:

* user-input sources (``request.json`` …) on functions  -> ``inputs`` + ``RECEIVES_INPUT``
* external services: SDK imports/calls and URLs used by network calls -> ``CONTACTS``
* database models (``__tablename__``) and DB reads/writes                -> ``Table``, ``MAPS_TO``, ``READS``/``WRITES``

Inputs are the index itself plus, when the repo is available, only the definition line ranges the
index already lists (no rescan, nothing executed). Everything here is ``discovered_by: algorithm``.
If Stage 2 later emits ``input_sources``/``db_access``/``external_services``, graph_builder uses
those directly and this pass only fills gaps.
"""
from __future__ import annotations

import re
from typing import TYPE_CHECKING, Optional
from urllib.parse import urlparse

from .graph_builder import add_edge, add_node, ev, nodes_of, pred, succ, tag
from .schema import svc_id, table_id

if TYPE_CHECKING:
    from .graph_builder import GraphBuilder

# import name (top level) -> external service. SaaS SDKs and network datastores only.
SDK_SERVICES = {
    "stripe": "Stripe", "braintree": "Braintree", "paypalrestsdk": "PayPal", "twilio": "Twilio",
    "sendgrid": "SendGrid", "mailchimp_marketing": "Mailchimp", "boto3": "AWS", "botocore": "AWS",
    "openai": "OpenAI", "anthropic": "Anthropic", "slack_sdk": "Slack", "slack": "Slack",
    "firebase_admin": "Firebase", "sentry_sdk": "Sentry", "mixpanel": "Mixpanel", "analytics": "Segment",
    "github": "GitHub", "gitlab": "GitLab", "auth0": "Auth0", "okta": "Okta", "plaid": "Plaid",
    "redis": "Redis", "pymongo": "MongoDB", "motor": "MongoDB", "psycopg2": "PostgreSQL", "psycopg": "PostgreSQL",
    "asyncpg": "PostgreSQL", "pymysql": "MySQL", "mysql": "MySQL", "elasticsearch": "Elasticsearch",
    "kafka": "Kafka", "confluent_kafka": "Kafka", "pika": "RabbitMQ", "google": "Google Cloud",
    "azure": "Azure", "telegram": "Telegram", "discord": "Discord", "pusher": "Pusher",
}
WEB_FRAMEWORKS = ("flask", "django", "fastapi", "starlette", "werkzeug", "bottle", "tornado", "sanic", "aiohttp")
INPUT_RE = re.compile(r"\brequest\.(json|get_json|args|form|files|values|data|cookies|headers|POST|GET|FILES|"
                      r"body|query_params|path_params|stream|get_data|query)\b")
ARGV_RE = re.compile(r"\bsys\.argv\b|\.parse_args\(|\binput\(")
FASTAPI_SKIP_PARAMS = {"request", "db", "session", "background_tasks", "current_user", "user", "response", "self"}
DB_LIBS = ("sqlalchemy", "flask_sqlalchemy", "django.db", "pymongo", "motor", "psycopg2", "psycopg", "sqlite3",
           "mysql", "pymysql", "peewee", "tortoise", "sqlmodel", "asyncpg", "pony")
WRITE_METHODS = r"add|add_all|delete|merge|commit|flush|bulk_save_objects|bulk_insert_mappings|save|create|" \
                r"bulk_create|bulk_update|get_or_create|update_or_create|insert_one|insert_many|update_one|" \
                r"update_many|delete_one|delete_many|replace_one|executemany|insert|update"
READ_METHODS = r"query|filter|filter_by|scalars|exclude|find|find_one|fetchone|fetchall|fetchmany|raw|select|" \
               r"get_object_or_404|first_or_404|get_or_404"
WRITE_CALL_RE = re.compile(rf"\.(?:{WRITE_METHODS})$")
READ_CALL_RE = re.compile(rf"\.(?:{READ_METHODS})$|\.objects\.(?:get|all|filter)$")
WRITE_SRC_RE = re.compile(rf"\b(?:session|db\.session|cursor|conn|connection|collection|objects|\w+_collection)\."
                          rf"(?:{WRITE_METHODS})\s*\(|\.save\(\s*\)")
READ_SRC_RE = re.compile(rf"\b(?:session|db\.session|cursor|conn|connection|collection|objects|query)\."
                         rf"(?:{READ_METHODS}|get|all|first|one)\s*\(|\.query\.")
SQL_RE = re.compile(r"\b(SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER)\b\s+(?:INTO\s+|FROM\s+)?[\w\"`*]", re.I)
TABLENAME_RE = re.compile(r"__tablename__\s*=\s*['\"]([\w.]+)['\"]")
DB_TABLE_RE = re.compile(r"\bdb_table\s*=\s*['\"]([\w.]+)['\"]")
DJANGO_MODEL_RE = re.compile(r"^\s*class\s+(\w+)\s*\([^)]*\bmodels\.Model\b")


class _Src:
    """Lines of definitions, read once per file and only when the repo is available."""

    def __init__(self, source) -> None:
        self.source = source
        self.cache: dict[str, Optional[list[str]]] = {}

    def lines(self, path: str, start: int, end: int) -> list[tuple[int, str]]:
        if not self.source or not self.source.available:
            return []
        if path not in self.cache:
            try:
                self.cache[path] = [t for _, t in self.source.read_lines(path, 1, None)]
            except Exception:
                self.cache[path] = None
        text = self.cache[path]
        if not text:
            return []
        return [(i, text[i - 1]) for i in range(max(1, start), min(len(text), end) + 1)]


def _fn_nodes(b: "GraphBuilder", path: str) -> list[str]:
    return [nid for _, _, nid in b.def_ranges.get(path, []) if nid.startswith("fn:")]


def _file_imports(f: dict) -> list[str]:
    return [i.get("name") or "" for i in f.get("imports", []) or []]


def enrich(b: "GraphBuilder") -> None:
    src = _Src(b.source)
    G = b.G
    files = [f for f in b.ci.get("files", []) or [] if f.get("path")]
    tables_by_class = _tables(b, src, files)
    for f in files:
        path = f["path"]
        try:
            if not f.get("input_sources"):
                _inputs(b, src, f)
            if not f.get("external_services"):
                _services(b, f)
            if not f.get("db_access"):
                _db(b, src, f, tables_by_class)
        except Exception as exc:  # fail soft per file
            b.error(f"enrich:{path}", exc)
    G.graph["enriched"] = {"source_available": bool(b.source and b.source.available)}


# --------------------------------------------------------------------------- inputs

def _inputs(b: "GraphBuilder", src: _Src, f: dict) -> None:
    G = b.G
    path = f["path"]
    web = any(i.split(".")[0] in WEB_FRAMEWORKS for i in _file_imports(f))
    for fn in _fn_nodes(b, path):
        d = G.nodes[fn]
        found: list[tuple[str, int]] = []
        if web:
            for i, line in src.lines(path, d["line"], d["end_line"]):
                for m in INPUT_RE.finditer(line):
                    found.append((f"request.{m.group(1)}", i))
        for i, line in src.lines(path, d["line"], d["end_line"]):
            if ARGV_RE.search(line):
                found.append(("command-line arguments" if "input(" not in line else "stdin input()", i))
        entries = pred(G, fn, "HANDLES")
        routes = [e for e in entries if e.startswith("route:")]
        if routes and not found:
            fw = {G.nodes[r].get("framework") for r in routes}
            params = [p for p in d.get("params", []) if p.lstrip("*") not in FASTAPI_SKIP_PARAMS]
            if "fastapi" in fw and params:
                found.append((f"request parameters ({', '.join(params)})", d["line"]))
            else:
                found.append(("HTTP request", G.nodes[routes[0]].get("line") or d["line"]))
        if any(e.startswith("cli:") for e in entries) and not found:
            found.append(("command-line arguments", d["line"]))
        seen = set()
        for source, line in found:
            if source in seen:
                continue
            seen.add(source)
            d["inputs"].append({"source": source, "line": line, "discovered_by": "algorithm"})
            for e in entries:
                add_edge(G, fn, e, "RECEIVES_INPUT", "algorithm", [ev(path, line)], key=f"RECEIVES_INPUT:{source}",
                         source=source, confidence=0.9 if source.startswith("request.") else 0.7)


# --------------------------------------------------------------------------- services

def _domain(url: str) -> Optional[str]:
    try:
        host = urlparse(url).hostname
    except ValueError:
        return None
    return host


def _services(b: "GraphBuilder", f: dict) -> None:
    G = b.G
    path = f["path"]
    fns = _fn_nodes(b, path)
    sdk_imports = {}
    for imp in f.get("imports", []) or []:
        if imp.get("kind") != "external":
            continue
        top = (imp.get("name") or "").split(".")[0]
        if top in SDK_SERVICES:
            sdk_imports.setdefault(top, imp.get("line"))
    callers_by_sdk: dict[str, list[tuple[str, int]]] = {}
    for fn in fns + [n for n in nodes_of(G, "Function") if G.nodes[n].get("file") == path and G.nodes[n].get("module_level")]:
        for c in G.nodes[fn].get("external_calls", []):
            top = (c.get("import_name") or str(c.get("target", "")).split(".")[0])
            if top in SDK_SERVICES:
                callers_by_sdk.setdefault(top, []).append((fn, c.get("line")))
    for top in sorted(set(sdk_imports) | set(callers_by_sdk)):
        name = SDK_SERVICES[top]
        sid = add_node(G, svc_id(name), "ExternalService", "algorithm", [ev(path, sdk_imports.get(top))],
                       name=name, via="sdk", sdk=top)
        G.nodes[f"file:{path}"]["services"].append({"service": sid, "via": "sdk", "line": sdk_imports.get(top)})
        callers = callers_by_sdk.get(top)
        if callers:
            for fn, line in callers:
                add_edge(G, fn, sid, "CONTACTS", "algorithm", [ev(path, line)], via="sdk", sdk=top, confidence=0.9)
        else:
            # imported but never called directly (e.g. a client factory that returns the module)
            for fn in fns:
                add_edge(G, fn, sid, "CONTACTS", "algorithm", [ev(path, sdk_imports.get(top))], via="sdk-import",
                         sdk=top, confidence=0.6)

    urls = f.get("string_urls", []) or []
    for fn in fns:
        d = G.nodes[fn]
        net = [s for s in d.get("sensitive", []) if s.get("category") == "network"]
        if not net:
            continue
        in_fn = [u for u in urls if d["line"] <= (u.get("line") or 0) <= d["end_line"]]
        hosts = [(h, u) for u in in_fn for h in [_domain(u.get("url", ""))] if h]
        if not hosts:
            G.graph["known_unknowns"].append(
                f"network call {net[0].get('target')} at {path}:{net[0].get('line')} uses a non-literal URL")
            tag(G, fn, "network_dynamic_url")
            continue
        for host, u in hosts:
            sid = add_node(G, svc_id(host), "ExternalService", "algorithm", [ev(path, u.get("line"))], name=host,
                           via="url", url=u.get("url"))
            G.nodes[f"file:{path}"]["services"].append({"service": sid, "via": "url", "line": u.get("line")})
            add_edge(G, fn, sid, "CONTACTS", "algorithm", [ev(path, u.get("line")), ev(path, net[0].get("line"))],
                     via="url", url=u.get("url"), call=net[0].get("target"), confidence=0.9)


# --------------------------------------------------------------------------- database

def _tables(b: "GraphBuilder", src: _Src, files: list[dict]) -> dict[str, str]:
    """class node -> table name, from __tablename__ / db_table / Django models in class bodies."""
    G = b.G
    out: dict[str, str] = {}
    for f in files:
        path = f["path"]
        for start, end, nid in b.def_ranges.get(path, []):
            if not nid.startswith("class:"):
                continue
            body = src.lines(path, start, end)
            table, line = None, start
            for i, text in body:
                m = TABLENAME_RE.search(text) or DB_TABLE_RE.search(text)
                if m:
                    table, line = m.group(1), i
                    break
            if not table and body and DJANGO_MODEL_RE.search(body[0][1]):
                app = path.split("/")[-2] if "/" in path else ""
                table = f"{app}_{G.nodes[nid]['name'].lower()}" if app else G.nodes[nid]["name"].lower()
            if table:
                tid = add_node(G, table_id(table), "Table", "algorithm", [ev(path, line)], name=table,
                               model=G.nodes[nid]["name"])
                add_edge(G, nid, tid, "MAPS_TO", "algorithm", [ev(path, line)])
                out[nid] = table
                b.model_tables[G.nodes[nid]["name"]] = table
    return out


def _db(b: "GraphBuilder", src: _Src, f: dict, tables_by_class: dict[str, str]) -> None:
    G = b.G
    path = f["path"]
    imports = _file_imports(f)
    db_file = any(any(i == lib or i.startswith(lib + ".") for lib in DB_LIBS) for i in imports)
    model_names = {G.nodes[c]["name"]: t for c, t in tables_by_class.items()}
    for fn in _fn_nodes(b, path):
        d = G.nodes[fn]
        writes: list[tuple[Optional[str], int]] = []
        reads: list[tuple[Optional[str], int]] = []
        # models constructed in this function (constructor calls resolve to Class / __init__)
        built = []
        for callee in succ(G, fn, "CALLS"):
            cls = callee if callee.startswith("class:") else (
                f"class:{callee[3:].rsplit('.', 1)[0]}" if callee.endswith(".__init__") else None)
            if cls in tables_by_class:
                built.append(tables_by_class[cls])
        for c in d.get("external_calls", []):
            t = str(c.get("target") or "")
            if any(t == lib or t.startswith(lib + ".") for lib in DB_LIBS) or ".session." in t or ".objects." in t:
                model = next((m for m in model_names if f".{m}." in f".{t}"), None)
                table = model_names.get(model) if model else None
                if WRITE_CALL_RE.search(t):
                    writes.append((table, c.get("line")))
                elif READ_CALL_RE.search(t):
                    reads.append((table, c.get("line")))
        if db_file or built or model_names:
            for i, text in src.lines(path, d["line"], d["end_line"]):
                model = next((m for m in model_names if re.search(rf"\b{re.escape(m)}\b", text)), None)
                table = model_names.get(model) if model else None
                sql = SQL_RE.search(text) if "execute" in text else None
                if sql:
                    verb = sql.group(1).upper()
                    (reads if verb == "SELECT" else writes).append((table, i))
                elif WRITE_SRC_RE.search(text):
                    writes.append((table, i))
                elif READ_SRC_RE.search(text):
                    reads.append((table, i))
        if built and writes:
            writes = [(t or built[0], line) for t, line in writes]
        for etype, items in (("WRITES", writes), ("READS", reads)):
            for table, line in items:
                d.setdefault("db_ops", []).append({"operation": etype.lower(), "table": table, "line": line})
                if table:
                    tid = add_node(G, table_id(table), "Table", "algorithm", [ev(path, line)], name=table)
                    add_edge(G, fn, tid, etype, "algorithm", [ev(path, line)], confidence=0.8)
                else:
                    tag(G, fn, "writes_db" if etype == "WRITES" else "reads_db")
                    G.graph.setdefault("db_unknown_tables", []).append({"file": path, "line": line, "function": fn})
