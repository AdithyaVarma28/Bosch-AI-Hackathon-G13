"""Code-level remediation: SQL injection in the application's own code (CWE-89).

Finds SQL statements built by string formatting and passed to a DB-API cursor (`c.execute("... '%s'" % (a, b))`,
`"... '{}'".format(a)`, f-strings) and rewrites each call to a parameterized query (`c.execute("... ?", (a, b))`).
The fix changes the application's code, not a dependency version, so validation must show two things:
  T1 exploit  an injection payload works before the fix and is treated as data after it   FAIL -> PASS
  T2 guard    the function no longer builds SQL by string formatting (AST)                 FAIL -> PASS
  T3 feature  the function still does its job with normal input                            PASS -> PASS
T1/T3 run the real function against a temporary SQLite database created from the repository's own CREATE TABLE.
Supported now: sqlite3 (qmark style). Other drivers are reported but get only the guard test.
"""
from __future__ import annotations

import ast
import json
import re
from pathlib import Path
from typing import Optional

SKIP = {".git", ".venv", "venv", "env", "node_modules", "site-packages", "__pycache__", "tests", "test", "migrations"}
PH_PERCENT = re.compile(r"'?%[sdifr]'?")
PH_FORMAT = re.compile(r"'?\{[^{}]*\}'?")


def _py_files(root: Path):
    for p in sorted(Path(root).rglob("*.py")):
        rel = p.relative_to(root)
        if any(part in SKIP for part in rel.parts[:-1]) or rel.name.startswith("test_"):
            continue
        yield rel, p


def _seg(src: str, node) -> Optional[str]:
    return ast.get_source_segment(src, node)


def sites_in_source(src: str, rel: str) -> list[dict]:
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return []
    out = []
    funcs = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    owner = {}
    for f in funcs:
        for n in ast.walk(f):
            owner.setdefault(id(n), f)
    for call in ast.walk(tree):
        if not (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
                and call.func.attr in ("execute", "executemany") and len(call.args) == 1 and not call.keywords):
            continue
        a0 = call.args[0]
        sql = params = None
        if isinstance(a0, ast.BinOp) and isinstance(a0.op, ast.Mod) and isinstance(a0.left, ast.Constant) and isinstance(a0.left.value, str):
            sql, params, ph = a0.left.value, (a0.right.elts if isinstance(a0.right, ast.Tuple) else [a0.right]), PH_PERCENT
        elif isinstance(a0, ast.Call) and isinstance(a0.func, ast.Attribute) and a0.func.attr == "format" \
                and isinstance(a0.func.value, ast.Constant) and isinstance(a0.func.value.value, str) and not a0.keywords:
            sql, params, ph = a0.func.value.value, list(a0.args), PH_FORMAT
        elif isinstance(a0, ast.JoinedStr):
            parts, params = [], []
            for v in a0.values:
                if isinstance(v, ast.Constant):
                    parts.append(str(v.value).replace("{", "{{").replace("}", "}}"))
                else:
                    parts.append("{}")
                    params.append(v.value)
            sql, ph = "".join(parts), PH_FORMAT
        if sql is None or not params or not re.match(r"\s*(select|insert|update|delete|replace)\b", sql, re.I):
            continue
        if len(ph.findall(sql)) != len(params):
            continue
        new_sql = ph.sub("?", sql)
        old = _seg(src, call)
        segs = [_seg(src, p) for p in params]
        if not old or None in segs or src.count(old) != 1:
            continue
        new = f"{_seg(src, call.func)}({json.dumps(new_sql)}, ({', '.join(segs)},))"
        f = owner.get(id(call))
        verb = sql.strip().split()[0].upper()
        table = (re.search(r"\b(?:from|into|update)\s+([A-Za-z_]\w*)", sql, re.I) or [None, None])[1]
        cols = [m.group(1) for m in re.finditer(r"([A-Za-z_]\w*)\s*=\s*" + ph.pattern, sql)]
        if verb == "INSERT":
            m = re.search(r"\(([^)]*)\)\s*values", sql, re.I)
            cols = [c.strip() for c in m.group(1).split(",")] if m else []
        db = None
        if f is not None:
            for n in ast.walk(f):
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "connect" \
                        and isinstance(n.func.value, ast.Name) and n.func.value.id == "sqlite3" and n.args \
                        and isinstance(n.args[0], ast.Constant):
                    db = n.args[0].value
        out.append({"file": rel, "line": call.lineno, "function": f.name if f else None,
                    "fargs": [a.arg for a in f.args.args] if f else [],
                    "fdefaults": len(f.args.defaults) if f else 0,
                    "verb": verb, "table": table, "columns": cols,
                    "params": [p.id if isinstance(p, ast.Name) else None for p in params],
                    "sql": sql, "new_sql": new_sql, "old": old, "new": new, "db": db,
                    "driver": "sqlite3" if re.search(r"^\s*import sqlite3|^\s*from sqlite3", src, re.M) else "unknown"})
    return out


def find_sites(root: Path) -> list[dict]:
    res = []
    for rel, p in _py_files(root):
        try:
            src = p.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        res += sites_in_source(src, rel.as_posix())
    return res


def schema(root: Path, table: Optional[str], columns: Optional[list] = None, near: Optional[str] = None) -> Optional[str]:
    """The repository's own CREATE TABLE for `table`: one that has every column the query uses, nearest to `near`."""
    if not table:
        return None
    rx = re.compile(r"CREATE TABLE (?:IF NOT EXISTS )?" + re.escape(table) + r"\s*\(([^)]*)\)", re.I)
    found = []
    for p in sorted(Path(root).rglob("*")):
        if p.suffix not in (".py", ".sql") or any(part in SKIP for part in p.relative_to(root).parts[:-1]):
            continue
        try:
            for m in rx.finditer(p.read_text(encoding="utf-8", errors="ignore")):
                ddl = f"CREATE TABLE {table} ({m.group(1)})"
                have = {c.split()[0] for c in m.group(1).split(",") if c.split()}
                if not columns or set(columns) <= have:
                    rel = p.relative_to(root).as_posix()
                    same = near and Path(rel).parent == Path(near).parent
                    found.append((0 if same else 1, rel, ddl))
        except OSError:
            continue
    return sorted(found)[0][2] if found else None


def _route_callers(root: Path, func: str, file: str) -> list[str]:
    """Files with HTTP routes that call this function (module.func( or func()."""
    mod = Path(file).stem
    rx = re.compile(rf"\b({re.escape(mod)}\.)?{re.escape(func)}\(")
    hits = []
    for rel, p in _py_files(root):
        t = p.read_text(encoding="utf-8", errors="ignore")
        if ".route(" in t and rx.search(t) and rel.as_posix() != file and rel.parent == Path(file).parent:
            hits.append(rel.as_posix())
    return hits


# ------------------------------------------------------------------ remediation units
def code_units(out: Path, root: Path, start: int = 1) -> tuple[list[dict], list[dict]]:
    """(register entries, remediation units) for SQL injection sites, one unit per function."""
    from .candidates import _cand
    sites = find_sites(root)
    by_fn: dict[tuple, list[dict]] = {}
    for s in sites:
        by_fn.setdefault((s["file"], s["function"]), []).append(s)
    regs, units = [], []
    for i, ((file, fn), ss) in enumerate(sorted(by_fn.items(), key=lambda kv: (kv[0][0], kv[1][0]["line"])), start):
        callers = _route_callers(root, fn, file) if fn else []
        auth = bool(fn and re.search(r"login|auth|password|token|session", fn, re.I))
        prio = "critical" if callers and auth else "high" if callers else "low"
        fid = f"C-{i:03d}"
        where = f"{file}:{ss[0]['line']}" + (f" in {fn}()" if fn else "")
        reason = (f"reachable from HTTP routes in {', '.join(callers[:3])}" if callers else
                  "not called from an HTTP route (script / setup code)")
        regs.append({
            "finding_id": fid, "kind": "code", "subtype": "sql_injection", "vuln_id": "CWE-89",
            "title": f"SQL injection: {ss[0]['verb']} built with string formatting in {fn or 'module'}() ({file})",
            "component": f"code:{file}::{fn}", "component_name": file, "priority": prio, "stage_risk": prio,
            "decision": "Act" if prio in ("critical", "high") else "Track", "decision_model": "guardian-code",
            "finding_confidence": "high", "rank": 0, "summary": "SQL query built from user-controlled values",
            "priority_reasons": [reason, "user input is concatenated into SQL (CWE-89): an attacker can change the query"
                                 + (", e.g. log in without a password" if auth and ss[0]["verb"] == "SELECT" else "")],
            "confidence_reasons": ["the query string and its formatting are visible in the code (AST)"],
            "evidence": [{"id": f"{fid}-E{j}", "where": f"{s['file']}:{s['line']}", "text": s["old"][:200]} for j, s in enumerate(ss, 1)],
            "decision_inputs": {}, "decision_by": {}, "decision_why": {}, "sites": ss})
        supported = all(s["driver"] == "sqlite3" for s in ss)
        cand = _cand("parameterize_sql", "replace-unsafe-api",
                     f"Use a parameterized query in {fn or 'module'}() ({file}): values are passed to the driver, never pasted into SQL",
                     [{"path": s["file"], "old_text": s["old"], "new_text": s["new"]} for s in ss] if supported else [],
                     sites=ss, compatibility=["same SQL, same results for normal input: only the way values reach the "
                                              "database changes (sqlite3 '?' placeholders)"],
                     notes=[f"{s['file']}:{s['line']}: {s['sql'].strip()[:90]}  →  {s['new_sql'].strip()[:90]}" for s in ss],
                     rollback="git revert the fix commit", expected_after="resolved")
        if not supported:
            cand.update(kind="escalate", label=f"Parameterize the SQL in {fn}() by hand (driver not sqlite3)", expected_after="unchanged")
        cand["cid"] = 0
        units.append({"rid": fid.replace("C-", "C-"), "target": f"code:{file}::{fn}", "target_label": f"SQL injection in {fn or file}()",
                      "target_kind": "code", "finding_ids": [fid], "ranks": [0 if prio == "critical" else 1 if prio == "high" else 50],
                      "priority": prio, "decision": regs[-1]["decision"], "decision_model": "guardian-code", "stage_risk": prio,
                      "downgrade_limited": False, "finding_confidence": "high", "candidates": [cand], "proposals": [],
                      "status": "new"})
    return regs, units


def still_vulnerable(root: Path, unit: dict) -> list[dict]:
    file, _, fn = (unit.get("target") or "").removeprefix("code:").partition("::")
    return [s for s in find_sites(root) if s["file"] == file and str(s["function"]) == fn]


# ------------------------------------------------------------------ tests (T1 exploit / T2 guard / T3 feature)
HARNESS = '''
SQLI = {spec}


def _sqli_func(tmp_path, monkeypatch, rows):
    """Load the real function with its module, on a fresh SQLite database built from the repository's schema."""
    import sqlite3
    monkeypatch.chdir(tmp_path)
    d = str(ROOT / SQLI["dir"])
    if d not in sys.path:
        sys.path.insert(0, d)
    for m in [m for m in sys.modules if m == SQLI["module"]]:
        del sys.modules[m]
    mod = importlib.import_module(SQLI["module"])
    con = sqlite3.connect(SQLI["db"])
    con.execute(SQLI["ddl"])
    for r in rows:
        con.execute(f"INSERT INTO {{SQLI['table']}} ({{', '.join(r)}}) VALUES ({{', '.join('?' * len(r))}})", list(r.values()))
    con.commit()
    con.close()
    return getattr(mod, SQLI["function"])


def _sqli_rows(where=None):
    import sqlite3
    con = sqlite3.connect(SQLI["db"])
    con.row_factory = sqlite3.Row
    q = f"SELECT * FROM {{SQLI['table']}}" + (f" WHERE {{where[0]}} = ?" if where else "")
    rows = [dict(r) for r in con.execute(q, [where[1]] if where else [])]
    con.close()
    return rows
'''


def _defaults(ddl: str) -> dict:
    cols = {}
    for part in ddl[ddl.index("(") + 1: ddl.rindex(")")].split(","):
        w = part.split()
        if w and w[0].upper() not in ("PRIMARY", "UNIQUE", "FOREIGN", "CHECK", "CONSTRAINT"):
            cols[w[0]] = 0 if len(w) > 1 and re.match(r"int|real|num|bool|float", w[1], re.I) else ""
    return cols


def test_blocks(out: Path, unit: dict, wt: Path) -> tuple[list[dict], str]:
    """T1 + T3 for each patched function (sqlite3); T2 is the AST guard."""
    blocks = []
    file, _, fn = (unit.get("target") or "").removeprefix("code:").partition("::")
    blocks.append({"kind": "T2", "source": "template", "name": "test_t2_guard_no_sql_string_formatting",
                   "title": f"{fn}() no longer builds SQL with string formatting",
                   "code": f'''def test_t2_guard_no_sql_string_formatting():
    """T2 guard (not proof): {fn}() in {file} passes values to the driver instead of formatting them into SQL."""
    import ast
    src = (ROOT / {file!r}).read_text(encoding="utf-8")
    fn = next(n for n in ast.walk(ast.parse(src)) if isinstance(n, ast.FunctionDef) and n.name == {fn!r})
    bad = []
    for n in ast.walk(fn):
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in ("execute", "executemany") and n.args:
            a = n.args[0]
            if isinstance(a, ast.JoinedStr) or (isinstance(a, ast.BinOp) and isinstance(a.op, ast.Mod)) or \\
                    (isinstance(a, ast.Call) and isinstance(a.func, ast.Attribute) and a.func.attr == "format"):
                bad.append(n.lineno)
    assert not bad, f"SQL built by string formatting on line(s) {{bad}}"
'''})
    # the vulnerable sites as found before the patch (the worktree may already be patched)
    sites = [s for c in unit.get("candidates") or [] for s in c.get("sites") or []] or \
        [s for s in find_sites(wt) if s["file"] == file and str(s["function"]) == fn]
    if len(sites) != 1:
        return blocks, ""
    s = sites[0]
    ddl = schema(wt, s["table"], [c for c, p in zip(s["columns"], s["params"]) if p], s["file"])
    args = [p for p in s["params"] if p]
    required = s["fargs"][: len(s["fargs"]) - s["fdefaults"]]
    if s["driver"] != "sqlite3" or not s["db"] or not ddl or not args or any(a not in args for a in required) \
            or any(p is not None and p not in s["fargs"] for p in s["params"]):
        return blocks, ""
    cols = _defaults(ddl)
    colmap = [(c, p) for c, p in zip(s["columns"], s["params"]) if p and c in cols]
    if not colmap:
        return blocks, ""
    spec = {"dir": str(Path(file).parent.as_posix()) if Path(file).parent.as_posix() != "." else ".",
            "module": Path(file).stem, "function": fn, "db": s["db"], "ddl": ddl, "table": s["table"]}
    header = HARNESS.format(spec=json.dumps(spec))
    verb, slug = s["verb"], re.sub(r"\W+", "_", fn).lower()
    base = {c: v for c, v in cols.items()}
    if verb == "SELECT":
        seed = {**base, **{c: f"real_{c}" for c, _ in colmap}}
        ok_kw = {p: f"real_{c}" for c, p in colmap}
        last_c, last_p = colmap[-1]
        bad_kw = {**ok_kw, last_p: "wrong' OR '1'='1"}
        t1 = f'''def test_t1_exploit_sql_injection_{slug}(tmp_path, monkeypatch):
    """T1 exploit (CWE-89): {fn}() must not match a row when {last_p} is wrong, even if it contains SQL.
    Before the fix the payload {bad_kw[last_p]!r} rewrites the WHERE clause and the row is returned (e.g. login bypass).
    Expected: FAILS before the fix, PASSES after it."""
    f = _sqli_func(tmp_path, monkeypatch, [{seed!r}])
    assert not f(**{bad_kw!r}), "SQL injection: the payload changed the query and matched a row"
'''
        t3 = f'''def test_t3_feature_{slug}_still_finds_the_row(tmp_path, monkeypatch):
    """T3 feature: with correct, normal input {fn}() still finds the row (expected PASS before and after)."""
    f = _sqli_func(tmp_path, monkeypatch, [{seed!r}])
    assert f(**{ok_kw!r})
'''
    elif verb == "INSERT":
        c0, p0 = colmap[0]
        kw = {p: f"normal_{c}" if isinstance(cols[c], str) else 1 for c, p in colmap}
        evil = {**kw, p0: "O'Brien'); DROP TABLE x; --"}
        t1 = f'''def test_t1_exploit_sql_injection_{slug}(tmp_path, monkeypatch):
    """T1 exploit (CWE-89): a value containing a quote must be stored as data, not executed as SQL.
    Before the fix the quote breaks out of the string literal (syntax error / injected SQL).
    Expected: FAILS before the fix, PASSES after it."""
    f = _sqli_func(tmp_path, monkeypatch, [])
    f(**{evil!r})
    assert _sqli_rows(({c0!r}, {evil[p0]!r})), "the value was not stored literally"
'''
        t3 = f'''def test_t3_feature_{slug}_still_stores_the_row(tmp_path, monkeypatch):
    """T3 feature: with normal input {fn}() still stores the row (expected PASS before and after)."""
    f = _sqli_func(tmp_path, monkeypatch, [])
    f(**{kw!r})
    assert _sqli_rows(({c0!r}, {kw[p0]!r}))
'''
    elif verb == "UPDATE" and len(colmap) >= 2:
        (sc, sp), (wc, wp) = colmap[0], colmap[-1]
        victim = {**base, sc: "old", wc: "victim"}
        other = {**base, sc: "old", wc: "bystander"}
        t1 = f'''def test_t1_exploit_sql_injection_{slug}(tmp_path, monkeypatch):
    """T1 exploit (CWE-89): the new {sc} of one row must not leak into the WHERE clause.
    Before the fix the payload comments out the WHERE clause and EVERY row is changed.
    Expected: FAILS before the fix, PASSES after it."""
    f = _sqli_func(tmp_path, monkeypatch, [{victim!r}, {other!r}])
    f(**{{{sp!r}: "pwned' --", {wp!r}: "victim"}})
    assert _sqli_rows(({wc!r}, "bystander"))[0][{sc!r}] == "old", "the update changed another row"
'''
        t3 = f'''def test_t3_feature_{slug}_still_updates_one_row(tmp_path, monkeypatch):
    """T3 feature: with normal input {fn}() still changes exactly the intended row (PASS before and after)."""
    f = _sqli_func(tmp_path, monkeypatch, [{victim!r}, {other!r}])
    f(**{{{sp!r}: "new", {wp!r}: "victim"}})
    assert _sqli_rows(({wc!r}, "victim"))[0][{sc!r}] == "new"
    assert _sqli_rows(({wc!r}, "bystander"))[0][{sc!r}] == "old"
'''
    else:
        return blocks, ""
    blocks.insert(0, {"kind": "T1", "source": "template", "name": f"test_t1_exploit_sql_injection_{slug}",
                      "title": f"an SQL-injection payload against {fn}() works before the fix and is treated as data after it",
                      "vuln_id": "CWE-89", "code": t1})
    blocks.append({"kind": "T3", "source": "template", "name": t3.split("(")[0].split()[-1],
                   "title": f"{fn}() still works with normal input", "code": t3})
    return blocks, header
