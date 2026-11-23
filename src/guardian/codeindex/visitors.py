"""Single-pass ast.NodeVisitor extracting per-file facts. Repo-level resolution happens in resolver.py."""
from __future__ import annotations

import ast
from urllib.parse import urlparse

from ..models import (CallRef, CodeFile, DbAccess, DbModel, Definition, ImportRef, Route, SensitiveCall, SimpleRef)
from . import patterns as P


def dotted(node: ast.AST) -> str | None:
    """Name / Attribute chain -> 'a.b.c'. Calls in the chain become 'f()'."""
    parts = []
    while True:
        if isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        elif isinstance(node, ast.Name):
            parts.append(node.id)
            break
        elif isinstance(node, ast.Call):
            inner = dotted(node.func)
            if not inner:
                return None
            parts.append(inner + "()")
            break
        else:
            return None
    return ".".join(reversed(parts))


def _const_str(node: ast.AST | None) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


class FileVisitor(ast.NodeVisitor):
    def __init__(self, cf: CodeFile, module_path: str, is_package: bool):
        self.cf = cf
        self.path = cf.path
        self.module = module_path
        self.package = module_path if is_package else module_path.rpartition(".")[0]
        self.aliases: dict[str, str] = {}       # local name -> fully dotted name
        self.local_defs: set[str] = set()       # top-level function/class names in this module
        self.scope: list[str] = []              # qualname stack
        self.class_stack: list[str] = []
        self.try_depth = 0
        self.if_depth = 0
        self.framework: str | None = None
        self.route_handlers: set[str] = set()
        self.var_types: dict[str, str] = {}

    # ----------------------------------------------------------------- helpers
    @property
    def current(self) -> str:
        return f"{self.path}::{'.'.join(self.scope)}" if self.scope else f"{self.path}::<module>"

    def resolve_name(self, name: str | None) -> str | None:
        if not name:
            return None
        head, _, rest = name.partition(".")
        if head in ("self", "cls") and self.class_stack and rest:
            first = rest.split(".")[0]
            return f"{self.module}.{self.class_stack[-1]}.{first}" if first else None
        if head in self.aliases:
            base = self.aliases[head]
            return f"{base}.{rest}" if rest else base
        if head in self.local_defs:
            return f"{self.module}.{name}"
        return name

    # ----------------------------------------------------------------- module
    def visit_Module(self, node: ast.Module) -> None:
        self.cf.docstring = ast.get_docstring(node)
        for n in node.body:  # pre-register top-level defs so forward references resolve
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                self.local_defs.add(n.name)
        self.generic_visit(node)

    def visit_Try(self, node: ast.Try) -> None:
        self.try_depth += 1
        self.generic_visit(node)
        self.try_depth -= 1

    visit_TryStar = visit_Try

    def visit_If(self, node: ast.If) -> None:
        t = node.test
        if (isinstance(t, ast.Compare) and isinstance(t.left, ast.Name) and t.left.id == "__name__"
                and any(_const_str(c) == "__main__" for c in t.comparators)):
            self.cf.cli_entrypoints.append(SimpleRef(function=self.current, name="__main__", line=node.lineno,
                                                     how="if __name__ == '__main__'"))
        self.if_depth += 1
        self.generic_visit(node)
        self.if_depth -= 1

    # ----------------------------------------------------------------- imports
    def _add_import(self, name: str, alias: str | None, line: int, local: str) -> None:
        self.aliases[local] = name
        self.cf.imports.append(ImportRef(name=name, alias=alias, kind="unknown", line=line,
                                         in_try_except=self.try_depth > 0, conditional=self.if_depth > 0 or bool(self.scope)))
        if name.split(".")[0] in ("fastapi", "starlette"):
            self.framework = "fastapi"
        elif name.split(".")[0] == "flask" and self.framework is None:
            self.framework = "flask"
        elif name.split(".")[0] == "django" and self.framework is None:
            self.framework = "django"

    def visit_Import(self, node: ast.Import) -> None:
        for a in node.names:
            local = a.asname or a.name.split(".")[0]
            target = a.name if a.asname else a.name.split(".")[0]
            self._add_import(a.name, a.asname, node.lineno, local)
            self.aliases[local] = target if not a.asname else a.name

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.level:
            parts = self.package.split(".") if self.package else []
            up = node.level - 1
            base_parts = parts[: len(parts) - up] if up else parts
            base = ".".join(base_parts + ([node.module] if node.module else []))
        else:
            base = node.module or ""
        for a in node.names:
            if a.name == "*":
                self._add_import(base, None, node.lineno, f"*{base}")
                continue
            full = f"{base}.{a.name}" if base else a.name
            self._add_import(full, a.asname, node.lineno, a.asname or a.name)

    # ----------------------------------------------------------------- definitions
    def _def(self, node, kind: str) -> None:
        qual = ".".join(self.scope + [node.name])
        decorators = [dotted(d.func if isinstance(d, ast.Call) else d) or ast.unparse(d)[:80] for d in node.decorator_list]
        params = []
        returns = None
        if not isinstance(node, ast.ClassDef):
            a = node.args
            params = [x.arg for x in a.posonlyargs + a.args + a.kwonlyargs]
            if a.vararg:
                params.append("*" + a.vararg.arg)
            if a.kwarg:
                params.append("**" + a.kwarg.arg)
            returns = ast.unparse(node.returns)[:120] if node.returns else None
        bases = [ast.unparse(b)[:80] for b in getattr(node, "bases", [])]
        self.cf.definitions.append(Definition(
            id=f"{self.path}::{qual}", type=kind, name=node.name, line=node.lineno,
            end_line=getattr(node, "end_lineno", None), decorators=decorators, params=params, returns=returns,
            docstring=(ast.get_docstring(node) or None), bases=bases))
        return qual

    def _visit_func(self, node, kind):
        if self.class_stack and len(self.scope) == len(self.class_stack):
            kind = "method"
        qual = self._def(node, kind)
        func_id = f"{self.path}::{qual}"
        self._routes_and_cli(node, func_id)
        for d in node.decorator_list:  # decorators run in the enclosing scope
            self.visit(d)
        self.scope.append(node.name)
        self.visit(node.args)
        if node.returns:
            self.visit(node.returns)
        for st in node.body:
            self.visit(st)
        self.scope.pop()

    def visit_FunctionDef(self, node):
        self._visit_func(node, "function")

    def visit_AsyncFunctionDef(self, node):
        self._visit_func(node, "async_function")

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        qual = self._def(node, "class")
        bases = {ast.unparse(b) for b in node.bases}
        resolved_bases = {self.resolve_name(dotted(b)) or "" for b in node.bases}
        is_orm = bool(bases & P.ORM_BASES) or any(r.endswith(("db.Model", "models.Model", "DeclarativeBase", "SQLModel"))
                                                  for r in resolved_bases) or any(b.endswith(".Model") for b in bases)
        if is_orm:
            table, fields = None, []
            for st in node.body:
                if isinstance(st, ast.Assign) and len(st.targets) == 1 and isinstance(st.targets[0], ast.Name):
                    nm = st.targets[0].id
                    if nm == "__tablename__":
                        table = _const_str(st.value)
                    elif isinstance(st.value, ast.Call):
                        fn = dotted(st.value.func) or ""
                        if fn in P.FIELD_CALLS or fn.startswith("models.") or fn.endswith("Field"):
                            fields.append(nm)
                elif isinstance(st, ast.AnnAssign) and isinstance(st.target, ast.Name):
                    fields.append(st.target.id)
            fw = "django" if any("models.Model" in b for b in bases | resolved_bases) else "sqlalchemy"
            if fw == "django" and table is None:
                table = f"{self.module.split('.')[0]}_{node.name.lower()}"
            elif table is None:
                fw = "sqlmodel" if "SQLModel" in " ".join(bases) else fw
            self.cf.db_models.append(DbModel(class_id=f"{self.path}::{qual}", table=table, fields=fields,
                                             framework=fw, line=node.lineno))
        for d in node.decorator_list + node.bases + node.keywords:
            self.visit(d)
        self.scope.append(node.name)
        self.class_stack.append(qual)
        for st in node.body:
            self.visit(st)
        self.class_stack.pop()
        self.scope.pop()

    def _routes_and_cli(self, node, func_id: str) -> None:
        for d in node.decorator_list:
            call = d if isinstance(d, ast.Call) else None
            name = dotted(call.func if call else d) or ""
            last = name.rsplit(".", 1)[-1]
            obj = name.rsplit(".", 1)[0] if "." in name else ""
            if call and last in ("route",) and obj:
                path = _const_str(call.args[0]) if call.args else None
                methods = ["GET"]
                for kw in call.keywords:
                    if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple, ast.Set)):
                        methods = [_const_str(e) or "?" for e in kw.value.elts]
                for m in methods:
                    self.cf.routes.append(Route(framework=self.framework or "flask", method=m.upper(), path=path or "?",
                                                handler=func_id, line=d.lineno))
                self.route_handlers.add(func_id)
            elif call and last in P.ROUTE_METHODS and obj and not obj.endswith(("requests", "httpx", "session", "client")):
                path = _const_str(call.args[0]) if call.args else None
                if path is None:
                    for kw in call.keywords:
                        if kw.arg == "path":
                            path = _const_str(kw.value)
                fw = self.framework or ("fastapi" if "router" in obj.lower() else "flask")
                self.cf.routes.append(Route(framework=fw, method="ANY" if last == "api_route" else last.upper(),
                                            path=path or "?", handler=func_id, line=d.lineno))
                self.route_handlers.add(func_id)
                if fw == "fastapi":  # FastAPI params are user input
                    for p in [a.arg for a in node.args.args + node.args.kwonlyargs]:
                        if p not in ("self", "request", "db", "session", "background_tasks", "response"):
                            self.cf.input_sources.append(SimpleRef(function=func_id, name=p, line=node.lineno,
                                                                   how="fastapi-param"))
            elif last in ("command", "group") and (name.startswith(("click.", "typer.")) or obj.endswith(("cli", "app", "group"))) \
                    and self.aliases.get(obj.split(".")[0], obj).split(".")[0] in ("click", "typer", "cli", "app") \
                    and any(self.aliases.get(k, "").split(".")[0] in ("click", "typer") for k in self.aliases):
                self.cf.cli_entrypoints.append(SimpleRef(function=func_id, name=node.name, line=d.lineno, how=name))

    # ----------------------------------------------------------------- expressions
    def visit_Attribute(self, node: ast.Attribute) -> None:
        base = dotted(node.value)
        resolved = self.resolve_name(base) if base else None
        if resolved and resolved.endswith("request"):
            if node.attr in P.FLASK_INPUT_ATTRS and (resolved.startswith(("flask", "werkzeug")) or self.framework == "flask"):
                self._input(node, f"request.{node.attr}", "flask")
            elif node.attr in P.DJANGO_INPUT_ATTRS:
                self._input(node, f"request.{node.attr}", "django")
            elif node.attr in P.FLASK_INPUT_ATTRS:
                self._input(node, f"request.{node.attr}", self.framework or "http")
        if resolved == "sys" and node.attr == "argv":
            self._input(node, "sys.argv", "cli")
        self.generic_visit(node)

    def _input(self, node, name: str, how: str) -> None:
        if not any(r.name == name and r.line == node.lineno for r in self.cf.input_sources):
            self.cf.input_sources.append(SimpleRef(function=self.current, name=name, line=node.lineno, how=how))

    def visit_Name(self, node: ast.Name) -> None:
        if self.scope and node.id in self.aliases and node.id not in self.local_defs:
            target = self.aliases[node.id]
            fid = self.current
            if not any(r.function == fid and r.name == target for r in self.cf.name_refs):
                self.cf.name_refs.append(SimpleRef(function=fid, name=target, line=node.lineno, how="reference"))

    def visit_Subscript(self, node: ast.Subscript) -> None:
        base = dotted(node.value)
        if base and self.resolve_name(base) == "os.environ":
            key = _const_str(node.slice)
            self.cf.env_reads.append(SimpleRef(function=self.current, name=key or "<dynamic>", line=node.lineno, how="os.environ[]"))
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str) and len(node.value) < 2000:
            for m in P.URL_RE.finditer(node.value):
                url = m.group(0).rstrip(").,;")
                self.cf.string_urls.append(SimpleRef(function=self.current, name=url, line=node.lineno,
                                                     detail=urlparse(url).hostname))

    def visit_Call(self, node: ast.Call) -> None:
        raw = dotted(node.func)
        target = self.resolve_name(raw) if raw else None
        line = node.lineno
        if target:
            head = target.split(".")[0]
            kind = "builtin" if raw in P.BUILTINS and raw not in self.aliases and raw not in self.local_defs else "unknown"
            self.cf.calls.append(CallRef(caller=self.current, target=target, kind=kind, line=line))
            # env reads
            if target in ("os.environ.get", "os.getenv", "os.environ.setdefault"):
                key = _const_str(node.args[0]) if node.args else None
                self.cf.env_reads.append(SimpleRef(function=self.current, name=key or "<dynamic>", line=line,
                                                   how=target.replace("os.environ.", "os.environ.")))
            # dynamic imports
            if target in P.DYNAMIC_IMPORT:
                arg = _const_str(node.args[0]) if node.args else None
                self.cf.dynamic_imports.append(SimpleRef(function=self.current, name=arg or "<dynamic>", line=line, how=target))
            # sensitive calls
            cat = P.sensitive_category(target)
            if raw == "open" and "open" not in self.aliases:
                mode = _const_str(node.args[1]) if len(node.args) > 1 else next(
                    (_const_str(k.value) for k in node.keywords if k.arg == "mode"), None)
                if mode and any(c in mode for c in "wax+"):
                    cat = "file_write"
            if target in ("yaml.load", "yaml.load_all"):
                loader = next((dotted(k.value) for k in node.keywords if k.arg == "Loader"), None) or (
                    dotted(node.args[1]) if len(node.args) > 1 else None)
                if loader and "Safe" in loader:
                    cat = None
            if cat:
                self.cf.sensitive_calls.append(SensitiveCall(function=self.current, category=cat, target=target, line=line))
            if raw == "input" and "input" not in self.aliases:
                self._input(node, "input()", "cli")
            if target.endswith("ArgumentParser") and head in ("argparse",):
                self.cf.cli_entrypoints.append(SimpleRef(function=self.current, name="argparse", line=line, how=target))
            # DB access
            self._db(node, raw, target, line)
            # Django urls.py
            if self.path.endswith("urls.py") and target.split(".")[-1] in ("path", "re_path", "url") and len(node.args) >= 2:
                p = _const_str(node.args[0])
                view = dotted(node.args[1])
                if p is not None and view:
                    self.cf.routes.append(Route(framework="django", method="ANY", path=p,
                                                handler=self.resolve_name(view) or view, line=line))
        self.generic_visit(node)

    def _db(self, node: ast.Call, raw: str | None, target: str, line: int) -> None:
        if not raw or "." not in raw:
            return
        recv, _, op = raw.rpartition(".")
        recv_last = recv.split(".")[-1].rstrip("()")
        resolved_recv = self.resolve_name(recv) or recv
        is_db_recv = bool(P.DB_RECEIVER.search(recv_last)) or recv.endswith(".objects") or recv_last.endswith("session")
        if op == "execute" or op == "executemany" or op == "raw":
            sql = _const_str(node.args[0]) if node.args else None
            if sql and P.SQL_RE.match(sql) or (is_db_recv and op != "raw") or op == "raw":
                self.cf.db_access.append(DbAccess(function=self.current, operation="raw_sql", target=raw, line=line,
                                                  model=None))
            return
        if not is_db_recv and not resolved_recv.startswith(("sqlalchemy", "pymongo", "django.db")):
            return
        model = None
        if recv.endswith(".objects"):
            model = recv.rsplit(".objects", 1)[0].split(".")[-1]
        elif op in ("add", "delete", "merge") and node.args:
            arg = node.args[0]
            if isinstance(arg, ast.Name):
                model = self.var_types.get(arg.id, arg.id)
            elif isinstance(arg, ast.Call):
                model = dotted(arg.func)
        elif op == "query" and node.args:
            model = dotted(node.args[0])
        if op in P.DB_WRITE:
            self.cf.db_access.append(DbAccess(function=self.current, operation="write", target=raw, model=model, line=line))
        elif op in P.DB_READ:
            self.cf.db_access.append(DbAccess(function=self.current, operation="read", target=raw, model=model, line=line))

    def visit_Assign(self, node: ast.Assign) -> None:
        # `order = Order(...)`: remember local var -> constructor so `session.add(order)` names the model
        if isinstance(node.value, ast.Call):
            fn = dotted(node.value.func)
            if fn and fn[:1].isupper():
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        self.var_types[t.id] = fn
        self.generic_visit(node)
