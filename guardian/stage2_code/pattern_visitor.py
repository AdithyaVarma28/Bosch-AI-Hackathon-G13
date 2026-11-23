"""Calls, sensitive calls, env reads, routes and entry points, with import aliases resolved."""
import ast
import re

from guardian.models.code_index import (
    CallRef,
    CliEntrypoint,
    DynamicImport,
    EnvRead,
    Route,
    SensitiveCall,
    StringUrl,
)
from guardian.stage2_code.import_resolver import ModuleMap
from guardian.stage2_code.patterns import (
    BUILTIN_CALLS,
    DJANGO_INCLUDES,
    DJANGO_PATHS,
    HTTP_VERBS,
    SAFE_YAML_LOADERS,
    categorize,
    is_write_mode,
)
from guardian.stage2_code.visitors import build_aliases, scope_aliases, stored_names


def _chain(node: ast.AST) -> list[str] | None:
    """['a','b','c'] for a.b.c, None when the expression is not a plain Name/Attribute chain."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return parts[::-1]
    return None


def _const_str(node: ast.AST | None) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


class PatternCollector(ast.NodeVisitor):
    def __init__(self, path: str, module_path: str, is_package: bool, mmap: ModuleMap, tree: ast.Module,
                 file_dir: str = ""):
        self.path = path
        self.module_path = module_path
        self.is_package = is_package
        self.mmap = mmap
        self.file_dir = file_dir
        self.aliases = scope_aliases(tree.body, module_path, is_package)  # module scope only
        self._scopes: list[dict[str, str | None]] = [self.aliases]  # None marks a shadowed name
        self.toplevel = {n.name for n in tree.body
                         if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))}
        values = list(build_aliases(tree, module_path, is_package).values())  # any scope: framework hints
        self.uses_fastapi = any(v.startswith("fastapi") for v in values)
        self.uses_flask = any(v.startswith("flask") for v in values)
        self.uses_typer = any(v.startswith("typer") for v in values)
        self.calls: list[CallRef] = []
        self.sensitive: list[SensitiveCall] = []
        self.env: list[EnvRead] = []
        self.routes: list[Route] = []
        self.cli: list[CliEntrypoint] = []
        self.urls: list[StringUrl] = []
        self.dynamic: list[DynamicImport] = []
        self._stack: list[tuple[str, str]] = []

    # --- helpers ---------------------------------------------------------
    def _qual(self, name: str | None = None) -> str:
        parts: list[str] = []
        last = len(self._stack) - 1
        for i, (n, kind) in enumerate(self._stack):
            parts.append(n)
            if kind == "function" and (i < last or name):
                parts.append("<locals>")
        if name:
            parts.append(name)
        return ".".join(parts)

    def _caller(self) -> str:
        return f"{self.path}::{self._qual()}" if self._stack else f"{self.path}::<module>"

    def _resolve(self, node: ast.AST) -> tuple[str | None, bool]:
        """(dotted target, is_builtin) for a call/attribute expression, alias-resolved."""
        parts = _chain(node)
        if not parts:
            return None, False
        root = parts[0]
        for scope in reversed(self._scopes):
            if root in scope:
                bound = scope[root]
                if bound is None:  # shadowed by a parameter or local assignment
                    return None, False
                return ".".join([bound] + parts[1:]), False
        if root in self.toplevel and len(parts) == 1:
            return f"{self.module_path}.{root}", False
        if len(parts) == 1 and root in BUILTIN_CALLS:
            return root, True
        return None, False

    def _handler_for(self, target: str) -> str:
        parts = target.split(".")
        for i in range(len(parts), 0, -1):
            module = ".".join(parts[:i])
            if self.mmap.is_module(module):
                rest = ".".join(parts[i:])
                file = self.mmap.module_to_file[module]
                return f"{file}::{rest}" if rest else file
        return target

    # --- scopes ----------------------------------------------------------
    def _enter(self, node, kind: str) -> None:
        for d in node.decorator_list:
            self._decorator(d, node)
            self.visit(d)
        if kind == "function":
            self.visit(node.args)
            a = node.args
            params = [p.arg for p in a.posonlyargs + a.args + a.kwonlyargs]
            params += [x.arg for x in (a.vararg, a.kwarg) if x]
            scope: dict[str, str | None] = {n: None for n in params}
            scope.update({n: None for n in stored_names(node.body)})
            scope.update(scope_aliases(node.body, self.module_path, self.is_package))
            self._scopes.append(scope)
        self._stack.append((node.name, kind))
        for stmt in node.body:
            self.visit(stmt)
        self._stack.pop()
        if kind == "function":
            self._scopes.pop()

    def visit_FunctionDef(self, node) -> None:
        self._enter(node, "function")

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._enter(node, "class")

    def _flask_like(self, obj: ast.AST) -> bool:
        """`.route` is a Flask route if Flask is imported here or the object comes from a repo module."""
        if self.uses_flask:
            return True
        parts = _chain(obj)
        root = self.aliases.get(parts[0]) if parts else None
        return bool(root and self.mmap.classify(root) == "internal")

    def _safe_yaml_loader(self, node: ast.Call) -> bool:
        expr = node.args[1] if len(node.args) > 1 else None
        for kw in node.keywords:
            if kw.arg in ("Loader", "loader"):
                expr = kw.value
        target, _ = self._resolve(expr) if expr is not None else (None, False)
        return bool(target and target.rsplit(".", 1)[-1] in SAFE_YAML_LOADERS)

    # --- decorators: routes + cli ----------------------------------------
    def _decorator(self, d: ast.AST, fn) -> None:
        call = d if isinstance(d, ast.Call) else None
        target_expr = d.func if call else d
        target, _ = self._resolve(target_expr)
        line = d.lineno
        if target and target.startswith("click.") and target.rsplit(".", 1)[-1] in ("command", "group"):
            self.cli.append(CliEntrypoint(kind="click", name=fn.name, line=line))
        if isinstance(target_expr, ast.Attribute) and self.uses_typer and target_expr.attr in ("command", "callback"):
            self.cli.append(CliEntrypoint(kind="typer", name=fn.name, line=line))
        if call is None or not isinstance(call.func, ast.Attribute):
            return
        attr = call.func.attr
        handler = f"{self.path}::{self._qual(fn.name)}"
        path = (_const_str(call.args[0]) if call.args else None) or "<dynamic>"
        if attr == "route" and self._flask_like(call.func.value):
            methods = ["GET"]
            for kw in call.keywords:
                if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)):
                    found = [_const_str(e).upper() for e in kw.value.elts if _const_str(e)]
                    methods = found or methods
            for m in methods:
                self.routes.append(Route(framework="flask", method=m, path=path, handler=handler, line=line))
        elif attr in HTTP_VERBS and (self.uses_fastapi or self.uses_flask):
            fw = "fastapi" if self.uses_fastapi else "flask"
            self.routes.append(Route(framework=fw, method=attr.upper(), path=path, handler=handler, line=line))

    # --- statements / expressions ----------------------------------------
    def visit_If(self, node: ast.If) -> None:
        t = node.test
        if (isinstance(t, ast.Compare) and isinstance(t.left, ast.Name) and t.left.id == "__name__"
                and len(t.comparators) == 1 and _const_str(t.comparators[0]) == "__main__"):
            self.cli.append(CliEntrypoint(kind="main_guard", name="__main__", line=node.lineno))
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str) and re.fullmatch(r"https?://\S+", node.value):
            self.urls.append(StringUrl(url=node.value, line=node.lineno))

    def visit_Subscript(self, node: ast.Subscript) -> None:
        target, _ = self._resolve(node.value)
        if target == "os.environ" and isinstance(node.ctx, ast.Load):
            self.env.append(EnvRead(var=_const_str(node.slice) or "<dynamic>", how="os.environ[]", line=node.lineno))
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        target, builtin = self._resolve(node.func)
        if target:
            self._record_call(node, target, builtin)
            if target in DJANGO_PATHS:
                self._django_route(node)
        self.generic_visit(node)

    def _record_call(self, node: ast.Call, target: str, builtin: bool) -> None:
        if builtin and target == "open":
            mode = _const_str(node.args[1]) if len(node.args) > 1 else None
            for kw in node.keywords:
                if kw.arg == "mode":
                    mode = _const_str(kw.value)
            if mode and is_write_mode(mode):
                self.sensitive.append(SensitiveCall(category="file_write", target="open", line=node.lineno))
            return
        if target in ("importlib.import_module", "__import__"):
            expr = _const_str(node.args[0] if node.args else None) or "<dynamic>"
            self.dynamic.append(DynamicImport(expr=expr, line=node.lineno))
        category = categorize(target)
        if target in ("yaml.load", "yaml.load_all") and self._safe_yaml_loader(node):
            category = None
        if category:
            self.sensitive.append(SensitiveCall(category=category, target=target, line=node.lineno))
        if builtin:
            return
        top = target.split(".")[0]
        kind = "internal" if top in self.toplevel else self.mmap.classify(target)
        if kind == "external" and self.mmap.resolve_nearby(target, self.file_dir):
            kind = "internal"  # script-style sibling module, consistent with the import record
        self.calls.append(CallRef(caller=self._caller(), target=target, kind=kind,
                                  import_name=top if kind != "internal" else None, line=node.lineno))
        if target in ("os.getenv", "os.environ.get"):
            var = _const_str(node.args[0] if node.args else None) or "<dynamic>"
            self.env.append(EnvRead(var=var, how=target, line=node.lineno))
        if target == "argparse.ArgumentParser":
            self.cli.append(CliEntrypoint(kind="argparse", name="ArgumentParser", line=node.lineno))

    def _django_route(self, node: ast.Call) -> None:
        path = _const_str(node.args[0]) if node.args else None
        if path is None or len(node.args) < 2:
            return
        view = node.args[1]
        if isinstance(view, ast.Call):
            inner, _ = self._resolve(view.func)
            if inner in DJANGO_INCLUDES:
                mod = _const_str(view.args[0]) if view.args else None
                self.routes.append(Route(framework="django", method="ANY", path=path,
                                         handler=f"include:{mod or '<dynamic>'}", line=node.lineno))
                return
            if isinstance(view.func, ast.Attribute) and view.func.attr == "as_view":
                view = view.func.value
        handler_target, _ = self._resolve(view)
        if handler_target:
            self.routes.append(Route(framework="django", method="ANY", path=path,
                                     handler=self._handler_for(handler_target), line=node.lineno))
