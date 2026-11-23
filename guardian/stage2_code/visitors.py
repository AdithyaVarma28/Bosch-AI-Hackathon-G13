"""ast visitors that extract facts. They only read syntax trees; nothing is executed."""
import ast

from guardian.models.code_index import Definition, ImportRef
from guardian.stage2_code.import_resolver import ModuleMap


def absolute_from(node: ast.ImportFrom, module_path: str, is_package: bool) -> str | None:
    """Absolute dotted module of a `from ... import` statement (None if the relative level overshoots)."""
    if not node.level:
        return node.module or ""
    package = module_path if is_package else module_path.rpartition(".")[0]
    parts = package.split(".") if package else []
    up = node.level - 1
    if up >= len(parts):  # climbing past the top-level package is an ImportError in Python
        return None
    base = parts[: len(parts) - up] if up else parts
    if node.module:
        base = base + node.module.split(".")
    return ".".join(base)


def build_aliases(tree: ast.AST, module_path: str, is_package: bool) -> dict[str, str]:
    """Local name -> dotted target for every import in the file (scope-insensitive)."""
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                aliases[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom):
            module = absolute_from(node, module_path, is_package)
            if module is None:
                continue
            for a in node.names:
                if a.name != "*":
                    aliases[a.asname or a.name] = f"{module}.{a.name}" if module else a.name
    return aliases


def _iter_scope_nodes(body):
    """Nodes belonging to one scope: descends into blocks and classes but not into nested functions."""
    stack = list(body)
    while stack:
        n = stack.pop()
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            continue
        yield n
        stack.extend(ast.iter_child_nodes(n))


def scope_aliases(body, module_path: str, is_package: bool) -> dict[str, str]:
    """Import bindings visible directly in one scope (module body or one function body)."""
    aliases: dict[str, str] = {}
    for node in _iter_scope_nodes(body):
        if isinstance(node, ast.Import):
            for a in node.names:
                aliases[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom):
            module = absolute_from(node, module_path, is_package)
            if module is None:
                continue
            for a in node.names:
                if a.name != "*":
                    aliases[a.asname or a.name] = f"{module}.{a.name}" if module else a.name
    return aliases


def stored_names(body) -> set[str]:
    """Names assigned (or bound by for/with/except) directly in one scope; they shadow imports."""
    names: set[str] = set()
    for n in _iter_scope_nodes(body):
        if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
            names.add(n.id)
        elif isinstance(n, ast.ExceptHandler) and n.name:
            names.add(n.name)
    return names


class ImportCollector(ast.NodeVisitor):
    def __init__(self, module_path: str, is_package: bool, mmap: ModuleMap, file_dir: str = ""):
        self.module_path = module_path
        self.is_package = is_package
        self.mmap = mmap
        self.file_dir = file_dir
        self.imports: list[ImportRef] = []
        self._try = 0
        self._cond = 0

    # --- context flags -------------------------------------------------
    def _enter_try(self, node):
        self._try += 1
        self.generic_visit(node)
        self._try -= 1

    visit_Try = _enter_try
    visit_TryStar = _enter_try

    def _enter_cond(self, node):
        self._cond += 1
        self.generic_visit(node)
        self._cond -= 1

    visit_If = _enter_cond
    visit_While = _enter_cond

    # --- imports -------------------------------------------------------
    def _add(self, name: str, alias: str | None, line: int, *, relative: bool = False) -> None:
        bare = name.removesuffix(".*")
        kind = "internal" if relative else self.mmap.classify(bare)
        resolved = self.mmap.resolve(bare) if kind == "internal" else None
        if kind == "external":  # script-style import of a sibling module (e.g. vulpy)
            nearby = self.mmap.resolve_nearby(bare, self.file_dir)
            if nearby:
                kind, resolved = "internal", nearby
        self.imports.append(ImportRef(
            name=name, alias=alias, kind=kind, line=line, in_try_except=self._try > 0,
            conditional=self._cond > 0, resolved_file=resolved))

    def visit_Import(self, node: ast.Import) -> None:
        for a in node.names:
            self._add(a.name, a.asname, node.lineno)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = absolute_from(node, self.module_path, self.is_package)
        relative = bool(node.level)
        if module is None:
            self.imports.append(ImportRef(
                name="." * node.level + (node.module or ""), kind="internal", line=node.lineno,
                in_try_except=self._try > 0, conditional=self._cond > 0))
            return
        needs_module_ref = False
        for a in node.names:
            if a.name == "*":
                self._add(f"{module}.*", None, node.lineno, relative=relative)
                continue
            sub = f"{module}.{a.name}" if module else a.name
            if self.mmap.is_module(sub):
                self._add(sub, a.asname, node.lineno, relative=relative)
            else:
                needs_module_ref = True
        if needs_module_ref and module:
            self._add(module, None, node.lineno, relative=relative)


class DefinitionCollector(ast.NodeVisitor):
    def __init__(self, path: str):
        self.path = path
        self.definitions: list[Definition] = []
        self._stack: list[tuple[str, str]] = []  # (name, "class" | "function")

    def _qualname(self, name: str) -> str:
        parts: list[str] = []
        for n, kind in self._stack:
            parts.append(n)
            if kind == "function":
                parts.append("<locals>")
        return ".".join(parts + [name])

    @staticmethod
    def _params(args: ast.arguments) -> list[str]:
        out = [a.arg for a in args.posonlyargs + args.args]
        if args.vararg:
            out.append("*" + args.vararg.arg)
        out += [a.arg for a in args.kwonlyargs]
        if args.kwarg:
            out.append("**" + args.kwarg.arg)
        return out

    def _add(self, node, type_: str, params: list[str]) -> None:
        self.definitions.append(Definition(
            id=f"{self.path}::{self._qualname(node.name)}", type=type_, name=node.name,
            line=node.lineno, end_line=node.end_lineno or node.lineno,
            decorators=[ast.unparse(d) for d in node.decorator_list], params=params,
            docstring=ast.get_docstring(node)))

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._add(node, "class", [])
        self._stack.append((node.name, "class"))
        self.generic_visit(node)
        self._stack.pop()

    def _function(self, node, is_async: bool) -> None:
        in_class = bool(self._stack) and self._stack[-1][1] == "class"
        base = "method" if in_class else "function"
        self._add(node, f"async_{base}" if is_async else base, self._params(node.args))
        self._stack.append((node.name, "function"))
        self.generic_visit(node)
        self._stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._function(node, False)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._function(node, True)
