"""Day 1 JavaScript/TypeScript usage layer: import/require extraction only (no call graph)."""
from __future__ import annotations

import re

from ..models import CodeFile, ImportRef, SimpleRef
from . import patterns as P

NODE_BUILTINS = {"assert", "buffer", "child_process", "cluster", "crypto", "dgram", "dns", "events", "fs", "http", "http2",
                 "https", "net", "os", "path", "process", "querystring", "readline", "stream", "string_decoder", "timers",
                 "tls", "tty", "url", "util", "v8", "vm", "worker_threads", "zlib", "module", "perf_hooks", "async_hooks"}
JS_EXT = (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx")
_IMPORT_RES = [
    re.compile(r"""\brequire\s*\(\s*['"]([^'"]+)['"]\s*\)"""),
    re.compile(r"""\bimport\s+(?:[\w*{}\s,]+\s+from\s+)?['"]([^'"]+)['"]"""),
    re.compile(r"""\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)"""),
    re.compile(r"""\bexport\s+[\w*{}\s,]+\s+from\s+['"]([^'"]+)['"]"""),
]
_DYN = re.compile(r"""\b(require|import)\s*\(\s*[^'"\s)]""")
_EVAL = re.compile(r"\b(eval|new Function)\s*\(")
_CHILD = re.compile(r"\b(exec|execSync|spawn|spawnSync|execFile)\s*\(")


def package_of(spec: str) -> str:
    if spec.startswith("@"):
        return "/".join(spec.split("/")[:2])
    return spec.split("/")[0]


def index_js(cf: CodeFile, text: str) -> None:
    for i, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith("//"):
            continue
        for rx in _IMPORT_RES:
            for m in rx.finditer(line):
                spec = m.group(1)
                if spec.startswith((".", "/", "@/", "~/", "#", "$")) or spec in ("@", "~"):  # relative or tsconfig/vite aliases
                    kind, name, dist = "internal", spec, None
                elif spec.startswith("node:") or package_of(spec) in NODE_BUILTINS:
                    kind, name, dist = "stdlib", spec, None
                else:
                    kind, name, dist = "external", spec, package_of(spec)
                if not any(x.name == name and x.line == i for x in cf.imports):
                    cf.imports.append(ImportRef(name=name, kind=kind, line=i, distribution=dist))
        if _DYN.search(line):
            cf.dynamic_imports.append(SimpleRef(name="<dynamic>", line=i, how="require/import(expr)"))
        if _EVAL.search(line):
            cf.sensitive_calls.append(_sens("code_exec", _EVAL.search(line).group(1), i))
        if _CHILD.search(line) and "child_process" in text:
            cf.sensitive_calls.append(_sens("subprocess", _CHILD.search(line).group(1), i))
        for m in P.URL_RE.finditer(line):
            from urllib.parse import urlparse
            url = m.group(0).rstrip(").,;'\"")
            cf.string_urls.append(SimpleRef(name=url, line=i, detail=urlparse(url).hostname))
    cf.discovered_by = "regex"


def _sens(cat, target, line):
    from ..models import SensitiveCall
    return SensitiveCall(function=None, category=cat, target=target, line=line)
