"""Sandbox runner: extract one distribution and report AST facts. Never installs, builds or imports it.

Run as a separate process with a timeout (``analyze``). When ``GUARDIAN_SANDBOX=docker`` and a Docker
daemon is available, the same module runs in a throwaway container: ``--network none --read-only``,
non-root, 1 CPU, 512 MB, scratch tmpfs, deleted afterwards. Otherwise it runs as a local subprocess with
the same limits on time and archive size (parse-only, so nothing from the package runs either way).

    python -I -m guardian.stage5_anomalies.sandbox.runner <archive> <dest-dir>   -> JSON facts on stdout
"""
from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

TIMEOUT = 60
URL_RE = re.compile(r"https?://([A-Za-z0-9.-]+)")
NETWORK = ("urllib.request.", "urllib.urlopen", "requests.", "httpx.", "http.client.", "socket.", "aiohttp.", "urllib3.")
SUBPROC = ("subprocess.", "os.system", "os.popen", "os.exec", "os.spawn", "pty.spawn")
ENV = ("os.environ", "os.getenv", "os.environ.get")


def _name(node) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _name(node.func)
    return ""


def scan_python(text: str, path: str) -> list[dict]:
    """Behaviour facts of one Python file (network, subprocess, exec/eval, obfuscation, env, hooks)."""
    try:
        tree = ast.parse(text)
    except SyntaxError as exc:
        return [{"category": "parse_error", "target": str(exc)[:80], "line": exc.lineno or 1, "end_line": exc.lineno or 1}]
    aliases: dict[str, str] = {}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                aliases[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
        elif isinstance(n, ast.ImportFrom) and n.module:
            for a in n.names:
                aliases[a.asname or a.name] = f"{n.module}.{a.name}"
    out = []
    b64_lines = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Call):
            raw = _name(n.func)
            head = raw.split(".")[0]
            full = (aliases.get(head, head) + raw[len(head):]) if head else raw
            line, end = n.lineno, getattr(n, "end_lineno", n.lineno)
            cat = None
            if full in ("exec", "eval", "compile", "builtins.exec", "builtins.eval"):
                cat = "code_exec"
            elif full.startswith(NETWORK) or full in ("urlopen",):
                cat = "network"
            elif full.startswith(SUBPROC):
                cat = "subprocess"
            elif full.startswith(("base64.b64decode", "base64.decodebytes", "codecs.decode", "zlib.decompress", "marshal.loads")):
                cat = "decode"
                b64_lines.append(line)
            elif full.startswith(ENV):
                cat = "env_read"
            elif full.endswith("setup") and any(k.arg == "cmdclass" for k in n.keywords):
                cat = "install_hook"
            if cat:
                out.append({"category": cat, "target": full, "line": line, "end_line": end})
        elif isinstance(n, ast.Subscript) and _name(n.value) == "os.environ":
            out.append({"category": "env_read", "target": "os.environ[...]", "line": n.lineno, "end_line": n.lineno})
        elif isinstance(n, ast.Constant) and isinstance(n.value, str):
            for host in URL_RE.findall(n.value):
                out.append({"category": "domain", "target": host, "line": n.lineno, "end_line": n.lineno})
            if len(n.value) >= 40 and re.fullmatch(r"[A-Za-z0-9+/=]+", n.value):
                out.append({"category": "encoded_blob", "target": f"{len(n.value)} base64 chars", "line": n.lineno,
                            "end_line": n.lineno})
    execs = [f for f in out if f["category"] == "code_exec"]
    if execs and (b64_lines or any(f["category"] == "encoded_blob" for f in out)):
        for e in execs:
            out.append({"category": "obfuscated_exec", "target": "exec of decoded data", "line": e["line"], "end_line": e["end_line"]})
    for cls in [n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]:
        bases = {_name(b).split(".")[-1] for b in cls.bases}
        if bases & {"install", "develop", "build_py", "egg_info", "sdist", "build_ext", "bdist_wheel"}:
            out.append({"category": "install_hook", "target": f"class {cls.name}({', '.join(sorted(bases))})",
                        "line": cls.lineno, "end_line": getattr(cls, "end_lineno", cls.lineno)})
    return sorted(out, key=lambda f: (f["line"], f["category"]))


def facts(root: Path, files: list[str]) -> dict:
    res = {"files": {}, "ast": {}, "pth": [], "console_scripts": []}
    for rel in files:
        p = root / rel
        try:
            data = p.read_bytes()
        except OSError:
            continue
        res["files"][rel] = {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
        if rel.endswith(".py"):
            res["ast"][rel] = scan_python(data.decode("utf-8", "replace"), rel)
        elif rel.endswith(".pth"):
            text = data.decode("utf-8", "replace")
            code = [i + 1 for i, l in enumerate(text.splitlines()) if l.strip().startswith(("import ", "import\t"))]
            if code:
                res["pth"].append({"file": rel, "lines": code})
        elif rel.endswith("entry_points.txt"):
            text = data.decode("utf-8", "replace")
            if "[console_scripts]" in text:
                res["console_scripts"] += [l.split("=")[0].strip() for l in text.split("[console_scripts]")[1].splitlines()
                                           if "=" in l][:10]
    return res


def analyze(archive: Path, dest: Path, timeout: int = TIMEOUT) -> dict:
    """Extract + scan ``archive`` into ``dest`` in an isolated process; returns facts or {"error": ...}."""
    archive, dest = Path(archive).resolve(), Path(dest).resolve()
    use_docker = os.environ.get("GUARDIAN_SANDBOX") == "docker" and shutil.which("docker")
    if use_docker:
        root = Path(__file__).resolve().parents[3]
        dest.mkdir(parents=True, exist_ok=True)
        cmd = ["docker", "run", "--rm", "--network", "none", "--read-only", "--user", "65534:65534", "--cpus", "1",
               "--memory", "512m", "--tmpfs", "/tmp:size=256m", "-v", f"{root}:/src:ro", "-v", f"{archive}:/in/pkg:ro",
               "-v", f"{dest}:/out", "-w", "/src", "python:3.12-slim", "python", "-I", "-m",
               "guardian.stage5_anomalies.sandbox.runner", f"/in/pkg#{archive.name}", "/out"]
    else:
        # -I ignores PYTHONPATH and the cwd: load only this sandbox folder (not the guardian package)
        here = str(Path(__file__).resolve().parent)
        boot = f"import sys; sys.path.insert(0, {here!r}); import runner; sys.exit(runner.main(sys.argv[1:]))"
        cmd = [sys.executable, "-I", "-c", boot, str(archive), str(dest)]
    env = {"PATH": os.environ.get("PATH", ""), "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
           "PYTHONPATH": str(Path(__file__).resolve().parents[3]), "no_proxy": "*", "HTTP_PROXY": "http://0.0.0.0:9",
           "HTTPS_PROXY": "http://0.0.0.0:9"}
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env, encoding="utf-8", errors="replace")
    except subprocess.TimeoutExpired:
        return {"error": f"sandbox timed out after {timeout}s"}
    if r.returncode != 0:
        return {"error": (r.stderr or r.stdout).strip()[-300:]}
    try:
        out = json.loads(r.stdout)
    except json.JSONDecodeError:
        return {"error": "sandbox output was not JSON"}
    out["isolation"] = "docker" if use_docker else "subprocess"
    return out


def main(argv: list[str]) -> int:
    try:
        from .safe_extract import UnsafeArchive, safe_extract
    except ImportError:          # loaded as a top-level module inside the sandbox process
        from safe_extract import UnsafeArchive, safe_extract
    src, dest = argv[0], Path(argv[1])
    path, _, display = src.partition("#")
    archive = Path(path)
    if display:  # docker: mounted file has no extension; copy-free rename via symlink is refused, so read by name
        tmp = Path("/tmp") / display
        tmp.write_bytes(archive.read_bytes())
        archive = tmp
    try:
        files = safe_extract(archive, dest)
    except UnsafeArchive as exc:
        print(json.dumps({"error": f"unsafe archive: {exc}"}))
        return 0
    print(json.dumps(facts(dest, files)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
