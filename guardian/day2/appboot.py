"""Run the app, before and after (docs/DAY_2_COMPLETION_PLAN.md section 6).

1. Target Python: the platform the project says it runs on (GUARDIAN_TARGET_PYTHON, a Dockerfile pin,
   .python-version / runtime.txt, `python:slim`/`latest` = the newest stable CPython uv knows).
2. Install check on that Python: "installs" or the failing package and the error line.
3. Boot check: detect Flask / FastAPI / Django, prepare a temporary SQLite database, start the server on a free
   port, request `/` and up to 5 parameter-free GET routes. Healthy = no 5xx and at least one 2xx/3xx.
4. Build-health search: when the install fails because a pinned package has no wheel for the target Python,
   find the smallest newer version that ships one (and has no known vulnerability), and retry, up to 6 packages.
5. Live run: start the fixed app for the demo, stop it after 15 minutes.

Nothing here touches the user's checkout: every run happens in a sandbox folder with a throwaway venv.
"""
from __future__ import annotations

import os
import re
import shutil
import socket
import subprocess
import sys
import sysconfig
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Callable, Optional

from . import runtime
from .runtime import Env, _last_line, _run, _tail

MAX_BUMPS = 6
LIVE_MINUTES = 15


# ------------------------------------------------------------------ target Python
_NEWEST: Optional[str] = None


def newest_python() -> str:
    """The newest stable CPython minor version uv can provide (no rc, no free-threaded build)."""
    global _NEWEST
    if _NEWEST:
        return _NEWEST
    best = (sys.version_info.major, sys.version_info.minor)
    if shutil.which("uv"):
        code, out = _run(["uv", "python", "list"], timeout=60)
        if code == 0:
            for m in re.finditer(r"^cpython-(\d+)\.(\d+)\.(\d+)-(\S+)", out, re.M):
                if "freethreaded" in m.group(0) or "+" in m.group(0):
                    continue
                best = max(best, (int(m.group(1)), int(m.group(2))))
    _NEWEST = f"{best[0]}.{best[1]}"
    return _NEWEST


def target_python(root: Path) -> dict:
    """{"version", "source"}: the Python the project says it runs on."""
    env = os.environ.get("GUARDIAN_TARGET_PYTHON")
    if env:
        return {"version": env.strip(), "source": "GUARDIAN_TARGET_PYTHON"}
    df = root / "Dockerfile"
    text = df.read_text(encoding="utf-8", errors="replace") if df.exists() else ""
    m = re.search(r"^\s*FROM\s+(?:\S+/)?python:(\d+\.\d+)", text, re.I | re.M)
    if m:
        return {"version": m.group(1), "source": f"Dockerfile pins python:{m.group(1)}"}
    for f, rx in ((root / ".python-version", r"^\s*(\d+\.\d+)"), (root / "runtime.txt", r"python-(\d+\.\d+)")):
        if f.exists():
            mm = re.search(rx, f.read_text(encoding="utf-8", errors="replace"), re.M)
            if mm:
                return {"version": mm.group(1), "source": f"{f.name} says {mm.group(1)}"}
    m = re.search(r"^\s*FROM\s+(?:\S+/)?python(?::([A-Za-z][\w.-]*))?\s*(?:AS\s+\w+)?\s*$", text, re.I | re.M)
    if m:
        tag = m.group(1) or "latest"
        v = newest_python()
        return {"version": v, "source": f"Dockerfile uses python:{tag}, which means the newest Python ({v})"}
    v = f"{sys.version_info.major}.{sys.version_info.minor}"
    return {"version": v, "source": f"no Python pin in the project; Guardian's own Python ({v})"}


# ------------------------------------------------------------------ install check
FAIL_PATTERNS = [
    (re.compile(r"Failed to (?:download and )?build `([A-Za-z0-9_.\-]+)==([^`\s]+)`"), "no wheel for this Python; building it from source failed"),
    (re.compile(r"Failed to build ([A-Za-z0-9_.\-]+)==([^\s]+)"), "no wheel for this Python; building it from source failed"),
    (re.compile(r"Could not build wheels for ([A-Za-z0-9_.\-]+)()"), "no wheel for this Python; building it from source failed"),
    (re.compile(r"Failed to build ([A-Za-z0-9_.\-]+)()\s*$", re.M), "no wheel for this Python; building it from source failed"),
    (re.compile(r"there is no version of ([A-Za-z0-9_.\-]+)==([^\s,]+)"), "this version is not on the index"),
    (re.compile(r"Because ([A-Za-z0-9_.\-]+)==([^\s]+) requires Python"), "this version does not support this Python"),
]


def parse_failure(text: str) -> Optional[dict]:
    for rx, why in FAIL_PATTERNS:
        m = rx.search(text or "")
        if m:
            return {"package": m.group(1), "version": m.group(2) or None, "reason": why}
    return None


def error_line(text: str) -> str:
    for l in (text or "").splitlines():
        s = l.strip()
        if s.lower().startswith("error:") or s.startswith("ERROR:") or s.startswith("× "):
            return s[:240]
    return _last_line(text)


def install_args(root: Path) -> list[str]:
    reqs = runtime.requirement_files(root)
    return [a for r in reqs for a in ("-r", r)] or ["."]


def install_check(root: Path, version: str, env_dir: Path, args: Optional[list[str]] = None) -> tuple[dict, Optional[Env]]:
    """Install the project's dependencies on one Python. Returns (result, env or None)."""
    t0 = time.time()
    env, err = runtime.create_env(env_dir, version)
    if env is None:
        return {"ok": False, "python": version, "error": err or f"Python {version} is not available", "failing": None,
                "seconds": round(time.time() - t0, 1)}, None
    code, out, cmd = env.install(args or install_args(root), cwd=root)
    res = {"ok": code == 0, "python": env.full_version or version, "command": cmd, "seconds": round(time.time() - t0, 1),
           "error": "" if code == 0 else error_line(out), "failing": None if code == 0 else parse_failure(out),
           "log": _tail(out, 1500)}
    return res, env


# ------------------------------------------------------------------ framework detection
def _read(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _py_files(root: Path, limit: int = 400):
    n = 0
    for p in sorted(root.rglob("*.py")):
        rel = p.relative_to(root)
        if any(part in runtime.SKIP_DIRS or part in ("tests", "migrations") for part in rel.parts[:-1]):
            continue
        n += 1
        if n > limit:
            return
        yield rel, _read(p)


def detect_app(root: Path) -> dict:
    """{"framework": flask|fastapi|django|None, "app": FLASK_APP / module:var, "detail"}."""
    root = Path(root)
    for src, rx in ((".flaskenv", r"^\s*FLASK_APP\s*=\s*(\S+)"), (".env", r"^\s*FLASK_APP\s*=\s*(\S+)"),
                    ("Dockerfile", r"^\s*ENV\s+FLASK_APP[\s=]+(\S+)")):
        m = re.search(rx, _read(root / src), re.M)
        if m:
            a = m.group(1).strip("'\"")
            return {"framework": "flask", "app": a, "detail": f"Flask app FLASK_APP={a} (from {src})"}
    if (root / "manage.py").exists() and "django" in _read(root / "manage.py").lower():
        return {"framework": "django", "app": "manage.py", "detail": "manage.py (Django)"}
    flask_obj = factory = fastapi = None
    flask_key = (99, 999)
    for rel, txt in _py_files(root):
        mod = ".".join(rel.with_suffix("").parts)
        if mod.endswith(".__init__"):
            mod = mod[: -len(".__init__")]
        if not fastapi:
            mm = re.search(r"^(\w+)\s*=\s*FastAPI\(", txt, re.M)
            if mm:
                fastapi = f"{mod}:{mm.group(1)}"
        if len(rel.parts) <= 2:
            mm = re.search(r"^(\w+)\s*=\s*Flask\(", txt, re.M)
            # prefer the plainest entry file (app.py over app-ssl.py, top level over sub-folders)
            if mm and (not flask_obj or (len(rel.parts), len(rel.name)) < flask_key):
                flask_obj, flask_key = f"{mod}:{mm.group(1)}", (len(rel.parts), len(rel.name))
        if not factory and re.search(r"^def create_app\(", txt, re.M) and "Flask(" in txt:
            factory = f"{mod}:create_app()"
    if fastapi:
        return {"framework": "fastapi", "app": fastapi, "detail": f"FastAPI app {fastapi}"}
    if flask_obj or factory:
        a = flask_obj or factory
        f = root / (a.split(":")[0].replace(".", "/") + ".py")
        if f.exists() and _runs_itself(_read(f)):
            rel = f.relative_to(root).as_posix()
            return {"framework": "flask", "app": rel, "mode": "script", "cwd": Path(rel).parent.as_posix(),
                    "detail": f"Flask app {rel} (starts its own server with app.run)"}
        return {"framework": "flask", "app": a, "detail": f"Flask app {a}"}
    return {"framework": None, "app": None, "detail": "no Flask, FastAPI or Django app found"}


def _runs_itself(src: str) -> bool:
    """app.run(...) at module level (not under `if __name__ == "__main__"`)."""
    import ast
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return False
    return any(isinstance(n, ast.Expr) and isinstance(n.value, ast.Call) and isinstance(n.value.func, ast.Attribute)
               and n.value.func.attr == "run" for n in tree.body)


SCRIPT_WRAPPER = (
    "import sys, runpy, flask\n"
    "_port = int(sys.argv[2]); _orig = flask.Flask.run\n"
    "def _run(self, *a, **k):\n"
    "    return _orig(self, host='127.0.0.1', port=_port, debug=False, use_reloader=False)\n"
    "flask.Flask.run = _run\n"
    "sys.argv = [sys.argv[1]]\n"
    "runpy.run_path(sys.argv[0], run_name='__main__')\n")
INIT_SCRIPTS = ("db_init.py", "init_db.py", "initdb.py", "setup_db.py", "create_db.py", "db_setup.py")


def app_dir(root: Path, info: dict) -> Path:
    return Path(root) / info["cwd"] if info.get("mode") == "script" else Path(root)


def script_routes(root: Path, info: dict, limit: int = 5) -> list[str]:
    """Routes of a script-style Flask app, from its blueprints and decorators (it cannot be imported safely)."""
    d = app_dir(root, info)
    prefix, routes = {}, []
    texts = {p: _read(p) for p in sorted(d.glob("*.py"))}
    for t in texts.values():
        for m in re.finditer(r"register_blueprint\(\s*(\w+)\s*,\s*url_prefix\s*=\s*['\"]([^'\"]+)", t):
            prefix[m.group(1)] = m.group(2).rstrip("/")
    for t in texts.values():
        for m in re.finditer(r"@(\w+)\.route\(\s*['\"]([^'\"]*)['\"]([^)]*)\)", t):
            bp, path, rest = m.groups()
            if "<" in path or ("methods" in rest and "GET" not in rest):
                continue
            full = (prefix.get(bp, "") if bp != "app" else "") + path
            if full and not re.search(r"logout|delete|remove|reset", full):
                routes.append(full)
    routes = sorted(set(routes), key=lambda r: (r != "/", "login" not in r, len(r), r))
    return (["/"] + [r for r in routes if r != "/"])[: limit + 1]


# ------------------------------------------------------------------ boot check
def crash_line(text: str) -> str:
    """The exception line of a traceback (last line that looks like `SomeError: ...`)."""
    lines = [l.strip() for l in (text or "").splitlines() if re.match(r"^\s*[A-Za-z_][\w.]*(Error|Exception)\b.*:", l)]
    return (lines[-1] if lines else error_line(text))[:240]


def culprit_module(text: str) -> Optional[str]:
    """The installed package the crash happened in: the deepest traceback frame inside site-packages."""
    mods = re.findall(r"site-packages[\\/]+([A-Za-z0-9_]+)(?:[\\/]|\.py\b)", text or "")
    mods = [m for m in mods if m not in ("flask", "click", "werkzeug", "_pytest", "pluggy", "uvicorn")] or mods
    return mods[-1] if mods else None


# first release date of each CPython minor version: a package release published after it is the first that could
# have been tested on it (used when an old pin installs but crashes at import on the target Python)
PY_RELEASED = {"3.10": "2021-10-04", "3.11": "2022-10-24", "3.12": "2023-10-02", "3.13": "2024-10-07",
               "3.14": "2025-10-07", "3.15": "2026-10-01"}

def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **kw):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def http_get(url: str, timeout: float = 10.0) -> dict:
    t0 = time.time()
    try:
        r = _OPENER.open(urllib.request.Request(url, headers={"User-Agent": "guardian-bootcheck"}), timeout=timeout)
        status, body = r.status, r.read(65536)
    except urllib.error.HTTPError as e:
        status, body = e.code, (e.read(65536) if hasattr(e, "read") else b"")
    except (urllib.error.URLError, OSError, socket.timeout) as e:
        return {"status": None, "error": str(getattr(e, "reason", e))[:160], "ms": int((time.time() - t0) * 1000)}
    m = re.search(rb"<title>(.*?)</title>", body or b"", re.I | re.S)
    return {"status": status, "ms": int((time.time() - t0) * 1000),
            "title": m.group(1).decode("utf-8", "replace").strip()[:120] if m else None}


def app_env(work: Path, info: dict) -> dict:
    keep = dict(os.environ)
    for k in ("DATABASE_URL", "REDIS_URL", "ELASTICSEARCH_URL", "MAIL_SERVER", "FLASK_ENV", "PYTHONPATH", "VIRTUAL_ENV"):
        keep.pop(k, None)
    db = (Path(work) / "guardian-boot.db").resolve().as_posix()
    keep.update({"DATABASE_URL": f"sqlite:///{db}", "PYTHONIOENCODING": "utf-8", "PYTHONDONTWRITEBYTECODE": "1",
                 "FLASK_DEBUG": "0", "SECRET_KEY": keep.get("SECRET_KEY", "guardian-boot-check")})
    if info.get("framework") == "flask":
        keep["FLASK_APP"] = info["app"]
    return keep


def prepare(root: Path, env: Env, info: dict, envvars: dict) -> list[dict]:
    """Database setup before the first start: `flask db upgrade` / `manage.py migrate`."""
    steps = []
    if info.get("mode") == "script":
        d = app_dir(root, info)
        for name in INIT_SCRIPTS:
            if (d / name).exists():
                code, out = _run([str(env.python), name], cwd=d, timeout=120, env=envvars)
                steps.append({"step": f"{info['cwd']}/{name} (the app's own database setup)", "ok": code == 0,
                              "detail": _last_line(out)})
        return steps
    if info["framework"] == "flask" and (root / "migrations").is_dir():
        code, out = _run([str(env.python), "-m", "flask", "db", "upgrade"], cwd=root, timeout=180, env=envvars)
        steps.append({"step": "flask db upgrade (temporary SQLite)", "ok": code == 0, "detail": _last_line(out)})
    elif info["framework"] == "django":
        code, out = _run([str(env.python), "manage.py", "migrate", "--noinput"], cwd=root, timeout=180, env=envvars)
        steps.append({"step": "manage.py migrate (temporary SQLite)", "ok": code == 0, "detail": _last_line(out)})
    return steps


def flask_routes(root: Path, env: Env, envvars: dict, limit: int = 5) -> list[str]:
    code, out = _run([str(env.python), "-m", "flask", "routes"], cwd=root, timeout=60, env=envvars)
    rules = []
    if code == 0:
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[-1].startswith("/") and "GET" in parts[-2] and "<" not in parts[-1] \
                    and not parts[-1].startswith("/static"):
                rules.append(parts[-1])
    rules = [r for r in set(rules) if not re.search(r"logout|delete|remove|reset", r)]
    rules = sorted(rules, key=lambda r: (r != "/", "login" not in r, len(r), r))
    return (["/"] + [r for r in rules if r != "/"])[: limit + 1]


def server_cmd(env: Env, info: dict, port: int) -> list[str]:
    fw = info["framework"]
    if info.get("mode") == "script":
        return [str(env.python), "-c", SCRIPT_WRAPPER, Path(info["app"]).name, str(port)]
    if fw == "flask":
        return [str(env.python), "-m", "flask", "run", "--host", "127.0.0.1", "--port", str(port), "--no-reload", "--no-debugger"]
    if fw == "fastapi":
        return [str(env.python), "-m", "uvicorn", info["app"], "--host", "127.0.0.1", "--port", str(port)]
    return [str(env.python), "manage.py", "runserver", f"127.0.0.1:{port}", "--noreload"]


def start_server(root: Path, env: Env, info: dict, envvars: dict, port: int, logfile: Path) -> subprocess.Popen:
    fh = open(logfile, "w", encoding="utf-8", errors="replace")
    flags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
    p = subprocess.Popen(server_cmd(env, info, port), cwd=app_dir(root, info), env=envvars, stdout=fh, stderr=subprocess.STDOUT,
                         creationflags=flags)
    p._guardian_log = fh  # type: ignore[attr-defined]
    return p


def stop_server(p: Optional[subprocess.Popen]) -> None:
    if p is None:
        return
    try:
        if p.poll() is None:
            if os.name == "nt":
                subprocess.run(["taskkill", "/PID", str(p.pid), "/T", "/F"], capture_output=True, timeout=20)
            else:
                p.terminate()
            p.wait(timeout=10)
    except Exception:
        try:
            p.kill()
        except Exception:
            pass
    fh = getattr(p, "_guardian_log", None)
    if fh:
        fh.close()


def wait_up(p: subprocess.Popen, url: str, timeout: float = 45.0) -> Optional[dict]:
    t0 = time.time()
    while time.time() - t0 < timeout:
        if p.poll() is not None:
            return None
        r = http_get(url, timeout=3)
        if r.get("status"):
            r["first_response_s"] = round(time.time() - t0, 1)
            return r
        time.sleep(0.5)
    return None


def boot(root: Path, env: Optional[Env], work: Path, max_routes: int = 5,
         step: Callable[[str], None] = lambda m: None) -> dict:
    """Start the app in the sandbox and request its routes. Never raises."""
    root, work = Path(root), Path(work)
    info = detect_app(root)
    res = {"framework": info["framework"], "app": info["app"], "detected": info["detail"]}
    if env is None:
        return {**res, "status": "skipped", "detail": "not started: the dependencies did not install"}
    if not info["framework"]:
        return {**res, "status": "skipped", "detail": info["detail"] + ": boot check skipped (not a failure)"}
    work.mkdir(parents=True, exist_ok=True)
    envvars = app_env(work, info)
    if info["framework"] == "fastapi":
        if _run([str(env.python), "-c", "import uvicorn"], timeout=60)[0] != 0:
            env.install(["uvicorn"], timeout=300)
    res["prepare"] = prepare(root, env, info, envvars)
    paths = (script_routes(root, info, max_routes) if info.get("mode") == "script" else
             flask_routes(root, env, envvars, max_routes) if info["framework"] == "flask" else ["/"])
    port = free_port()
    log = work / f"boot-{port}.log"
    step(f"starting the app ({info['detail']}) on 127.0.0.1:{port}…")
    p = start_server(root, env, info, envvars, port, log)
    try:
        first = wait_up(p, f"http://127.0.0.1:{port}/")
        if first is None:
            stop_server(p)
            out = _read(log)
            return {**res, "status": "failed", "detail": "the server did not answer: " + (crash_line(out) or "no output"),
                    "log": _tail(out, 6000), "python": env.full_version, "culprit": culprit_module(out)}
        if info["framework"] == "fastapi":
            try:
                import json as _json
                spec = _OPENER.open(f"http://127.0.0.1:{port}/openapi.json", timeout=5).read()
                paths = ["/"] + [k for k, v in _json.loads(spec).get("paths", {}).items() if "get" in v and "{" not in k][:max_routes]
            except Exception:
                pass
        routes = []
        for path in dict.fromkeys(paths):
            r = http_get(f"http://127.0.0.1:{port}{path}")
            routes.append({"path": path, **r})
    finally:
        stop_server(p)
    codes = [r["status"] for r in routes if r.get("status")]
    bad = [r for r in routes if (r.get("status") or 0) >= 500]
    ok = [c for c in codes if 200 <= c < 400]
    status = "healthy" if ok and not bad else "unhealthy"
    detail = ", ".join(f"{r['path']} {r.get('status') or 'no answer'}" for r in routes)
    return {**res, "status": status, "routes": routes, "detail": detail, "python": env.full_version,
            "first_response_s": first.get("first_response_s"), "log": _tail(_read(log), 4000)}


# ------------------------------------------------------------------ live run (page 5 "Run fixed app")
class LiveApps:
    _apps: dict[str, dict] = {}
    _lock = threading.Lock()

    @classmethod
    def status(cls, key: str) -> Optional[dict]:
        a = cls._apps.get(key)
        if a and a["proc"].poll() is not None:
            cls.stop(key)
            return None
        return {k: v for k, v in a.items() if k not in ("proc", "timer")} if a else None

    @classmethod
    def start(cls, key: str, root: Path, env: Env, work: Path) -> dict:
        with cls._lock:
            cls.stop(key)
            info = detect_app(root)
            if not info["framework"]:
                raise RuntimeError(info["detail"])
            envvars = app_env(work, info)
            if not (Path(work) / "guardian-boot.db").exists():
                prepare(root, env, info, envvars)
            port = free_port()
            p = start_server(root, env, info, envvars, port, Path(work) / f"live-{port}.log")
            first = wait_up(p, f"http://127.0.0.1:{port}/")
            if first is None:
                stop_server(p)
                raise RuntimeError("the app did not start: " + (error_line(_read(Path(work) / f"live-{port}.log")) or "no output"))
            t = threading.Timer(LIVE_MINUTES * 60, cls.stop, args=(key,))
            t.daemon = True
            t.start()
            cls._apps[key] = {"proc": p, "timer": t, "url": f"http://127.0.0.1:{port}/", "port": port,
                              "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                              "stops_after_min": LIVE_MINUTES, "python": env.full_version, "framework": info["framework"]}
            return cls.status(key)

    @classmethod
    def stop(cls, key: str) -> None:
        a = cls._apps.pop(key, None)
        if a:
            a["timer"].cancel()
            stop_server(a["proc"])


# ------------------------------------------------------------------ build-health search
def platform_tags() -> list[str]:
    p = sysconfig.get_platform().replace("-", "_").replace(".", "_")
    if p.startswith("win"):
        return [p]
    if p.startswith("linux"):
        return ["manylinux", "musllinux", "linux"]
    return ["macosx"]


def wheel_fits(filename: str, version: str) -> bool:
    """Does this wheel install on CPython `version` (e.g. "3.14") on this machine's platform?"""
    if not filename.endswith(".whl"):
        return False
    parts = filename[:-4].split("-")
    if len(parts) < 5:
        return False
    py, abi, plat = parts[-3].split("."), parts[-2].split("."), parts[-1].split(".")
    xy = version.replace(".", "")
    ok_py = f"cp{xy}" in py or ("py3" in py and "none" in abi) or (
        "abi3" in abi and any(t.startswith("cp3") and t[2:].isdigit() and int(t[2:]) <= int(xy) for t in py))
    if not ok_py:
        return False
    if "any" in plat:
        return True
    want = platform_tags()
    return any(any(t.startswith(w) or w in t for w in want) and ("amd64" in t or "x86_64" in t or "universal" in t or "arm64" in t)
               for t in plat)


def compatible_upgrade(vt, name: str, current: str, version: str) -> tuple[Optional[str], str]:
    """The smallest newer, non-yanked, non-prerelease version of `name` with a wheel for Python `version` and no
    known vulnerability. (version or None, reason)."""
    from packaging.version import InvalidVersion, Version
    proj = vt.project(name)
    if not proj or not proj.get("releases"):
        return None, f"no release list for {name} from the package index"
    try:
        cur = Version(current)
    except InvalidVersion:
        return None, f"cannot read the current version {current!r}"
    cands = []
    for ver, files in proj["releases"].items():
        try:
            v = Version(ver)
        except InvalidVersion:
            continue
        if v <= cur or v.is_prerelease or not files or all(f.get("yanked") for f in files):
            continue
        if any(wheel_fits(f.get("filename") or "", version) for f in files if not f.get("yanked")):
            cands.append(v)
    for v in sorted(cands):
        vul = vt.vulns_of(name, str(v))
        if vul:
            continue
        return str(v), f"{name} {v} is the first release after {current} with a wheel for Python {version}" + (
            "" if vul is not None else " (vulnerability data unavailable)")
    return None, f"no release of {name} after {current} ships a wheel for Python {version}"


def runtime_upgrade(vt, name: str, current: str, version: str) -> tuple[Optional[str], str]:
    """For a pin that installs but crashes on Python `version`: the smallest same-major release published after
    that Python came out (and with no known vulnerability)."""
    from packaging.version import InvalidVersion, Version
    since = PY_RELEASED.get(version)
    proj = vt.project(name)
    if not since or not proj or not proj.get("releases"):
        return None, f"no release data for {name}"
    cur = Version(current)
    cands = []
    for ver, files in proj["releases"].items():
        try:
            v = Version(ver)
        except InvalidVersion:
            continue
        up = min((f.get("upload_time_iso_8601") or f.get("upload_time") or "9999") for f in files) if files else "9999"
        if v > cur and not v.is_prerelease and up[:10] >= since and not all(f.get("yanked") for f in files):
            cands.append(v)
    cands.sort(key=lambda v: (v.major != cur.major, v))
    for v in cands:
        if not vt.vulns_of(name, str(v)):
            return str(v), (f"{name} {current} crashes at import on Python {version}; {v} is the first {name} release "
                            f"published after Python {version} came out ({since})")
    return None, f"no {name} release after Python {version} came out"


def _dist_for_module(out: Path, mod: str) -> str:
    from .common import read_json as _rj
    ci = _rj(Path(out) / "code_index.json", {}) or {}
    return (ci.get("import_name_to_distribution") or {}).get(mod) or mod


def build_health(out: Path, root: Path, log: Callable[[str], None] = lambda m: None) -> dict:
    """Install check on the target Python; when it fails on a pinned package without a wheel, bump that pin to the
    smallest compatible version and retry (at most MAX_BUMPS packages). Works on copies of the requirement files."""
    from .candidates import RepoFiles, VersionTools
    root = Path(root)
    tgt = target_python(root)
    res = {"target": tgt, "bumps": [], "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    reqs = runtime.requirement_files(root)
    if not reqs:
        res.update(status="n/a", detail="no requirements file: nothing to install-check")
        return res
    work = Path(tempfile.mkdtemp(prefix="guardian-buildhealth-"))
    try:
        scratch = work / "repo"
        for r in reqs:
            (scratch / r).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(root / r, scratch / r)
        log(f"build health: installing the dependencies on Python {tgt['version']} ({tgt['source']})…")
        first, env = install_check(scratch, tgt["version"], work / "env")
        res["before"] = {k: v for k, v in first.items() if k != "log"}
        res["before_log"] = first.get("log")
        if env is None:
            res.update(status="unavailable", detail=first["error"])
            return res
        vt = VersionTools(out, RepoFiles(scratch))
        cur = first
        for _ in range(MAX_BUMPS if not first["ok"] else 0):
            f = cur.get("failing")
            if not f or not f.get("package"):
                res.update(status="unfixable", detail=f"install fails for a reason Guardian cannot fix automatically: {cur['error']}")
                break
            rf = RepoFiles(scratch)
            lines = [(fn, line, m) for fn, line, m in rf.req_lines(f["package"]) if m.group(3) == "=="]
            if not lines:
                res.update(status="unfixable", detail=f"{f['package']} fails to install but is not pinned in a requirements file "
                                                      f"(a transitive dependency): {cur['error']}")
                break
            old = lines[0][2].group(4)
            new, why = compatible_upgrade(vt, f["package"], old, tgt["version"])
            if not new:
                res.update(status="unfixable", detail=why)
                break
            for fn, line, m in lines:
                p = scratch / fn
                p.write_text(p.read_text(encoding="utf-8").replace(line.rstrip("\r\n"), line.rstrip("\r\n").replace(f"=={old}", f"=={new}", 1), 1),
                             encoding="utf-8")
            res["bumps"].append({"package": m.group(1), "from": old, "to": new, "why": f"{f['reason']}; {why}",
                                 "error": cur["error"]})
            log(f"build health: {m.group(1)} {old} → {new}, retrying the install…")
            code, o, cmd = env.install(install_args(scratch), cwd=scratch)
            cur = {"ok": code == 0, "error": "" if code == 0 else error_line(o), "failing": None if code == 0 else parse_failure(o),
                   "python": env.full_version, "command": cmd}
            if code == 0:
                break
        else:
            if not first["ok"]:
                res.update(status="unfixable", detail=f"still failing after {MAX_BUMPS} pin bumps: {cur['error']}")
        if not cur["ok"]:
            return res
        # it installs: does it start? an old pin can install and still crash at import on a new Python
        app = work / "app"
        shutil.copytree(root, app, ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc", "venv", ".venv", "node_modules"))
        for r in reqs:
            shutil.copy2(scratch / r, app / r)
        for _ in range(MAX_BUMPS):
            log(f"build health: starting the app on Python {tgt['version']}…")
            b = boot(app, env, work / f"boot-{len(res['bumps'])}")
            res["boot"] = {k: v for k, v in b.items() if k != "log"}
            if b["status"] != "failed" or not b.get("culprit"):
                break
            dist = _dist_for_module(out, b["culprit"])
            rf = RepoFiles(scratch)
            lines = [(fn, line, m) for fn, line, m in rf.req_lines(dist) if m.group(3) == "=="]
            if lines and any(x.get("kind") == "runtime" and x["package"].lower() == lines[0][2].group(1).lower() for x in res["bumps"]):
                res["runtime_issue"] = f"still crashes in {b['culprit']} after bumping it once: {b['detail']}"
                break
            if not lines:
                res["runtime_issue"] = f"the app crashes in {b['culprit']} (not pinned): {b['detail']}"
                break
            name, old = lines[0][2].group(1), lines[0][2].group(4)
            new, why = runtime_upgrade(vt, name, old, tgt["version"])
            if not new:
                res["runtime_issue"] = why
                break
            for fn, line, m in lines:
                for d in (scratch, app):
                    fp = d / fn
                    fp.write_text(fp.read_text(encoding="utf-8").replace(line.rstrip("\r\n"), line.rstrip("\r\n").replace(f"=={old}", f"=={new}", 1), 1), encoding="utf-8")
            res["bumps"].append({"package": name, "from": old, "to": new, "why": why, "error": b["detail"], "kind": "runtime"})
            log(f"build health: {name} {old} → {new} (crashed at import), reinstalling…")
            code, o, cmd = env.install(install_args(scratch), cwd=scratch)
            if code != 0:
                res["runtime_issue"] = f"after bumping {name}: {error_line(o)}"
                break
        runs = (res.get("boot") or {}).get("status")
        if not res["bumps"]:
            res.update(status="ok", detail=f"installs on Python {first['python']}" + (" and starts" if runs == "healthy" else f" (boot: {runs})"))
        else:
            res.update(status="fixable", detail=f"installs{' and starts' if runs == 'healthy' else ''} on Python {env.full_version} after "
                                                f"{len(res['bumps'])} pin bump(s)" + (f"; still: {res['runtime_issue']}" if res.get("runtime_issue") else ""))
            res["after"] = {**cur, "ok": True, "python": env.full_version, "boot": runs}
        return res
    finally:
        shutil.rmtree(work, ignore_errors=True)
