"""Package URL helpers. PURL is the primary key across SBOM, OSV, graph and findings."""
from __future__ import annotations

import re
from urllib.parse import quote, unquote


def normalize_pypi(name: str) -> str:
    """PEP 503 normalisation: PyYAML -> pyyaml, Foo_Bar.baz -> foo-bar-baz."""
    return re.sub(r"[-_.]+", "-", name).lower()


def normalize_name(ecosystem: str, name: str) -> str:
    return normalize_pypi(name) if ecosystem == "pypi" else name.lower() if ecosystem == "npm" else name


def make_purl(ecosystem: str, name: str, version: str | None) -> str:
    eco = {"npm": "npm", "pypi": "pypi"}.get(ecosystem, "generic")
    n = normalize_name(ecosystem, name)
    if eco == "npm" and n.startswith("@") and "/" in n:
        scope, pkg = n.split("/", 1)
        path = f"{quote(scope, safe='')}/{quote(pkg, safe='')}"
    else:
        path = quote(n, safe="")
    return f"pkg:{eco}/{path}" + (f"@{quote(version, safe='')}" if version else "")


def package_key(ecosystem: str, name: str) -> str:
    """Version-less package identity, used for the 'Package' layer of the graph."""
    return make_purl(ecosystem, name, None)


def parse_purl(purl: str) -> tuple[str, str, str | None]:
    """Return (ecosystem, name, version) from a purl. Qualifiers/subpaths are dropped."""
    m = re.match(r"^pkg:([^/]+)/(.+?)(?:@([^?#]+))?(?:[?#].*)?$", purl)
    if not m:
        raise ValueError(f"invalid purl: {purl}")
    eco, path, ver = m.groups()
    name = unquote(path)
    return eco, name, unquote(ver) if ver else None


PURL_RE = re.compile(r"^pkg:[a-z0-9.+-]+/[^@\s]+(@[^\s]+)?$")


def is_valid_purl(purl: str) -> bool:
    return bool(PURL_RE.match(purl))
