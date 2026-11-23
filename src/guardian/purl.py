"""Package URL helpers. PURL is the primary key across SBOM, OSV, graph and findings.

Supported ecosystems and the name convention used inside Guardian:
  npm       name            pkg:npm/%40scope/name@1.0.0
  pypi      name            pkg:pypi/pyyaml@6.0.1            (PEP 503 normalised)
  maven     group:artifact  pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1
  golang    module path     pkg:golang/github.com/gin-gonic/gin@v1.6.2
  cargo     crate           pkg:cargo/serde@1.0.100
  gem       gem             pkg:gem/rails@6.0.0
  composer  vendor/package  pkg:composer/monolog/monolog@2.0.0
  nuget     package id      pkg:nuget/newtonsoft.json@12.0.1
"""
from __future__ import annotations

import re
from urllib.parse import quote, unquote

ECOSYSTEMS = ("npm", "pypi", "maven", "golang", "cargo", "gem", "composer", "nuget")
PURL_TYPE = {e: e for e in ECOSYSTEMS}
OSV_ECOSYSTEM = {"npm": "npm", "pypi": "PyPI", "maven": "Maven", "golang": "Go", "cargo": "crates.io",
                 "gem": "RubyGems", "composer": "Packagist", "nuget": "NuGet"}
# language of source files -> ecosystem whose packages it imports
LANGUAGE_ECOSYSTEM = {"python": "pypi", "javascript": "npm", "typescript": "npm", "java": "maven", "kotlin": "maven",
                      "scala": "maven", "go": "golang", "rust": "cargo", "ruby": "gem", "php": "composer",
                      "csharp": "nuget", "fsharp": "nuget", "vb": "nuget"}


def normalize_pypi(name: str) -> str:
    """PEP 503 normalisation: PyYAML -> pyyaml, Foo_Bar.baz -> foo-bar-baz."""
    return re.sub(r"[-_.]+", "-", name).lower()


def normalize_name(ecosystem: str, name: str) -> str:
    if ecosystem == "pypi":
        return normalize_pypi(name)
    if ecosystem in ("npm", "composer", "nuget", "gem"):
        return name.lower()
    if ecosystem == "cargo":
        return name.lower().replace("_", "-")
    return name  # maven, golang: case-sensitive identifiers


def _seg(s: str) -> str:
    return quote(s, safe="")


def make_purl(ecosystem: str, name: str, version: str | None) -> str:
    eco = PURL_TYPE.get(ecosystem, "generic")
    n = normalize_name(ecosystem, name)
    if eco == "npm" and n.startswith("@") and "/" in n:
        scope, pkg = n.split("/", 1)
        path = f"{_seg(scope)}/{_seg(pkg)}"
    elif eco == "maven" and ":" in n:
        g, a = n.split(":", 1)
        path = f"{_seg(g)}/{_seg(a)}"
    elif eco in ("golang", "composer"):
        path = "/".join(_seg(p) for p in n.split("/"))
    else:
        path = _seg(n)
    return f"pkg:{eco}/{path}" + (f"@{quote(version, safe='+')}" if version else "")


def package_key(ecosystem: str, name: str) -> str:
    """Version-less package identity, used for the 'Package' layer of the graph."""
    return make_purl(ecosystem, name, None)


def parse_purl(purl: str) -> tuple[str, str, str | None]:
    """Return (ecosystem, name, version) from a purl. Qualifiers/subpaths are dropped."""
    m = re.match(r"^pkg:([^/]+)/(.+?)(?:@([^?#@]+))?(?:[?#].*)?$", purl)
    if not m:
        raise ValueError(f"invalid purl: {purl}")
    eco, path, ver = m.groups()
    parts = [unquote(p) for p in path.split("/")]
    if eco == "maven" and len(parts) >= 2:
        name = f"{'.'.join(parts[:-1]) if len(parts) > 2 else parts[0]}:{parts[-1]}"
    else:
        name = "/".join(parts)
    return eco, name, unquote(ver) if ver else None


PURL_RE = re.compile(r"^pkg:[a-z0-9.+-]+/[^@\s]+(@[^\s]+)?$")


def is_valid_purl(purl: str) -> bool:
    return bool(PURL_RE.match(purl))
