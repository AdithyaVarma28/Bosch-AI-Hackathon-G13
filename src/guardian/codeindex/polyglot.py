"""Usage layer for non-Python languages (Java/Kotlin/Scala, Go, Rust, Ruby, PHP, C#, plus JS/TS extras).

Static, regex-based and line-accurate. It extracts imports, HTTP routes, env-var reads, risky calls and URL
literals, then maps imports to packages of the matching ecosystem. There is no call graph for these languages
on Day 1: facts are attributed to the file (`<module>`), and coverage says so.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

from ..models import CodeFile, ExternalService, ImportRef, Route, SensitiveCall, SimpleRef
from ..purl import normalize_name
from . import patterns as P

EXT_LANG = {".java": "java", ".kt": "kotlin", ".kts": "kotlin", ".scala": "scala", ".go": "go", ".rs": "rust",
            ".rb": "ruby", ".rake": "ruby", ".php": "php", ".cs": "csharp"}

IMPORT_RES: dict[str, list[re.Pattern]] = {
    "java": [re.compile(r"^\s*import\s+(?:static\s+)?([\w.]+?)(?:\.\*)?\s*;")],
    "kotlin": [re.compile(r"^\s*import\s+([\w.]+?)(?:\.\*)?(?:\s+as\s+\w+)?\s*$")],
    "scala": [re.compile(r"^\s*import\s+([\w.]+?)(?:\.[{_*].*)?\s*$")],
    "rust": [re.compile(r"^\s*(?:pub(?:\([\w:]+\))?\s+)?use\s+(?:::)?(\w+)"), re.compile(r"^\s*extern\s+crate\s+(\w+)")],
    "ruby": [re.compile(r"""^\s*require\s*\(?\s*['"]([^'"]+)['"]""")],
    "php": [re.compile(r"^\s*use\s+(?:function\s+|const\s+)?\\?([A-Za-z_][\w\\]*\\[\w\\]+)")],
    "csharp": [re.compile(r"^\s*(?:global\s+)?using\s+(?:static\s+)?(?:\w+\s*=\s*)?([A-Z][\w.]*)\s*;")],
}
HTTP_WORDS = {"get", "post", "put", "delete", "patch", "any", "all", "handle", "handlefunc", "request", "resources",
              "resource", "match", "head", "options"}
REQUIRE_RELATIVE = re.compile(r"""^\s*require_relative\s*\(?\s*['"]([^'"]+)['"]""")
DECL_RES = {"java": re.compile(r"^\s*package\s+([\w.]+)\s*;"), "kotlin": re.compile(r"^\s*package\s+([\w.]+)"),
            "scala": re.compile(r"^\s*package\s+([\w.]+)"), "csharp": re.compile(r"^\s*namespace\s+([\w.]+)"),
            "php": re.compile(r"^\s*namespace\s+([\w\\]+)\s*;")}

ROUTE_RES: dict[str, list[tuple[re.Pattern, str]]] = {
    "java": [(re.compile(r'@(Get|Post|Put|Delete|Patch|Request)Mapping\s*\(\s*(?:value\s*=\s*|path\s*=\s*)?\{?\s*"([^"]*)"'), "spring"),
             (re.compile(r'@Path\s*\(\s*"([^"]+)"'), "jax-rs")],
    "go": [(re.compile(r'\.\s*(GET|POST|PUT|DELETE|PATCH|Get|Post|Put|Delete|Patch|Any|Handle|HandleFunc)\(\s*"(/[^"]*)"'), "go-http")],
    "rust": [(re.compile(r'#\[(get|post|put|delete|patch)\(\s*"([^"]+)"'), "actix/rocket"),
             (re.compile(r'\.route\(\s*"([^"]+)"\s*,\s*(get|post|put|delete|patch)'), "axum")],
    "ruby": [(re.compile(r"""^\s*(get|post|put|patch|delete)\s+['"]([^'"]+)['"]"""), "rails/sinatra"),
             (re.compile(r"^\s*(resources?)\s+:(\w+)"), "rails")],
    "php": [(re.compile(r"""Route::(get|post|put|patch|delete|any|match)\(\s*['"]([^'"]+)"""), "laravel"),
            (re.compile(r"""(?:#\[|@)Route\(\s*['"]([^'"]+)"""), "symfony")],
    "csharp": [(re.compile(r'\[Http(Get|Post|Put|Delete|Patch)(?:\s*\(\s*"([^"]*)")?'), "aspnet"),
               (re.compile(r'\.Map(Get|Post|Put|Delete|Patch)\(\s*"([^"]+)"'), "aspnet-minimal")],
    "javascript": [(re.compile(r"""\b(?:app|router|server|fastify|api)\.(get|post|put|delete|patch|all)\(\s*['"`](/[^'"`]*)"""), "express")],
}
ROUTE_RES["kotlin"] = ROUTE_RES["java"]
ROUTE_RES["scala"] = ROUTE_RES["java"]

ENV_RES = {
    "java": [re.compile(r'System\.getenv\(\s*"(\w+)"')], "kotlin": [re.compile(r'System\.getenv\(\s*"(\w+)"')],
    "scala": [re.compile(r'(?:sys\.env|System\.getenv)\(\s*"(\w+)"')],
    "go": [re.compile(r'os\.(?:Getenv|LookupEnv)\(\s*"(\w+)"')],
    "rust": [re.compile(r'env::var(?:_os)?\(\s*"(\w+)"'), re.compile(r'env!\(\s*"(\w+)"')],
    "ruby": [re.compile(r"""ENV\[\s*['"](\w+)['"]"""), re.compile(r"""ENV\.fetch\(\s*['"](\w+)['"]""")],
    "php": [re.compile(r"""getenv\(\s*['"](\w+)['"]"""), re.compile(r"""\$_(?:ENV|SERVER)\[\s*['"](\w+)['"]"""),
            re.compile(r"""\benv\(\s*['"](\w+)['"]""")],
    "csharp": [re.compile(r'Environment\.GetEnvironmentVariable\(\s*"(\w+)"')],
    "javascript": [re.compile(r"process\.env\.(\w+)"), re.compile(r"""process\.env\[\s*['"](\w+)['"]""")],
}

SINKS: dict[str, list[tuple[str, re.Pattern]]] = {
    "java": [("subprocess", re.compile(r"Runtime\.getRuntime\(\)\.exec|new\s+ProcessBuilder")),
             ("deserialize", re.compile(r"new\s+ObjectInputStream|\.readObject\(\)|XMLDecoder|enableDefaultTyping|new\s+Yaml\(\)")),
             ("code_exec", re.compile(r"ScriptEngineManager|GroovyShell|\.eval\(")),
             ("network", re.compile(r"new\s+URL\(|HttpClient|OkHttpClient|RestTemplate|WebClient|HttpURLConnection")),
             ("crypto", re.compile(r'MessageDigest\.getInstance\(\s*"(MD5|SHA-?1)"|Cipher\.getInstance\(\s*"DES')),
             ("file_write", re.compile(r"new\s+FileOutputStream|Files\.write"))],
    "go": [("subprocess", re.compile(r"exec\.Command(Context)?\(")),
           ("network", re.compile(r"http\.(Get|Post|PostForm|NewRequest(WithContext)?)\(|net\.Dial|\.Do\(req")),
           ("crypto", re.compile(r"\b(md5|sha1)\.(New|Sum)|InsecureSkipVerify:\s*true")),
           ("deserialize", re.compile(r"gob\.NewDecoder")), ("code_exec", re.compile(r"plugin\.Open\(")),
           ("file_write", re.compile(r"os\.(Create|WriteFile|OpenFile)\("))],
    "rust": [("subprocess", re.compile(r"Command::new\(")), ("network", re.compile(r"reqwest::|hyper::Client|TcpStream::connect")),
             ("deserialize", re.compile(r"bincode::deserialize|serde_pickle")),
             ("file_write", re.compile(r"File::create\(|fs::write\(")), ("code_exec", re.compile(r"\bunsafe\s*\{"))],
    "ruby": [("subprocess", re.compile(r"\bsystem\(|%x\{|Open3\.|IO\.popen|\bexec\(|`[^`]*#\{")),
             ("code_exec", re.compile(r"\beval\(|instance_eval|class_eval|\.constantize")),
             ("deserialize", re.compile(r"Marshal\.load|YAML\.(unsafe_)?load\(|Psych\.load\(")),
             ("network", re.compile(r"Net::HTTP|HTTParty|Faraday|RestClient|open-uri|URI\.open")),
             ("file_write", re.compile(r"File\.write|File\.open\([^)]*['\"][wa]"))],
    "php": [("subprocess", re.compile(r"\b(shell_exec|exec|system|passthru|proc_open|popen)\s*\(|`[^`]*\$")),
            ("code_exec", re.compile(r"\beval\s*\(|\bassert\s*\(\s*\$|create_function|\binclude\s*\(?\s*\$")),
            ("deserialize", re.compile(r"\bunserialize\s*\(")),
            ("network", re.compile(r"curl_exec|file_get_contents\(\s*['\"]https?|GuzzleHttp|fsockopen")),
            ("file_write", re.compile(r"file_put_contents|fwrite\(|move_uploaded_file")),
            ("crypto", re.compile(r"\bmd5\s*\(|\bsha1\s*\(|mcrypt_"))],
    "csharp": [("subprocess", re.compile(r"Process\.Start\(")),
               ("deserialize", re.compile(r"BinaryFormatter|NetDataContractSerializer|LosFormatter|TypeNameHandling\.(All|Auto|Objects)")),
               ("network", re.compile(r"HttpClient|WebClient|WebRequest\.Create")),
               ("crypto", re.compile(r"MD5\.Create|SHA1\.Create|DESCryptoServiceProvider")),
               ("code_exec", re.compile(r"CSharpScript|Assembly\.Load\(")), ("file_write", re.compile(r"File\.Write"))],
    "javascript": [("network", re.compile(r"\bfetch\(|axios\.|https?\.request\(|\bgot\(")),
                   ("file_write", re.compile(r"fs\.(writeFile|appendFile|createWriteStream)")),
                   ("deserialize", re.compile(r"node-serialize|\.unserialize\(")),
                   ("code_exec", re.compile(r"vm\.runIn|new\s+Function\("))],
}
SINKS["kotlin"] = SINKS["java"]
SINKS["scala"] = SINKS["java"]

RUBY_STDLIB = {"json", "set", "net/http", "uri", "openssl", "yaml", "psych", "securerandom", "digest", "fileutils", "time", "date",
               "logger", "csv", "erb", "socket", "open3", "base64", "tempfile", "pathname", "optparse", "benchmark", "english",
               "forwardable", "singleton", "ostruct", "stringio", "zlib", "open-uri", "pp", "timeout", "monitor", "thread",
               "rbconfig", "digest/sha1", "digest/md5", "net/https", "bigdecimal", "io/console", "shellwords", "find", "etc",
               "delegate", "observer", "strscan", "ipaddr", "resolv", "webrick", "rubygems", "bundler", "bundler/setup", "objspace"}
RUST_STD = {"std", "core", "alloc", "proc_macro", "test"}
RUST_INTERNAL = {"crate", "self", "super"}
JAVA_STD = ("java.", "javax.", "jdk.", "sun.", "com.sun.", "kotlin.", "scala.", "android.", "dalvik.")
SDK_KEYWORDS = {"stripe": "Stripe", "aws": "AWS", "amazonaws": "AWS", "twilio": "Twilio", "openai": "OpenAI", "sendgrid": "SendGrid",
                "firebase": "Firebase", "slack": "Slack", "redis": "Redis", "mongo": "MongoDB", "pgx": "PostgreSQL",
                "npgsql": "PostgreSQL", "postgres": "PostgreSQL", "mysql": "MySQL", "kafka": "Kafka", "rabbitmq": "RabbitMQ",
                "amqp": "RabbitMQ", "elasticsearch": "Elasticsearch", "sentry": "Sentry", "google-cloud": "Google Cloud",
                "cloud.google": "Google Cloud", "azure": "Azure", "anthropic": "Anthropic", "groq": "Groq", "paypal": "PayPal",
                "braintree": "Braintree", "mailgun": "Mailgun", "auth0": "Auth0", "okta": "Okta"}


def _strip_comment(line: str, lang: str) -> str:
    if lang in ("ruby",):
        return "" if line.lstrip().startswith("#") else line
    s = line.lstrip()
    return "" if s.startswith(("//", "/*", "*")) else line


def index_polyglot(cf: CodeFile, text: str, lang: str) -> None:
    """Fills imports (kind decided later), routes, env reads, sinks and URLs for one file."""
    lines = text.splitlines()
    mod = f"{cf.path}::<module>"
    if lang == "go":
        _go_imports(cf, lines)
    for i, raw in enumerate(lines, 1):
        line = _strip_comment(raw, lang)
        if not line.strip():
            continue
        for rx in IMPORT_RES.get(lang, []):
            m = rx.match(line)
            if m:
                cf.imports.append(ImportRef(name=m.group(1).rstrip("\\").replace("\\\\", "\\"), kind="unknown", line=i))
        if lang == "ruby":
            m = REQUIRE_RELATIVE.match(line)
            if m:
                cf.imports.append(ImportRef(name=m.group(1), kind="internal", line=i))
        for rx, fw in ROUTE_RES.get(lang, []):
            for m in rx.finditer(line):
                g = [x for x in m.groups() if x is not None]
                if len(g) == 1:
                    method, path = (g[0], "/") if g[0].lower() in HTTP_WORDS else ("ANY", g[0])
                else:
                    method, path = (g[0], g[1]) if g[0].lower() in HTTP_WORDS else (g[1], g[0])
                if fw == "rails" and method.startswith("resource"):
                    method, path = "RESOURCES", f"/{path}"
                if lang in ("java", "kotlin", "scala") and method in ("Request",):
                    method = "ANY"
                cf.routes.append(Route(framework=fw, method=method.upper(), path=path or "/", handler=mod, line=i))
        for rx in ENV_RES.get(lang, []):
            for m in rx.finditer(line):
                cf.env_reads.append(SimpleRef(function=mod, name=m.group(1), line=i, how=rx.pattern.split("\\")[0][:30]))
        for cat, rx in SINKS.get(lang, []):
            m = rx.search(line)
            if m:
                cf.sensitive_calls.append(SensitiveCall(function=mod, category=cat, target=m.group(0)[:60], line=i))
        if lang != "javascript":
            for m in P.URL_RE.finditer(line):
                url = m.group(0).rstrip(").,;'\"")
                cf.string_urls.append(SimpleRef(function=mod, name=url, line=i, detail=urlparse(url).hostname))
        if lang in ("java", "kotlin") and re.search(r"Class\.forName\(|\.loadClass\(", line):
            cf.dynamic_imports.append(SimpleRef(function=mod, name="<reflection>", line=i, how="Class.forName"))
    cf.discovered_by = "regex"


def _go_imports(cf: CodeFile, lines: list[str]) -> None:
    in_block = False
    for i, raw in enumerate(lines, 1):
        s = raw.strip()
        if s.startswith("import ("):
            in_block = True
            continue
        if in_block:
            if s.startswith(")"):
                in_block = False
                continue
            m = re.match(r'^(?:[\w.]+\s+)?"([^"]+)"', s)
            if m:
                cf.imports.append(ImportRef(name=m.group(1), kind="unknown", line=i))
            continue
        m = re.match(r'^import\s+(?:[\w.]+\s+)?"([^"]+)"', s)
        if m:
            cf.imports.append(ImportRef(name=m.group(1), kind="unknown", line=i))


def declared_namespaces(cf: CodeFile, text: str, lang: str) -> set[str]:
    rx = DECL_RES.get(lang)
    if not rx:
        return set()
    return {m.group(1) for line in text.splitlines()[:200] for m in [rx.match(line)] if m}


# ----------------------------------------------------------------------------- mapping imports -> packages
class PackageMapper:
    """Maps import names to package names of one ecosystem, using resolved + declared packages and hints."""

    def __init__(self, packages: dict[str, set[str]], hints: dict[str, dict[str, str]], own: dict[str, set[str]]):
        self.packages = packages      # ecosystem -> package names
        self.hints = hints            # ecosystem -> {namespace prefix -> package}
        self.own = own                # language -> namespaces / modules / crates declared in this repo

    def map(self, lang: str, name: str) -> tuple[str, str | None, str]:
        """-> (kind, package or None, mapping_status mapped|guessed|unmapped)."""
        fn = getattr(self, f"_{lang}", None)
        return fn(name) if fn else ("unknown", None, "unmapped")

    def _known(self, eco: str) -> set[str]:
        return self.packages.get(eco, set())

    def _java(self, name: str):
        if name.startswith(JAVA_STD):
            return "stdlib", None, "mapped"
        if any(name == o or name.startswith(o + ".") for o in self.own.get("java", set())):
            return "internal", None, "mapped"
        segs = name.split(".")
        best, best_score = None, 0
        for pkg in self._known("maven"):
            g, _, a = pkg.partition(":")
            gs = g.split(".")
            shared = 0
            for x, y in zip(segs, gs):
                if x != y:
                    break
                shared += 1
            if shared < 2:
                continue
            score = shared * 2 + (2 if shared == len(gs) else 0)
            score += sum(1 for t in re.split(r"[-_.]", a) if len(t) >= 4 and t in segs)
            if score > best_score:
                best, best_score = pkg, score
        if best:
            return "external", best, "mapped" if best_score >= 5 else "guessed"
        return "external", None, "unmapped"

    _kotlin = _java
    _scala = _java

    def _go(self, name: str):
        first = name.split("/")[0]
        if "." not in first:
            return "stdlib", None, "mapped"
        own = self.own.get("go", set())
        if any(name == o or name.startswith(o + "/") for o in own):
            return "internal", None, "mapped"
        cands = [m for m in self._known("golang") if name == m or name.startswith(m + "/")]
        if cands:
            return "external", max(cands, key=len), "mapped"
        parts = name.split("/")
        guess = "/".join(parts[:3]) if first in ("github.com", "gitlab.com", "bitbucket.org") else "/".join(parts[:2])
        return "external", guess, "guessed"

    def _rust(self, name: str):
        if name in RUST_STD:
            return "stdlib", None, "mapped"
        if name in RUST_INTERNAL or name in self.own.get("rust", set()):
            return "internal", None, "mapped"
        crate = normalize_name("cargo", name)
        known = {normalize_name("cargo", k) for k in self._known("cargo")}
        return ("external", crate, "mapped") if crate in known else ("external", crate, "guessed")

    def _ruby(self, name: str):
        if name.lower() in RUBY_STDLIB or name.split("/")[0] in RUBY_STDLIB:
            return "stdlib", None, "mapped"
        known = {normalize_name("gem", k) for k in self._known("gem")}
        first = name.split("/")[0]
        for cand in (name.replace("/", "-"), first, first.replace("_", "-")):
            if cand.lower() in known:
                return "external", cand.lower(), "mapped"
        return "external", first.lower(), "guessed"

    def _php(self, name: str):
        ns = name.replace("\\\\", "\\") + "\\"
        own = self.hints.get("composer:own", {})
        if any(ns.startswith(p) for p in own) or any(ns.startswith(o.replace("\\\\", "\\") + "\\") for o in self.own.get("php", set())):
            return "internal", None, "mapped"
        cands = [(p, pkg) for p, pkg in self.hints.get("composer", {}).items() if ns.startswith(p.replace("\\\\", "\\"))]
        if cands:
            return "external", max(cands, key=lambda x: len(x[0]))[1], "mapped"
        return "unknown", None, "unmapped"

    def _csharp(self, name: str):
        low = name.lower()
        cands = [p for p in self._known("nuget") if low == p.lower() or low.startswith(p.lower() + ".")]
        if cands:
            return "external", max(cands, key=len), "mapped"
        if any(name == o or name.startswith(o + ".") for o in self.own.get("csharp", set())):
            return "internal", None, "mapped"
        if name.split(".")[0] in ("System", "Microsoft", "Windows"):
            return "stdlib", None, "mapped"
        return "unknown", None, "unmapped"


def sdk_services_for(cf: CodeFile) -> None:
    """External services from SDK packages (any ecosystem) and from URLs in files that make network calls."""
    seen = {s.name for s in cf.external_services}
    for imp in cf.imports:
        if imp.kind != "external" or not imp.distribution:
            continue
        low = imp.distribution.lower()
        for k, svc in SDK_KEYWORDS.items():
            if k in low and svc not in seen:
                seen.add(svc)
                cf.external_services.append(ExternalService(name=svc, via="sdk", import_name=imp.name, line=imp.line))
                break
    if any(s.category == "network" for s in cf.sensitive_calls):
        for u in cf.string_urls:
            if u.detail and u.detail not in seen and not u.detail.endswith(("example.com", "localhost")):
                seen.add(u.detail)
                cf.external_services.append(ExternalService(name=u.detail, via="url", domain=u.detail, line=u.line))
