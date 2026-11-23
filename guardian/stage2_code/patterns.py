"""Sensitive-call categories. Patterns are fnmatch-style against alias-resolved dotted targets."""
from fnmatch import fnmatchcase

SENSITIVE: dict[str, tuple[str, ...]] = {
    "network": ("requests.*", "httpx.*", "urllib.request.*", "urllib3.*", "socket.*", "aiohttp.*", "http.client.*"),
    "subprocess": ("subprocess.*", "os.system", "os.popen", "os.spawn*", "os.exec*"),
    "code_exec": ("eval", "exec", "compile"),
    "deserialize": ("pickle.load", "pickle.loads", "cPickle.*", "marshal.load", "marshal.loads",
                    "yaml.load", "yaml.load_all", "yaml.unsafe_load*", "dill.*", "shelve.open",
                    "jsonpickle.decode"),
    "crypto": ("hashlib.md5", "hashlib.sha1"),
}
WRITE_MODE_CHARS = set("wax+")
BUILTIN_CALLS = {"eval", "exec", "compile", "open", "__import__"}
HTTP_VERBS = {"get", "post", "put", "delete", "patch", "head", "options"}
DJANGO_PATHS = {"django.urls.path", "django.urls.re_path", "django.conf.urls.url"}
DJANGO_INCLUDES = {"django.urls.include", "django.conf.urls.include"}
SAFE_YAML_LOADERS = {"SafeLoader", "CSafeLoader", "BaseLoader", "CBaseLoader"}


def categorize(target: str) -> str | None:
    for category, patterns in SENSITIVE.items():
        if any(fnmatchcase(target, p) for p in patterns):
            return category
    return None


def is_write_mode(mode: str) -> bool:
    return bool(WRITE_MODE_CHARS & set(mode))
