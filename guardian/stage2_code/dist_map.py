"""Import name -> PyPI distribution. Never guesses outside the curated table and the resolved set."""
from collections.abc import Callable

from guardian.purl import normalize_name

# Common cases where the import name differs from the distribution name.
CURATED: dict[str, str] = {
    "yaml": "PyYAML", "PIL": "Pillow", "cv2": "opencv-python", "sklearn": "scikit-learn",
    "bs4": "beautifulsoup4", "jwt": "PyJWT", "dateutil": "python-dateutil", "dotenv": "python-dotenv",
    "OpenSSL": "pyOpenSSL", "Crypto": "pycryptodome", "Cryptodome": "pycryptodomex", "magic": "python-magic",
    "serial": "pyserial", "usb": "pyusb", "attr": "attrs", "markdown": "Markdown", "git": "GitPython",
    "jose": "python-jose", "ldap": "python-ldap", "slugify": "python-slugify", "psycopg2": "psycopg2-binary",
    "MySQLdb": "mysqlclient", "zmq": "pyzmq", "skimage": "scikit-image", 
"pkg_resources": "setuptools", "docx": "python-docx", "pptx": "python-pptx", "wx": "wxPython",
    "gi": "PyGObject", "Xlib": "python-xlib", "socks": "PySocks", "engineio": "python-engineio",
    "socketio": "python-socketio", "flask_cors": "Flask-Cors", "flask_login": "Flask-Login",
    "flask_sqlalchemy": "Flask-SQLAlchemy", "flask_migrate": "Flask-Migrate", "crispy_forms": "django-crispy-forms",
    "rest_framework": "djangorestframework", "allauth": "django-allauth", "dj_database_url": "dj-database-url",
    "openid": "python3-openid", "argon2": "argon2-cffi", "chatterbot": "ChatterBot", "multipart": "python-multipart",
    "Bio": "biopython", "lxml": "lxml", "mx": "egenix-mx-base", "win32api": "pywin32", "yaml_include": "pyyaml-include",
}


# Other distributions that provide the same import name; a resolved package beats the curated default.
ALTERNATES: dict[str, tuple[str, ...]] = {
    "Crypto": ("pycrypto",), "psycopg2": ("psycopg2",), "jwt": ("jwt",), "PIL": ("PIL",),
    "yaml": ("pyyaml",), "git": ("git",), "attr": ("attr",), "magic": ("filemagic",),
}


class ImportMap(dict):
    """import name -> distribution, plus the resolved packages and any explicit installed-env entries."""

    def __init__(self, *args, resolved_norm: dict[str, str] | None = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.resolved_norm = resolved_norm or {}
        self.installed: set[str] = set()


def build_import_map(resolved, installed_dists: Callable[[], dict[str, list[str]]] | None = None) -> ImportMap:
    m = ImportMap(CURATED, resolved_norm={normalize_name(r.name): r.name for r in resolved})
    if installed_dists is not None:
        for import_name, dists in installed_dists().items():
            if dists:
                m[import_name] = dists[0]
                m.installed.add(import_name)
    return m


def map_import(name: str, m: ImportMap) -> str | None:
    top = name.split(".")[0]
    if top in m.installed:  # measured from a real environment: authoritative
        return m[top]
    candidates = ([m[top]] if top in m else []) + list(ALTERNATES.get(top, ()))
    for cand in candidates:  # what the project actually resolved wins over the curated default
        if normalize_name(cand) in m.resolved_norm:
            return m.resolved_norm[normalize_name(cand)]
    if normalize_name(top) in m.resolved_norm:
        return m.resolved_norm[normalize_name(top)]
    return m[top] if top in m else None
