"""Import name -> PyPI distribution. Without this, package <-> code linking breaks."""
from __future__ import annotations

from ..purl import normalize_pypi

FALLBACK = {
    "yaml": "PyYAML", "cv2": "opencv-python", "sklearn": "scikit-learn", "PIL": "Pillow", "bs4": "beautifulsoup4",
    "dateutil": "python-dateutil", "dotenv": "python-dotenv", "jwt": "PyJWT", "jose": "python-jose", "Crypto": "pycryptodome",
    "Cryptodome": "pycryptodomex", "OpenSSL": "pyOpenSSL", "google.protobuf": "protobuf", "magic": "python-magic",
    "serial": "pyserial", "usb": "pyusb", "wx": "wxPython", "gi": "PyGObject", "attr": "attrs", "pkg_resources": "setuptools",
    "setuptools": "setuptools", "flask_sqlalchemy": "Flask-SQLAlchemy", "flask_login": "Flask-Login",
    "flask_cors": "Flask-Cors", "flask_wtf": "Flask-WTF", "flask_migrate": "Flask-Migrate", "flask_restful": "Flask-RESTful",
    "rest_framework": "djangorestframework", "corsheaders": "django-cors-headers", "psycopg2": "psycopg2-binary",
    "MySQLdb": "mysqlclient", "multipart": "python-multipart", "socketio": "python-socketio", "engineio": "python-engineio",
    "telegram": "python-telegram-bot", "slugify": "python-slugify", "docx": "python-docx", "pptx": "python-pptx",
    "fitz": "PyMuPDF", "lxml": "lxml", "skimage": "scikit-image", "Levenshtein": "python-Levenshtein",
    "github": "PyGithub", "git": "GitPython", "zmq": "pyzmq", "nacl": "PyNaCl", "markdown": "Markdown",
    "jinja2": "Jinja2", "markupsafe": "MarkupSafe", "werkzeug": "Werkzeug", "itsdangerous": "itsdangerous",
    "google.cloud": "google-cloud-core", "googleapiclient": "google-api-python-client", "grpc": "grpcio",
    "websocket": "websocket-client", "pydantic_settings": "pydantic-settings", "typing_extensions": "typing-extensions",
    "sentry_sdk": "sentry-sdk", "slack_sdk": "slack-sdk", "sendgrid": "sendgrid", "dns": "dnspython", "ldap": "python-ldap",
    "win32api": "pywin32", "win32con": "pywin32", "pythoncom": "pywin32", "mpl_toolkits": "matplotlib", "_pytest": "pytest",
}


def build_dist_map(declared_pypi_names: list[str], import_names: set[str]) -> dict[str, str]:
    """Map each external top-level import to a distribution name using declared deps + fallback table."""
    declared = {normalize_pypi(n): n for n in declared_pypi_names}
    out: dict[str, str] = {}
    for imp in sorted(import_names):
        top = imp.split(".")[0]
        for cand in (imp, ".".join(imp.split(".")[:2]), top):
            if cand in FALLBACK:
                dist = FALLBACK[cand]
                out[top] = declared.get(normalize_pypi(dist), dist)
                break
        else:
            n = normalize_pypi(top)
            if n in declared:
                out[top] = declared[n]
            elif normalize_pypi(f"python-{top}") in declared:
                out[top] = declared[normalize_pypi(f"python-{top}")]
            elif normalize_pypi(f"py{top}") in declared:
                out[top] = declared[normalize_pypi(f"py{top}")]
            else:
                out[top] = top  # best guess: import name == distribution name (mapping_status=guessed)
    return out
