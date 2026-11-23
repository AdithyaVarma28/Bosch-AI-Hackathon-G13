"""Static pattern tables for the code index (facts, not judgments)."""
from __future__ import annotations

import re

SDK_SERVICES = {
    "stripe": "Stripe", "boto3": "AWS", "botocore": "AWS", "aiobotocore": "AWS", "twilio": "Twilio", "openai": "OpenAI",
    "anthropic": "Anthropic", "groq": "Groq", "sendgrid": "SendGrid", "google.cloud": "Google Cloud",
    "azure": "Azure", "firebase_admin": "Firebase", "slack_sdk": "Slack", "slack": "Slack", "redis": "Redis",
    "pymongo": "MongoDB", "motor": "MongoDB", "psycopg2": "PostgreSQL", "psycopg": "PostgreSQL", "asyncpg": "PostgreSQL",
    "pymysql": "MySQL", "mysql": "MySQL", "elasticsearch": "Elasticsearch", "kafka": "Kafka", "confluent_kafka": "Kafka",
    "pika": "RabbitMQ", "celery": "Celery broker", "sentry_sdk": "Sentry", "paypalrestsdk": "PayPal",
    "braintree": "Braintree", "mailchimp3": "Mailchimp", "github": "GitHub", "jira": "Jira", "dropbox": "Dropbox",
    "telegram": "Telegram", "discord": "Discord", "smtplib": "SMTP",
}

NETWORK_PREFIXES = ("requests.", "httpx.", "urllib.request.", "urllib3.", "aiohttp.", "http.client.", "socket.",
                    "ftplib.", "smtplib.", "websocket.", "websockets.", "pycurl.")
SUBPROCESS = ("subprocess.", "os.system", "os.popen", "os.exec", "os.spawn", "commands.", "pty.spawn", "asyncio.create_subprocess")
CODE_EXEC = {"eval", "exec", "compile", "builtins.eval", "builtins.exec", "runpy.run_path", "runpy.run_module"}
DESERIALIZE = {"pickle.load", "pickle.loads", "cPickle.load", "cPickle.loads", "marshal.load", "marshal.loads",
               "yaml.load", "yaml.unsafe_load", "yaml.load_all", "yaml.full_load", "shelve.open", "dill.load",
               "dill.loads", "jsonpickle.decode", "joblib.load", "torch.load", "pandas.read_pickle"}
FILE_WRITE_SUFFIX = ("write_text", "write_bytes")
FILE_WRITE = ("shutil.copy", "shutil.move", "shutil.rmtree", "os.remove", "os.unlink", "os.rename", "os.makedirs",
              "tempfile.mkstemp")
CRYPTO = ("hashlib.md5", "hashlib.sha1", "Crypto.", "Cryptodome.", "cryptography.", "ssl._create_unverified_context",
          "jwt.decode", "jwt.encode", "secrets.", "random.random", "random.randint")

DYNAMIC_IMPORT = {"importlib.import_module", "__import__", "importlib.__import__", "imp.load_source"}

ROUTE_METHODS = {"get", "post", "put", "delete", "patch", "head", "options", "websocket", "api_route"}

FLASK_INPUT_ATTRS = {"json", "args", "form", "files", "values", "data", "get_json", "cookies", "headers", "get_data", "stream"}
DJANGO_INPUT_ATTRS = {"POST", "GET", "body", "FILES", "COOKIES", "META", "data", "query_params"}

DB_WRITE = {"add", "add_all", "delete", "merge", "commit", "flush", "bulk_save_objects", "save", "create", "update",
            "bulk_create", "bulk_update", "get_or_create", "update_or_create", "insert", "insert_one", "insert_many",
            "update_one", "update_many", "delete_one", "delete_many"}
DB_READ = {"query", "get", "scalars", "scalar", "filter", "filter_by", "all", "first", "one", "exclude", "find", "find_one",
           "aggregate", "count", "select_related", "values"}
DB_RECEIVER = re.compile(r"(^|\.)(session|db|db\.session|Session|objects|cursor|conn|connection|collection|engine)$", re.I)
SQL_RE = re.compile(r"^\s*(select|insert|update|delete|create|drop|alter|with)\s", re.I)

ORM_BASES = {"Base", "db.Model", "Model", "models.Model", "DeclarativeBase", "SQLModel", "declarative_base()"}
FIELD_CALLS = {"Column", "mapped_column", "relationship", "Field", "db.Column", "db.relationship"}

URL_RE = re.compile(r"\bhttps?://[^\s'\"<>`]+", re.I)

TEST_FILE = re.compile(r"(^|/)(tests?|testing)/|(^|/)test_[^/]*\.py$|_test\.py$|(^|/)conftest\.py$")

BUILTINS = {"print", "len", "open", "range", "dict", "list", "set", "tuple", "int", "str", "float", "bool", "isinstance",
            "getattr", "setattr", "hasattr", "super", "sorted", "enumerate", "zip", "map", "filter", "min", "max", "sum",
            "any", "all", "repr", "type", "id", "iter", "next", "abs", "round", "format", "vars", "dir", "input",
            "eval", "exec", "compile", "__import__", "globals", "locals", "callable", "issubclass", "hash", "object",
            "property", "staticmethod", "classmethod", "Exception", "ValueError", "TypeError", "KeyError", "RuntimeError",
            "NotImplementedError", "bytes", "bytearray", "memoryview", "frozenset", "reversed", "slice", "chr", "ord"}


def is_test_path(path: str) -> bool:
    return bool(TEST_FILE.search(path))


def sensitive_category(target: str) -> str | None:
    if target in CODE_EXEC:
        return "code_exec"
    if target in DESERIALIZE:
        return "deserialize"
    if target.startswith(NETWORK_PREFIXES) or target in ("urllib.request.urlopen", "socket.create_connection"):
        return "network"
    if target.startswith(SUBPROCESS):
        return "subprocess"
    if target.startswith(FILE_WRITE) or target.endswith(FILE_WRITE_SUFFIX):
        return "file_write"
    if target.startswith(CRYPTO):
        return "crypto"
    return None


def sdk_service(import_name: str) -> str | None:
    if import_name in SDK_SERVICES:
        return SDK_SERVICES[import_name]
    top = import_name.split(".")[0]
    for k, v in SDK_SERVICES.items():
        if import_name.startswith(k + ".") or top == k:
            return v
    return None
