"""Stage 2 output (code_index.json), produced with stdlib `ast` only."""
from typing import Literal

from pydantic import BaseModel


class ImportRef(BaseModel):
    name: str
    alias: str | None = None
    kind: Literal["internal", "external", "stdlib"]
    line: int
    in_try_except: bool = False
    conditional: bool = False
    resolved_file: str | None = None
    distribution: str | None = None


class Definition(BaseModel):
    id: str
    type: Literal["function", "async_function", "class", "method", "async_method"]
    name: str
    line: int
    end_line: int
    decorators: list[str] = []
    params: list[str] = []
    docstring: str | None = None


class CallRef(BaseModel):
    caller: str
    target: str
    kind: Literal["internal", "external", "stdlib"]
    import_name: str | None = None
    line: int


class Route(BaseModel):
    framework: Literal["flask", "fastapi", "django"]
    method: str
    path: str
    handler: str
    line: int


class EnvRead(BaseModel):
    var: str
    how: str
    line: int


class SensitiveCall(BaseModel):
    category: Literal["network", "subprocess", "code_exec", "deserialize", "file_write", "crypto"]
    target: str
    line: int


class StringUrl(BaseModel):
    url: str
    line: int


class DynamicImport(BaseModel):
    expr: str
    line: int


class CliEntrypoint(BaseModel):
    kind: Literal["main_guard", "click", "typer", "argparse"]
    name: str
    line: int


class FileIndex(BaseModel):
    path: str
    module_path: str
    package_dir: str
    sha256: str
    loc: int
    is_test: bool
    parse_error: str | None = None
    docstring: str | None = None
    imports: list[ImportRef] = []
    definitions: list[Definition] = []
    calls: list[CallRef] = []
    routes: list[Route] = []
    cli_entrypoints: list[CliEntrypoint] = []
    env_reads: list[EnvRead] = []
    sensitive_calls: list[SensitiveCall] = []
    string_urls: list[StringUrl] = []
    dynamic_imports: list[DynamicImport] = []


class CodeIndex(BaseModel):
    source_roots: list[str] = []
    import_name_to_distribution: dict[str, str] = {}
    files: list[FileIndex] = []
    errors: list[str] = []
