"""Package URL helpers. PURL is the primary key for components across the whole system."""
import hashlib
import re


def normalize_name(name: str) -> str:
    """PEP 503 normalisation: lowercase, runs of [-_.] become a single '-'."""
    return re.sub(r"[-_.]+", "-", name).lower()


def make_purl(ecosystem: str, name: str, version: str) -> str:
    return f"pkg:{ecosystem}/{normalize_name(name)}@{version}"


def finding_id(cls: str, subject: str, locator: str) -> str:
    return hashlib.sha256(f"{cls}|{subject}|{locator}".encode()).hexdigest()[:12]
