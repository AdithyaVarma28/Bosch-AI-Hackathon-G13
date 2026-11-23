"""Contracts, PURL, store, ingest URL handling."""
import hashlib
import sqlite3

import pytest
from pydantic import ValidationError

from guardian.ingest import InvalidRepoUrl, parse_repo_url
from guardian.models import Claim, finding_id
from guardian.purl import make_purl, parse_purl


def test_make_purl_scoped_npm():
    assert make_purl("npm", "@scope/pkg", "1.2.3") == "pkg:npm/%40scope/pkg@1.2.3"


def test_pypi_purl_normalised():
    assert make_purl("pypi", "PyYAML", "6.0.1") == "pkg:pypi/pyyaml@6.0.1"
    assert parse_purl("pkg:npm/%40scope/pkg@1.2.3") == ("npm", "@scope/pkg", "1.2.3")


def test_finding_id_stable_and_distinct():
    a = finding_id("vuln", "pkg:npm/a@1", "GHSA-1")
    assert a == finding_id("vuln", "pkg:npm/a@1", "GHSA-1") != finding_id("vuln", "pkg:npm/a@1", "GHSA-2")
    assert len(a) == 12


def test_evidence_content_addressed(store):
    a = store.add_evidence("raw", "osv", "x", "hello")
    b = store.add_evidence("raw", "osv", "x", "hello")
    assert a.id == b.id and a.id.startswith("ev_") and a.sha256 == hashlib.sha256(b"hello").hexdigest()


def test_evidence_is_immutable(store):
    e = store.add_evidence("raw", "t", "l", "x")
    with pytest.raises(sqlite3.DatabaseError):
        store.conn.execute("UPDATE evidence SET excerpt='y' WHERE id=?", (e.id,))
    with pytest.raises(sqlite3.DatabaseError):
        store.conn.execute("DELETE FROM evidence WHERE id=?", (e.id,))


def test_fact_claim_requires_evidence():
    with pytest.raises(ValidationError):
        Claim(text="t", type="fact", evidence_ids=[], confidence="high")


@pytest.mark.parametrize("u", ["https://github.com/o/r", "https://github.com/o/r.git", "https://github.com/o/r/",
                               "https://github.com/o/r/tree/dev", "http://github.com/o/r"])
def test_url_variants_parse(u):
    assert parse_repo_url(u)[:2] == ("o", "r")


def test_tree_branch_extracted():
    assert parse_repo_url("https://github.com/o/r/tree/dev")[2] == "dev"


@pytest.mark.parametrize("u", ["https://gitlab.com/o/r", "https://github.com/o", "not a url", "https://github.com/o/r/../x"])
def test_bad_urls_rejected(u):
    with pytest.raises(InvalidRepoUrl):
        parse_repo_url(u)
