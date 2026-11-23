from guardian.purl import finding_id, make_purl, normalize_name


def test_make_purl_pep503():
    assert make_purl("pypi", "PyYAML", "6.0.1") == "pkg:pypi/pyyaml@6.0.1"
    assert make_purl("pypi", "Flask_Login", "0.6") == "pkg:pypi/flask-login@0.6"


def test_normalize_name_collapses_separators():
    assert normalize_name("Zope.Interface__x") == "zope-interface-x"


def test_finding_id_stable_and_distinct():
    a = finding_id("vuln", "pkg:pypi/a@1", "GHSA-1")
    assert a == finding_id("vuln", "pkg:pypi/a@1", "GHSA-1")
    assert a != finding_id("vuln", "pkg:pypi/a@1", "GHSA-2")
    assert len(a) == 12
