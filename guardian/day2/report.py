"""Page 6 "Report" (docs/DAY_2_COMPLETION_PLAN.md section 8): one minimalist, printable summary for a security lead.

report.json is the single source for the page and both exports (standalone HTML with inline CSS, and Markdown).
Vulnerability fixes and build-health fixes are kept apart; remaining and accepted risk is listed first-class.
"""
from __future__ import annotations

import html
from pathlib import Path

from .common import REGISTER_FILE, band_idx, load_remediations, now, read_json, write_json
from .fixed_repo import fixed_dir
from .history import read_audit

REPORT_FILE = "report.json"
METHODS = [
    "Prioritisation: SSVC-inspired decision table (exploitation, automatable, technical impact, mission) for CVEs, "
    "and a supply-chain table (suspicion × exposure) for other findings; the AI judges inputs, fixed rules decide.",
    "Sandbox install: every fix installed with the project's real dependencies in a throwaway environment, plus pip check.",
    "Project tests: the repository's own tests, run before and after each fix and on the combined fixed repository.",
    "Generated security tests: T1 exploit (fail → pass), T2 guard (fail → pass), T3 feature (pass → pass); "
    "a test counts only when Guardian observed the expected result.",
    "Combined rescan: the full Guardian scan run again on the fixed repository and compared finding by finding.",
]


def build(out: Path) -> dict:
    out = Path(out)
    reg = {e["finding_id"]: e for e in read_json(out / REGISTER_FILE, []) or []}
    units = load_remediations(out)
    fx = read_json(fixed_dir(out) / "result.json", {}) or {}
    meta = read_json(out / "scan.json", {}) or {}
    bh = read_json(out / "build_health.json", {}) or {}
    s = fx.get("summary") or {}
    rs = fx.get("rescan") or {}
    t = fx.get("tests") or {}
    included = {r["rid"]: r for r in fx.get("included") or []}
    by_rid = {u["rid"]: u for u in units}

    fixed, health = [], []
    for rid, r in included.items():
        u = by_rid.get(rid) or {}
        v = u.get("validation") or {}
        st = [x for x in (v.get("security_tests") or {}).get("tests") or [] if x.get("kept")]
        why = next((reg[f].get("priority_reasons") or [""] for f in u.get("finding_ids") or [] if f in reg), [""])
        row = {"rid": rid, "action": r["action"], "priority": r["priority"], "findings": r["findings"],
               "vuln_ids": r["vuln_ids"], "why": (why[-1] if why else "") or "",
               "tests": [{"kind": x.get("kind"), "name": x.get("name"), "title": x.get("title") or x.get("name"), "before": x.get("before"),
                          "after": x.get("after"), "as_expected": bool(x.get("as_expected")), "source": x.get("source") or "template"} for x in st],
               "fix_confidence": r.get("fix_confidence"), "approvers": r.get("approvers"), "commit": r.get("commit"),
               "validation": r.get("validation")}
        (health if r.get("kind") == "build_health" else fixed).append(row)

    remaining = []
    resolved = set(rs.get("resolved") or [])
    fixed_findings = {f for r in included.values() for f in r["findings"]}
    for u in sorted(units, key=lambda u: (-band_idx(u["priority"]), min(u.get("ranks") or [0]))):
        if u.get("target_kind") == "build_health" or u["rid"] in included:
            continue
        open_f = [f for f in u["finding_ids"] if f not in resolved]
        if not open_f:
            continue
        p = (u.get("proposals") or [{}])[u.get("current") or 0] if u.get("proposals") else {}
        rej = u.get("rejection") or {}
        status = ("accepted risk" if u.get("status") == "rejected" else
                  "no safe automatic fix (escalate)" if not p.get("edits") else
                  "fix proposed, not approved yet")
        remaining.append({"rid": u["rid"], "label": u["target_label"], "priority": u["priority"], "findings": open_f,
                          "status": status, "reason": rej.get("reason"), "by": rej.get("by"), "action": p.get("action")})
    accepted = sum(1 for r in remaining if r["status"] == "accepted risk")
    vb, va = rs.get("vulns_before"), rs.get("vulns_after")
    tgt = (fx.get("target") or bh.get("target") or {}).get("version")
    app_after = (s.get("app") or [None, None])[1]
    code = s.get("code")
    if fx.get("status") == "done" and code:
        verdict = (f"{code[0] - code[1]} of {code[0]} SQL-injection sites fixed in the code; app "
                   f"{'runs' if (s.get('app_ok') or [0, 0])[1] else app_after} on Python {tgt}; "
                   f"{len(t.get('regressions') or [])} test regression(s); {s['tests'].get('new_as_expected')} of "
                   f"{s['tests'].get('new')} security tests as expected; {code[1]} SQL-injection site(s) remaining.")
    elif fx.get("status") == "done" and vb is not None:
        verdict = (f"{vb - va} of {vb} known vulnerabilities fixed; app {'runs' if (s.get('app_ok') or [0, 0])[1] else app_after} "
                   f"on Python {tgt}; {len(t.get('regressions') or [])} test regression(s); {va} remaining ({accepted} accepted).")
    else:
        verdict = "No fixed repository built yet: approve fixes on the Remediation page, then build it on the Fixed repository page."
    ev = read_audit(out)
    keep = {"proposal_created", "review_decision", "validation_result", "validation_reused", "branch_applied", "apply_failed"}
    trail = [{"at": e.get("at"), "rid": e.get("rid"), "event": e.get("event"),
              "text": " · ".join(str(x) for x in (e.get("stage"), e.get("action"), e.get("status"), e.get("reviewer") and f"by {e['reviewer']}",
                                                  e.get("reason") and f"“{e['reason']}”", e.get("branch"), e.get("author")) if x)}
             for e in ev if e.get("event") in keep][-60:]
    approvers = sorted({a for r in included.values() for a in (r.get("approvers") or {}).values() if a})
    rep = {
        "generated_at": now(),
        "header": {"repo": fx.get("repo_name") or meta.get("repo"), "repo_url": meta.get("repo_url"),
                   "commit_before": (fx.get("head") or meta.get("commit") or "")[:10],
                   "fixed_branch": (fx.get("publish") or {}).get("branch"), "fixed_commit": ((fx.get("publish") or {}).get("commit") or "")[:10],
                   "scanned_at": meta.get("created_at"), "fixed_at": fx.get("finished_at"), "approvers": approvers,
                   "verdict": verdict, "target_python": tgt, "built": fx.get("status") == "done"},
        "before_after": ([{"what": "SQL-injection sites in the code (CWE-89)", "before": (s.get("code") or [None, None])[0],
                            "after": (s.get("code") or [None, None])[1]}] if s.get("code") else []) + [
            {"what": "Known vulnerabilities", "before": vb, "after": va},
            {"what": "… of them Critical/High", "before": (s.get("critical_high") or [None, None])[0], "after": (s.get("critical_high") or [None, None])[1]},
            {"what": "Supply-chain findings", "before": rs.get("supply_before"), "after": rs.get("supply_after")},
            {"what": f"Installs on Python {tgt}", "before": _yn(((fx.get("install") or {}).get("before") or {}).get("ok")),
             "after": _yn(((fx.get("install") or {}).get("after") or {}).get("ok"))},
            {"what": "App boots", "before": (s.get("app") or ["?", "?"])[0], "after": app_after},
            {"what": "Project tests passing", "before": _frac(t.get("project_before"), t.get("project_total")),
             "after": _frac(t.get("project_after"), t.get("project_total"))},
            {"what": "Guardian security tests as expected", "before": "—", "after": _frac(t.get("guardian_as_expected"), t.get("guardian_total"))},
        ] if fx.get("status") == "done" else [],
        "fixed": fixed, "build_health": health,
        "build_health_note": ("Build-health fixes are not vulnerability fixes: they bump pins that cannot be installed on the "
                              f"project's target Python ({tgt}), so the app can be deployed again.") if health else None,
        "skipped": fx.get("skipped") or [], "remaining": remaining, "new_findings": rs.get("new") or [],
        "sbom_diff": rs.get("sbom_diff"), "test_matrix": t.get("matrix") or [], "audit": trail, "methods": METHODS,
    }
    write_json(out / REPORT_FILE, rep)
    return rep


def _yn(x):
    return None if x is None else ("yes" if x else "no")


def _frac(a, b):
    return None if b in (None, 0) and a is None else f"{a or 0}/{b or 0}"


def _v(x) -> str:
    return "—" if x is None or x == "" else str(x)


# ------------------------------------------------------------------ exports
CSS = """body{font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;color:#1d2420;max-width:960px;margin:32px auto;padding:0 24px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:16px;margin:28px 0 8px;border-bottom:1px solid #dde3df;padding-bottom:4px}
.meta{color:#5d6a63;font-size:12px}.verdict{font-size:16px;background:#eef5f1;border-left:4px solid #1f6f54;padding:10px 14px;margin:14px 0}
table{border-collapse:collapse;width:100%;font-size:13px}th,td{border-bottom:1px solid #e6ebe8;padding:6px 8px;text-align:left;vertical-align:top}
th{color:#5d6a63;font-weight:600;font-size:12px}.ok{color:#1f6f54}.bad{color:#b3443a}code{font-size:12px}
details{margin:4px 0}small{color:#5d6a63}@media print{details{display:block}details>*{display:block}}"""


def to_html(rep: dict) -> str:
    e = lambda x: html.escape(_v(x))
    h = rep["header"]
    rows = lambda cols, data: "<table><tr>" + "".join(f"<th>{c}</th>" for c in cols) + "</tr>" + "".join(
        "<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in data) + "</table>"
    tmark = lambda x: f"<span class='{'ok' if x['as_expected'] else 'bad'}'>{x['kind']} {x['before']}→{x['after']}</span>"
    parts = [f"<!DOCTYPE html><html><head><meta charset='utf-8'><title>Guardian report — {e(h['repo'])}</title><style>{CSS}</style></head><body>",
             f"<h1>Guardian remediation report — {e(h['repo'])}</h1>",
             f"<div class='meta'>{e(h.get('repo_url'))} · commit {e(h['commit_before'])} → branch {e(h['fixed_branch'])} "
             f"{e(h['fixed_commit'])} · scanned {e(h['scanned_at'])} · fixed {e(h['fixed_at'])} · approved by {e(', '.join(h['approvers']))}</div>",
             f"<div class='verdict'>{e(h['verdict'])}</div>"]
    if rep["before_after"]:
        parts += ["<h2>Before → after</h2>", rows(["", "Before", "After"], [(e(r["what"]), e(r["before"]), e(r["after"])) for r in rep["before_after"]])]
    parts += ["<h2>What Guardian fixed</h2>", rows(["Fix", "Findings", "Priority · why", "Tests (before→after)", "Confidence", "Approved by"],
              [(f"<b>{e(r['rid'])}</b> {e(r['action'])}", e(", ".join(r["vuln_ids"])), f"{e(r['priority'])}<br><small>{e(r['why'])}</small>",
                " ".join(tmark(x) for x in r["tests"]) or "—", e(r["fix_confidence"]),
                e(" / ".join(f"{k}: {v}" for k, v in (r.get("approvers") or {}).items()))) for r in rep["fixed"]]) if rep["fixed"] else "<p>None yet.</p>"]
    if rep["build_health"]:
        parts += ["<h2>Build health (not vulnerability fixes)</h2>", f"<p><small>{e(rep['build_health_note'])}</small></p>",
                  rows(["Fix", "Tests", "Approved by"], [(f"<b>{e(r['rid'])}</b> {e(r['action'])}", " ".join(tmark(x) for x in r["tests"]) or "—",
                                                       e(" / ".join((r.get("approvers") or {}).values()))) for r in rep["build_health"]])]
    parts += ["<h2>Remaining and accepted risk</h2>", rows(["Item", "Priority", "Status", "Reason"],
              [(f"<b>{e(r['rid'])}</b> {e(r['label'])}<br><small>{e(', '.join(r['findings']))}</small>", e(r["priority"]), e(r["status"]),
                e(r.get("reason")) + (f" <small>({e(r['by'])})</small>" if r.get("by") else "")) for r in rep["remaining"]]) if rep["remaining"] else "<p>Nothing remaining.</p>"]
    if rep["skipped"]:
        parts += ["<p><b>Not composed (conflicts):</b> " + e("; ".join(f"{s['rid']}: {s['why']}" for s in rep["skipped"])) + "</p>"]
    if rep["new_findings"]:
        parts += ["<p><b>New in the rescan:</b> " + e("; ".join(f"{n['title']} ({n['risk']}{', needs a look' if not n['hard'] else ''})" for n in rep["new_findings"])) + "</p>"]
    if rep["test_matrix"]:
        parts += ["<h2>Test evidence</h2><details><summary>All tests, before → after</summary>",
                  rows(["Test", "Expected", "Before", "After", ""], [(f"<code>{e(m['test'])}</code>", e(m["expected"]), e(m["before"]), e(m["after"]),
                       "<span class='ok'>as expected</span>" if m["as_expected"] else "<span class='bad'>NOT as expected</span>") for m in rep["test_matrix"]]),
                  "</details>"]
    parts += ["<h2>Audit trail</h2><details><summary>Proposals, decisions, validations and commits</summary>",
              rows(["When", "Item", "Event"], [(e((a["at"] or "").replace("T", " ").replace("Z", "")), e(a["rid"]), f"{e(a['event'].replace('_', ' '))} <small>{e(a['text'])}</small>") for a in rep["audit"]]),
              "</details>", "<h2>How it was checked</h2><ol>" + "".join(f"<li>{e(m)}</li>" for m in rep["methods"]) + "</ol>",
              f"<p class='meta'>Generated by Guardian {e(rep['generated_at'])}</p></body></html>"]
    return "\n".join(parts)


def to_md(rep: dict) -> str:
    h = rep["header"]
    cell = lambda x: _v(x).replace("|", "\\|").replace("\n", " ")
    tbl = lambda cols, data: "\n".join(["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)] +
                                      ["| " + " | ".join(cell(c) for c in r) + " |" for r in data])
    tm = lambda r: " ".join(f"{x['kind']} {x['before']}→{x['after']}{'' if x['as_expected'] else ' (NOT as expected)'}" for x in r["tests"]) or "—"
    out = [f"# Guardian remediation report — {h['repo']}", "",
           f"{_v(h.get('repo_url'))} · commit {_v(h['commit_before'])} → branch `{_v(h['fixed_branch'])}` · approved by {', '.join(h['approvers']) or '—'}",
           "", f"**{h['verdict']}**", ""]
    if rep["before_after"]:
        out += ["## Before → after", "", tbl(["", "Before", "After"], [(r["what"], r["before"], r["after"]) for r in rep["before_after"]]), ""]
    out += ["## What Guardian fixed", "", tbl(["Fix", "Findings", "Priority", "Why", "Tests", "Confidence"],
            [(f"{r['rid']} {r['action']}", ", ".join(r["vuln_ids"]), r["priority"], r["why"], tm(r), r["fix_confidence"]) for r in rep["fixed"]])
            if rep["fixed"] else "None yet.", ""]
    if rep["build_health"]:
        out += ["## Build health (not vulnerability fixes)", "", rep["build_health_note"], "",
                tbl(["Fix", "Tests"], [(f"{r['rid']} {r['action']}", tm(r)) for r in rep["build_health"]]), ""]
    out += ["## Remaining and accepted risk", "", tbl(["Item", "Priority", "Status", "Reason"],
            [(f"{r['rid']} {r['label']}", r["priority"], r["status"], r.get("reason")) for r in rep["remaining"]]) if rep["remaining"] else "Nothing remaining.", ""]
    if rep["test_matrix"]:
        out += ["## Test evidence", "", tbl(["Test", "Expected", "Before", "After", "As expected"],
                [(m["test"], m["expected"], m["before"], m["after"], "yes" if m["as_expected"] else "NO") for m in rep["test_matrix"]]), ""]
    out += ["## Audit trail", "", tbl(["When", "Item", "Event"], [((a["at"] or "").replace("T", " ").replace("Z", ""), a["rid"], f"{a['event'].replace('_', ' ')} {a['text']}") for a in rep["audit"]]), "",
            "## How it was checked", ""] + [f"{i}. {m}" for i, m in enumerate(rep["methods"], 1)] + ["", f"_Generated by Guardian {rep['generated_at']}_", ""]
    return "\n".join(out)
