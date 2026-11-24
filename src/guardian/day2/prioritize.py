"""S10 Prioritize: an explainable 0-100 risk score per finding, a separate confidence, and a work queue.

Factors (each shown in the report with its points):
  severity        CVSS band, or the strength of a non-CVE signal
  exploitability  CISA KEV, malicious-package advisory, EPSS, several independent strong signals
  reachability    vulnerable symbol called > route reaches importing code > package imported > not referenced
  exposure        network-facing service vs CLI/library (Day 1 dossier), exposed container, CI with secrets
  production use  runtime vs dev/test scope, direct vs transitive, depth
  criticality     what the code using the component touches: exec/deserialize, DB, secrets, auth/payment routes
  policy          a block-rule violation always lands in Fix now
The Day 1 band stays the coarse order; the score ranks inside a band. Rules only: the breakdown is reproducible.
"""
from __future__ import annotations

import re

from ..context import RunContext
from ..models import Finding
from ..purl import package_key, parse_purl
from ..scoring import _is_malicious_advisory, package_name
from .models import Investigation, RiskFactor, RiskScore
from .policy import Policy, triage_violations

SEVERITY_POINTS = {"Critical": 30, "High": 22, "Medium": 12, "Low": 5, "None": 0}
SENSITIVE_ROUTE = re.compile(r"(login|auth|token|password|passwd|admin|checkout|pay|billing|account|session|upload|webhook)", re.I)
SECRET_ENV = re.compile(r"(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|DATABASE_URL|DSN)", re.I)
BAND_ORDER = {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "Unprioritized": 4}


def _component(ctx: RunContext, subject: str):
    return next((c for c in ctx.components if c.purl == subject), None)


def _advisory_symbols(ctx: RunContext, f: Finding) -> list[str]:
    """Vulnerable symbols named by the advisory (OSV ecosystem_specific.imports[].symbols), if any."""
    try:
        from ..detectors.osv import make_osv
        from ..httpcache import CachedHttp
        osv = make_osv(ctx.settings, CachedHttp(ctx.settings.cache_dir, offline=True))
        rec = osv.get_vuln(f.signals.get("advisory_id", "")) or {}
    except Exception:  # offline cache miss, bad snapshot: reachability just stays coarser
        return []
    out = []
    for aff in rec.get("affected") or []:
        for imp in (aff.get("ecosystem_specific") or {}).get("imports") or []:
            out += [s for s in imp.get("symbols") or [] if isinstance(s, str)]
        out += [s for s in (aff.get("database_specific") or {}).get("vulnerable_functions") or [] if isinstance(s, str)]
    return sorted(set(out))


def _code_files(ctx: RunContext, paths: set[str]):
    if not ctx.code_index:
        return []
    return [cf for cf in ctx.code_index.files if cf.path in paths]


def reachability(ctx: RunContext, f: Finding) -> tuple[str, str, list[str]]:
    """(level, detail, importing files)."""
    if f.cls != "vuln" or not ctx.graph:
        return "n/a", "not a package vulnerability", []
    blast = ctx.graph.blast_radius(f.subject) or {}
    files = [m for m in blast.get("importing_modules", []) if m]
    symbols = _advisory_symbols(ctx, f)
    if symbols and ctx.code_index:
        for cf in _code_files(ctx, set(files)):
            for call in cf.calls:
                tgt = (call.resolved_target or call.target or "")
                if any(tgt == s or tgt.endswith("." + s) for s in symbols):
                    return "function_reachable", f"vulnerable symbol `{tgt}` called in {cf.path}:{call.line}", files
    if blast.get("exposed_routes"):
        return "route_reachable", f"code importing it is reachable from {len(blast['exposed_routes'])} route(s)", files
    if files:
        return "imported", f"imported in {len(files)} file(s) (static reference, not proof of use)", files
    eco = parse_purl(f.subject)[0] if f.subject.startswith("pkg:") else None
    covered = bool(ctx.code_index and ctx.code_index.files and eco and any(
        cf.language in {"python": ["python"], "npm": ["javascript", "typescript"]}.get(eco, []) for cf in ctx.code_index.files))
    if covered and eco in ("pypi", "npm"):
        return "not_referenced", "no source file imports it or a package that depends on it", files
    return "unknown", "no code index for this ecosystem", files


def criticality(ctx: RunContext, files: list[str], f: Finding) -> tuple[str, float, str]:
    """What the code that uses the component touches. Returns (label, points, detail)."""
    if f.cls == "secret":
        return "critical", 12, "credential material"
    if f.cls == "ci":
        wf = next((w for w in (ctx.facts.ci_workflows if ctx.facts else []) if f.subject == w.file or f.locator.startswith(w.file)), None)
        uses_secrets = bool(wf and getattr(wf, "secrets_used", None))
        return ("high", 8, "workflow uses repository secrets") if uses_secrets else ("normal", 4, "CI workflow")
    if f.cls == "container":
        return "normal", 3, "build/runtime image"
    if not files or not ctx.code_index:
        return "unknown", 0, "no code using it was indexed"
    pts, why = 0.0, []
    cfs = _code_files(ctx, set(files))
    cats = {s.category for cf in cfs for s in cf.sensitive_calls}
    if cats & {"code_exec", "deserialize", "subprocess"}:
        pts += 8
        why.append("near " + "/".join(sorted(cats & {"code_exec", "deserialize", "subprocess"})))
    if "crypto" in cats:
        pts += 5
        why.append("crypto")
    if any(cf.db_access or cf.db_models for cf in cfs):
        pts += 6
        why.append("database access")
    if any(SECRET_ENV.search(e.name) for cf in cfs for e in cf.env_reads):
        pts += 4
        why.append("reads secrets from env")
    routes = [r for cf in cfs for r in cf.routes]
    if ctx.graph:
        blast = ctx.graph.blast_radius(f.subject) or {}
        routes_s = [str(r) for r in blast.get("exposed_routes", [])]
    else:
        routes_s = []
    if any(SENSITIVE_ROUTE.search(r.path) for r in routes) or any(SENSITIVE_ROUTE.search(r) for r in routes_s):
        pts += 5
        why.append("auth/payment/upload route")
    if any(cf.external_services for cf in cfs):
        pts += 2
        why.append("calls external services")
    pts = min(pts, 15)
    label = "critical" if pts >= 12 else "high" if pts >= 7 else "normal" if pts >= 2 else "low"
    return label, pts, ", ".join(why) or "plain library use"


def score_finding(ctx: RunContext, f: Finding, policy: Policy | None, trust: dict[str, int],
                  investigations: dict[str, Investigation] | None = None) -> RiskScore:
    s = f.signals
    factors: list[RiskFactor] = []
    conf_reasons: list[str] = []
    # severity
    if f.cls == "vuln":
        band = s.get("severity_band")
        factors.append(RiskFactor(name="severity", points=SEVERITY_POINTS.get(band or "", 8),
                                  detail=f"{band or 'unknown'}" + (f" CVSS {s['cvss']}" if s.get("cvss") else "")))
    elif f.cls == "secret":
        factors.append(RiskFactor(name="severity", points=25, detail="hard-coded credential"))
    else:
        factors.append(RiskFactor(name="severity", points={"C": 22, "S": 20, "W": 8}[f.classification],
                                  detail={"C": "confirmed", "S": "strong signal", "W": "weak signal"}[f.classification]))
    # exploitability
    ex = 0.0
    exd = []
    if s.get("kev"):
        ex += 25
        exd.append("CISA KEV")
    if f.cls == "vuln" and _is_malicious_advisory(s):
        ex += 30
        exd.append("malicious-package advisory")
    epss = s.get("epss")
    if isinstance(epss, (int, float)):
        if epss >= 0.5:
            ex += 15
        elif epss >= 0.1:
            ex += 7
        exd.append(f"EPSS {epss:.2f}")
    n_trust = trust.get(package_name(f.subject), 0)
    if f.cls == "anomaly" and n_trust >= 2:
        ex += 15
        exd.append(f"{n_trust} independent strong signals on this package")
    inv = (investigations or {}).get(f.id)
    if inv and inv.verdict == "likely_malicious":
        ex += 25
        exd.append("investigation: likely malicious")
    elif inv and inv.verdict == "suspicious":
        ex += 8
        exd.append("investigation: suspicious")
    if f.cls == "vuln" and not exd:
        conf_reasons.append("no KEV/EPSS data (offline or not listed)")
    factors.append(RiskFactor(name="exploitability", points=ex, detail=", ".join(exd) or "no exploitation data"))
    # reachability
    level, rdetail, files = reachability(ctx, f)
    rpts = {"function_reachable": 25, "route_reachable": 20, "imported": 10, "not_referenced": -5, "unknown": 5, "n/a": 0}[level]
    factors.append(RiskFactor(name="reachability", points=rpts, detail=f"{level}: {rdetail}"))
    if level == "unknown":
        conf_reasons.append("reachability unknown (not downgraded)")
    elif level in ("route_reachable", "imported"):
        conf_reasons.append("reachability from static references only")
    # exposure
    exposure = ctx.dossier.exposure if ctx.dossier else "unknown"
    epts = {"network_facing": 10, "cli_or_library": 3, "unknown": 5}[exposure]
    edet = exposure
    if f.cls == "container" and ctx.facts and any(sv.ports for sv in ctx.facts.config.compose_services):
        epts += 3
        edet += ", container publishes ports"
    factors.append(RiskFactor(name="exposure", points=epts, detail=edet))
    # production use
    comp = _component(ctx, f.subject) if f.subject.startswith("pkg:") else None
    scope = s.get("scope") or (comp.scope if comp else None)
    if f.cls in ("ci", "container", "secret"):
        ppts, pdet = 5, "build/release path"
    elif scope in ("dev", "test", "optional", "build"):
        ppts, pdet = -10, f"{scope} scope only"
    elif scope == "prod":
        ppts, pdet = 10, "runtime scope"
    else:
        ppts, pdet = 3, "scope unknown"
    if comp is not None:
        if comp.direct:
            ppts += 3
            pdet += ", direct"
        else:
            depth = min((len(p) for p in (s.get("all_paths") or [])), default=0)
            pdet += f", transitive (depth {depth or '?'})"
            if depth > 3:
                ppts -= 2
        if comp.source == "manifest":
            conf_reasons.append("version from manifest range, not a lockfile")
    factors.append(RiskFactor(name="production_use", points=ppts, detail=pdet))
    # criticality
    clabel, cpts, cdet = criticality(ctx, files, f)
    factors.append(RiskFactor(name="criticality", points=cpts, detail=f"{clabel}: {cdet}"))
    # policy
    violations = triage_violations(policy, f, investigations) if policy else []
    block = [v for v in violations if (policy.rule(v) or {}).get("severity") == "block"] if policy else []
    if block:
        factors.append(RiskFactor(name="policy", points=5, detail="violates " + ", ".join(block)))
    total = int(max(0, min(100, round(sum(x.points for x in factors)))))
    # confidence (data quality)
    sbom_conf = ctx.sbom_report.confidence if ctx.sbom_report else "low"
    if f.cls == "vuln":
        conf = sbom_conf
        if sbom_conf != "high":
            conf_reasons.append(f"SBOM confidence {sbom_conf}")
    else:
        conf = {"C": "high", "S": "medium", "W": "low"}[f.classification]
        conf_reasons.append(f"signal classification {f.classification}")
    if comp is not None and comp.source == "manifest" and conf == "high":
        conf = "medium"
    if level == "unknown" and conf == "high":
        conf = "medium"
    # bucket
    band = f.band or "Unprioritized"
    if block:
        bucket, why = "fix_now", "policy block rule: " + ", ".join(block)
    elif band == "P0":
        bucket, why = "fix_now", f"band P0 ({f.band_reason})"
    elif band == "P1" and level != "not_referenced":
        bucket, why = "fix_now", f"band P1 ({f.band_reason})"
    elif band in ("P1", "P2"):
        bucket, why = "schedule", f"band {band}" + (" but not referenced from code" if level == "not_referenced" else "")
    else:
        bucket, why = "monitor", f"band {band}"
    if f.cls in ("sbom_quality",):
        bucket, why = "monitor", "coverage gap, not a finding about the application"
    return RiskScore(finding_id=f.id, title=f.title, subject=f.subject, band=f.band, total=total, factors=factors,
                     reachability=level if level in ("function_reachable", "route_reachable", "imported", "not_referenced",
                                                     "unknown", "n/a") else "unknown",
                     criticality=clabel, confidence=conf, confidence_reasons=sorted(set(conf_reasons)), bucket=bucket,
                     bucket_reason=why, needs_human=total >= 60 and conf == "low", policy_violations=violations)


def prioritize(ctx: RunContext, findings: list[Finding], policy: Policy | None,
               investigations: dict[str, Investigation] | None = None) -> list[RiskScore]:
    trust: dict[str, int] = {}
    for f in findings:
        if f.classification == "S" and f.cls == "anomaly":
            trust[package_name(f.subject)] = trust.get(package_name(f.subject), 0) + 1
    scores = [score_finding(ctx, f, policy, trust, investigations) for f in findings if f.status == "open"]
    bucket_order = {"fix_now": 0, "schedule": 1, "monitor": 2}
    return sorted(scores, key=lambda r: (bucket_order[r.bucket], BAND_ORDER.get(r.band or "", 9), -r.total, r.title))


def plan_key_for(f: Finding) -> str:
    """Findings that one change fixes share a plan: all advisories of one package version, or one file rule."""
    if f.subject.startswith("pkg:"):
        try:
            eco, name, ver = parse_purl(f.subject)
            return f"{package_key(eco, name)}@{ver}" if ver else package_key(eco, name)
        except ValueError:
            pass
    return f"{f.cls}:{f.subject}:{f.signals.get('rule') or f.signals.get('signal') or f.locator}"
