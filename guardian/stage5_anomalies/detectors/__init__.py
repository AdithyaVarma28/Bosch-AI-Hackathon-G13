"""The 6 core detectors (deterministic). Each returns ``Signal``s with a fixed strength."""
from __future__ import annotations

from ..context import Stage5Context
from ..schema import Signal
from . import d1_typosquat, d2_unexpected, d3_updates, d4_install, d5_build_env, d6_lockfile


def run_detectors(ctx: Stage5Context) -> list[Signal]:
    sigs: list[Signal] = []
    for name, mod in (("D1", d1_typosquat), ("D2", d2_unexpected), ("D3", d3_updates)):
        try:
            sigs += mod.detect(ctx)
        except Exception as exc:  # one detector failing must not stop the others
            ctx.note("detector_errors", f"{name}: {type(exc).__name__}: {exc}")
    flagged = {s.subject for s in sigs if s.detector in ("D1", "D3")}
    for name, fn in (("D4", lambda: d4_install.detect(ctx, flagged)), ("D5", lambda: d5_build_env.detect(ctx)),
                     ("D6", lambda: d6_lockfile.detect(ctx))):
        try:
            sigs += fn()
        except Exception as exc:
            ctx.note("detector_errors", f"{name}: {type(exc).__name__}: {exc}")
    for i, s in enumerate(sigs, 1):
        s.signal_id = f"S-{i:03d}"
    return sigs
