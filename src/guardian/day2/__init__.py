"""Day 2: Brain & Shield. Prioritize, investigate, remediate, approve, validate, rescan, verify.

Stages (see docs/day2_plan.md):
  S10 prioritize.py   explainable risk score + confidence -> ranked queue
  S11 threat.py       evidence-driven investigation of non-CVE supply-chain signals
  S12 candidates.py   candidate fixes (graph-aware), simulate.py (compatibility), tournament round 1
  S13 approval.py     immutable, hash-bound human approval
  S14 sandbox.py      apply in a throwaway branch, build, test (tournament round 2), selfcorrect.py
  S15 rescan.py       rerun the unchanged Day 1 pipeline on the patched tree, diff SBOM + findings
  S16 verify.py       deterministic verdict + independent verifier agent, policy.py, report.py
Orchestrated by pipeline.py (LangGraph, resumable at the approval gate through persisted state).
"""
