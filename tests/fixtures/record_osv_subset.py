"""Record the OSV records that affect the full mini-shop fixture into a small zip laid out like the
official PyPI dump (``<ID>.json`` per record), so Stage 4 tests run offline and deterministically.

    python tests/fixtures/record_osv_subset.py            # needs network; rewrites tests/data/osv_minishop.zip
"""
from __future__ import annotations

import json
import re
import sys
import zipfile
from pathlib import Path

import httpx

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from make_mini_shop_full import BASE_LOCK  # noqa: E402

DEST = HERE.parent / "data" / "osv_minishop.zip"
EXTRA = [("PyYAML", "6.0.1"), ("PyYAML", "5.4.1"), ("minishop-utils", "1.0"), ("minishop-utils", "1.1"),
         ("shopfront-theme", "2.4.0"), ("shopfront-theme", "2.4.1"), ("reqeusts", "2.31.0")]


def main() -> None:
    pkgs = [(n, v) for n, v, _, _ in BASE_LOCK] + EXTRA
    body = {"queries": [{"package": {"name": n, "ecosystem": "PyPI"}, "version": v} for n, v in pkgs]}
    res = httpx.post("https://api.osv.dev/v1/querybatch", json=body, timeout=60).json()
    ids = sorted({v["id"] for r in res["results"] for v in r.get("vulns", []) or []})
    DEST.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(DEST, "w", zipfile.ZIP_DEFLATED) as z:
        for vid in ids:
            rec = httpx.get(f"https://api.osv.dev/v1/vulns/{vid}", timeout=30).json()
            z.writestr(f"{re.sub(r'[^A-Za-z0-9._-]', '_', vid)}.json", json.dumps(rec))
    print(f"{len(ids)} records for {len(pkgs)} package versions -> {DEST}")


if __name__ == "__main__":
    main()
