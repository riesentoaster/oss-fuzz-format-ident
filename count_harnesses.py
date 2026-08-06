#!/usr/bin/env python3
"""Count all OSS-Fuzz projects and harnesses (from latest public builds)."""

from __future__ import annotations

import concurrent.futures
import os
import pathlib

import requests
from remotezip import RemoteZip

BASE = "https://storage.googleapis.com"
BUCKETS = [
    "clusterfuzz-builds",
    "clusterfuzz-builds-afl",
    "clusterfuzz-builds-honggfuzz",
    "clusterfuzz-builds-centipede",
    "clusterfuzz-builds-no-engine",
]
SKIP_PREFIX = ("afl-", "jazzer_")
SKIP_EXACT = {"centipede", "llvm-symbolizer"}
ROOT = pathlib.Path(__file__).resolve().parent


def harness_count(project: str) -> int:
    """Number of fuzz targets in the project's latest public build archive."""
    for bucket in BUCKETS:
        for san in ("address", "undefined", "memory", "none"):
            ver = requests.get(
                f"{BASE}/{bucket}/{project}/{project}-{san}-latest.version",
                timeout=30,
            )
            if not (ver.ok and ver.text.strip()):
                continue
            with RemoteZip(f"{BASE}/{bucket}/{project}/{ver.text.strip()}") as z:
                n = 0
                for info in z.infolist():
                    name = info.filename
                    # Match oss-fuzz/infra/helper.py:_get_fuzz_targets: top-level
                    # executables, minus engine/runtime helpers.
                    if "/" in name or info.is_dir() or "." in name:
                        continue
                    if name.startswith(SKIP_PREFIX) or name in SKIP_EXACT:
                        continue
                    if (info.external_attr >> 16) & 0o111:
                        n += 1
                return n
    return 0


def main() -> None:
    projects = sorted(
        p.name for p in (ROOT / "oss-fuzz" / "projects").iterdir() if p.is_dir()
    )
    workers = min(32, os.cpu_count() or 8)
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        total = sum(pool.map(harness_count, projects))
    print(f"{len(projects)} projects, {total} harnesses")


if __name__ == "__main__":
    main()
