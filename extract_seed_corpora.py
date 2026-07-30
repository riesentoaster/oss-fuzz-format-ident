#!/usr/bin/env python3
"""Download OSS-Fuzz seed corpora and profile every seed with several identification tools.

Steps (--steps):

1. download — pull ``*_seed_corpus.zip`` members from each project's latest public
   GCS build archive into ``seed_corpora/<project>/``. Skips projects whose directory
   already exists.

2. profile — for every seed, record the filename extension plus what each tool says
   about the *content*: libmagic (MIME type and description), magika, and siegfried.
   Identical evidence recurs heavily inside a corpus, so seeds are collapsed into one
   JSON line per *distinct* combination with a ``count``, into ``raw_seeds.jsonl``.

   libmagic's description is recorded but deliberately not used for labelling — it hurt
   precision when measured, see ALGORITHM.md. It is kept because profiling costs hours
   and storing it leaves the question re-testable.

Labelling happens in ``identify.py``; see ``ALGORITHM.md`` for the reasoning.

Parallelism: one process per harness, each shelling out to batched tool invocations.
The Python side does almost nothing, so the GIL is irrelevant here.

Usage: python3 extract_seed_corpora.py [--steps download profile] [--workers N]
"""

from __future__ import annotations

import argparse
import collections
import concurrent.futures
import csv
import io
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile

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
SUFFIX = "_seed_corpus.zip"
ROOT = pathlib.Path(__file__).resolve().parent
OUT = ROOT / "seed_corpora"
RAW = ROOT / "raw_seeds.jsonl"

MAGIKA = next(
    (str(p) for p in (ROOT / ".venv/bin/magika",) if p.exists()), shutil.which("magika")
)
SF = next((str(p) for p in (ROOT / "tools/sf",) if p.exists()), shutil.which("sf"))
if not MAGIKA:
    sys.exit("magika not installed")
if not SF:
    sys.exit("siegfried not installed")
SF_HOME = ROOT / "tools/siegfried_home/siegfried"

BATCH = 8192  # seeds per `file` invocation
TOOL_TIMEOUT = 1800
DOWNLOAD_RETRIES = 5

# Seeds are unpacked here. Deliberately not /tmp: that is often a RAM-backed tmpfs, and a
# few of the largest corpora unpacked at once will exhaust it.
SCRATCH = ROOT / ".scratch"


def _parse_indexed(text: str, offset: int, count: int) -> list[str]:
    """Parse ``file``'s ``<index>: <label>`` output into a list aligned to seeds
    ``offset .. offset + count``.

    Seeds are extracted under numeric names, so the index anchors each line even when a
    label itself contains a newline (continuations are appended to the previous label).
    """
    labels = [""] * count
    last = None
    for line in text.split("\n"):
        head, sep, tail = line.partition(": ")
        if sep and head.isdigit() and 0 <= int(head) - offset < count:
            last = int(head) - offset
            labels[last] = tail.strip()
        elif last is not None and line:
            labels[last] += " " + line.strip()
    return labels


def _file_labels(dirpath: str, count: int, *flags: str) -> list[str]:
    """Run `file` once per BATCH seeds, reading paths from stdin.

    Flags must precede ``-f -``: `file` applies options in order, so anything after the
    file list is silently ignored.
    """
    labels: list[str] = []
    for start in range(0, count, BATCH):
        names = [str(i) for i in range(start, min(start + BATCH, count))]
        try:
            out = subprocess.run(
                ["file", *flags, "-f", "-"],
                input="\n".join(names).encode(),
                capture_output=True,
                cwd=dirpath,
                timeout=TOOL_TIMEOUT,
                check=False,
            ).stdout.decode(errors="replace")
        except subprocess.TimeoutExpired:
            out = ""
        labels.extend(_parse_indexed(out, start, len(names)))
    return labels


def _magika_labels(dirpath: str, count: int) -> list[str]:
    """magika labels, index-aligned. One process for the whole harness: model load dominates."""
    try:
        out = subprocess.run(
            [MAGIKA, "-r", "--format", "%p\t%l", "."],
            capture_output=True,
            cwd=dirpath,
            timeout=TOOL_TIMEOUT,
            check=False,
        ).stdout.decode(errors="replace")
    except subprocess.TimeoutExpired:
        return [""] * count
    labels = [""] * count
    for line in out.splitlines():
        path, _, label = line.rpartition("\t")
        name = os.path.basename(path.strip())
        if name.isdigit() and int(name) < count:
            labels[int(name)] = label.strip()
    return labels


def _siegfried_labels(dirpath: str, count: int) -> list[str]:
    """siegfried PRONOM format names, index-aligned (first match per seed wins)."""
    env = dict(os.environ)
    if SF_HOME.exists():
        env["SIEGFRIED_HOME"] = str(SF_HOME)
    try:
        out = subprocess.run(
            [SF, "-csv", "."],
            capture_output=True,
            cwd=dirpath,
            timeout=TOOL_TIMEOUT,
            env=env,
            check=False,
        ).stdout.decode(errors="replace")
    except subprocess.TimeoutExpired:
        return [""] * count
    labels = [""] * count
    for row in csv.DictReader(io.StringIO(out)):
        name = os.path.basename((row.get("filename") or "").strip())
        if name.isdigit() and int(name) < count and not labels[int(name)]:
            labels[int(name)] = (row.get("format") or "").strip()
    return labels


def profile_zip(task):
    """Profile one harness zip. Returns (status_line, [record, ...], seeds).

    Seeds are extracted under numeric names so that magika and siegfried judge content
    only: neither can peek at the extension, which keeps them independent of the
    filename channel the algorithm treats as a separate observer.

    Seeds sharing the same evidence are indistinguishable to ``identify.py``, so they are
    emitted once with a count. Corpora are highly repetitive: 4.2M seeds collapse to 334k
    rows, taking the profile from 704MB to 72MB and identify.py's load from 10s to 1s.
    """
    key, path = task
    start = time.time()
    with tempfile.TemporaryDirectory(dir=SCRATCH) as tmp:
        exts = []
        with zipfile.ZipFile(path) as zf:
            for info in (m for m in zf.infolist() if not m.is_dir()):
                with zf.open(info) as src, open(os.path.join(tmp, str(len(exts))), "wb") as dst:
                    shutil.copyfileobj(src, dst)
                exts.append(pathlib.PurePosixPath(info.filename).suffix.lstrip(".").lower())
        count = len(exts)
        channels = (
            _file_labels(tmp, count, "--mime-type"),
            _file_labels(tmp, count),
            _magika_labels(tmp, count),
            _siegfried_labels(tmp, count),
        )
    seen = collections.Counter(
        (exts[i], *(channel[i] for channel in channels)) for i in range(count)
    )
    records = [
        {"key": key, "ext": ext, "mime": mime, "desc": desc, "magika": magika,
         "sf": sf, "count": n}
        for (ext, mime, desc, magika, sf), n in seen.items()
    ]
    return (
        f"profiled {count} seeds as {len(records)} rows in {time.time() - start:.2f}s",
        records,
        count,
    )


def _harnesses(project):
    return [
        (f"{project}/{path.name[: -len(SUFFIX)]}", path)
        for path in sorted((OUT / project).rglob(f"*{SUFFIX}"))
    ]


def download(project):
    """Download seed-corpus zips for one project, retrying the whole attempt on error."""
    start = time.time()
    project_dir = OUT / project
    harnesses = _harnesses(project)
    if project_dir.is_dir():
        return (
            (f"{project}: {len(harnesses)} cached in {time.time() - start:.2f}s", harnesses)
            if harnesses
            else (None, [])
        )

    last_exc = None
    for attempt in range(1, DOWNLOAD_RETRIES + 1):
        try:
            for bucket in BUCKETS:
                for san in ("address", "undefined", "memory", "none"):
                    ver = requests.get(
                        f"{BASE}/{bucket}/{project}/{project}-{san}-latest.version",
                        timeout=30,
                    )
                    if ver.ok and ver.text.strip():
                        project_dir.mkdir(parents=True, exist_ok=True)
                        with RemoteZip(f"{BASE}/{bucket}/{project}/{ver.text.strip()}") as z:
                            for name in z.namelist():
                                if name.endswith(SUFFIX):
                                    z.extract(name, project_dir)
                        harnesses = _harnesses(project)
                        label = f"{len(harnesses)} seeds" if harnesses else "0 seeds"
                        return f"{project}: {label} in {time.time() - start:.2f}s", harnesses
            project_dir.mkdir(parents=True, exist_ok=True)
            return f"{project}: no build in {time.time() - start:.2f}s", []
        except Exception as exc:
            last_exc = exc
            if attempt < DOWNLOAD_RETRIES:
                time.sleep(min(2 ** (attempt - 1), 8))
    return f"{project}: error ({last_exc}) after {DOWNLOAD_RETRIES} tries", []


def discover(projects):
    """Find already-downloaded seed-corpus zips on disk."""
    work = []
    for project in sorted(set(projects)):
        work.extend(_harnesses(project))
    print(f"discovered {len(work)} seed-corpus zips")
    return work


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--max-projects", type=int, default=None)
    parser.add_argument("--raw", type=pathlib.Path, default=RAW, help="profile output path")
    parser.add_argument(
        "--workers", type=int, default=max(1, (os.cpu_count() or 8) // 8),
        help="parallel harnesses (each one drives several tool subprocesses)",
    )
    parser.add_argument(
        "--steps", nargs="+", default=["download", "profile"],
        choices=["download", "profile"],
    )
    args = parser.parse_args()

    projects = sorted(p.name for p in (ROOT / "oss-fuzz" / "projects").iterdir() if p.is_dir())
    if args.max_projects is not None:
        projects = projects[: args.max_projects]
    OUT.mkdir(parents=True, exist_ok=True)

    work = []
    if "download" in args.steps:
        print(f"downloading seed corpora for {len(projects)} projects...")
        start = time.time()
        skipped = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count() or 8) as pool:
            futures = {pool.submit(download, p): p for p in projects}
            for done, fut in enumerate(concurrent.futures.as_completed(futures), 1):
                try:
                    line, harnesses = fut.result()
                except Exception as exc:
                    print(f"[{done}/{len(projects)}] {futures[fut]}: error ({exc})")
                    continue
                if line:
                    print(f"[{done}/{len(projects)}] {line}")
                else:
                    skipped += 1
                work.extend(harnesses)
        print(f"downloaded {len(work)} zips in {time.time() - start:.2f}s", end="")
        if skipped:
            print(f" ({skipped} projects with no seeds, cached)", end="")
        print()

    if "profile" in args.steps:
        if not work:
            work = discover(projects)
        SCRATCH.mkdir(exist_ok=True)
        print("profiling with file, magika, siegfried")
        start, seeds = time.time(), 0
        with (
            args.raw.open("w") as raw,
            concurrent.futures.ProcessPoolExecutor(max_workers=args.workers) as pool,
        ):
            futures = {pool.submit(profile_zip, w): w[0] for w in work}
            for done, fut in enumerate(concurrent.futures.as_completed(futures), 1):
                key = futures[fut]
                try:
                    line, records, count = fut.result()
                except Exception as exc:
                    print(f"[{done}/{len(work)}] {key}: error ({exc})")
                    continue
                raw.writelines(json.dumps(r) + "\n" for r in records)
                seeds += count
                print(f"[{done}/{len(work)}] {key}: {line}")
        print(f"profiled {seeds} seeds from {len(work)} harnesses in {time.time() - start:.2f}s")
        print(f"wrote {args.raw.name}; now run identify.py")


if __name__ == "__main__":
    main()
