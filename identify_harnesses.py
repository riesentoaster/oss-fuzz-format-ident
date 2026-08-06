#!/usr/bin/env python3
"""Download OSS-Fuzz seed corpora, profile seeds, and identify harness input formats.

Steps (--steps):

1. download — pull ``*_seed_corpus.zip`` members from each project's latest public
   GCS build archive into ``data/seed_corpora/<project>/``. Skips projects whose
   directory already exists.

2. profile — for every seed, record the filename extension plus what each tool says
   about the *content*: libmagic (MIME type and description), magika, and siegfried.
   Identical evidence recurs heavily inside a corpus, so seeds are collapsed into one
   JSON line per *distinct* combination with a ``count``, into ``data/raw_seeds.jsonl``.

   libmagic's description is recorded but deliberately not used for labelling — it hurt
   precision when measured, see ALGORITHM.md. It is kept because profiling costs hours
   and storing it leaves the question re-testable.

3. identify — decide each harness's input format from the profile, writing
   ``data/identified.json``, ``data/formats.json``, and ``data/mapped_formats.json``.
   See ``ALGORITHM.md`` for the reasoning; in short:

     * Every tool output is an opaque symbol. The code never inspects, splits or rewrites a
       label, and contains no table of formats. The only knowledge it holds is which outputs
       mean "I have nothing to say".
     * Two labels denote the same format when they land on the same seeds: restricted to the
       seeds where both observers spoke, each label predicts the other. Connected components
       of that relation are the format identities.
     * A seed is confirmed when two independent observers put linked labels on *it*, not on
       some other seed. A harness is confident when one identity dominates its confirmed
       seeds.

Parallelism: one process per harness, each shelling out to batched tool invocations.
The Python side does almost nothing, so the GIL is irrelevant here.

Usage: python3 identify_harnesses.py [--steps download profile identify] [--workers N]
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

MAGIKA = next(
    (str(p) for p in (ROOT / ".venv/bin/magika",) if p.exists()), shutil.which("magika")
)
SF = next((str(p) for p in (ROOT / "tools/sf",) if p.exists()), shutil.which("sf"))
SF_HOME = ROOT / "tools/siegfried_home/siegfried"

BATCH = 8192  # seeds per `file` invocation
TOOL_TIMEOUT = 1800
DOWNLOAD_RETRIES = 5


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

    Seeds sharing the same evidence are indistinguishable to the identify step, so they are
    emitted once with a count. Corpora are highly repetitive: 4.2M seeds collapse to 334k
    rows, taking the profile from 704MB to 72MB and identify's load from 10s to 1s.
    """
    key, path = task
    start = time.time()
    with tempfile.TemporaryDirectory() as tmp:
        exts = []
        with zipfile.ZipFile(path) as zf:
            for info in (m for m in zf.infolist() if not m.is_dir()):
                with (
                    zf.open(info) as src,
                    open(os.path.join(tmp, str(len(exts))), "wb") as dst,
                ):
                    shutil.copyfileobj(src, dst)
                exts.append(
                    pathlib.PurePosixPath(info.filename).suffix.lstrip(".").lower()
                )
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
        {
            "key": key,
            "ext": ext,
            "mime": mime,
            "desc": desc,
            "magika": magika,
            "sf": sf,
            "count": n,
        }
        for (ext, mime, desc, magika, sf), n in seen.items()
    ]
    return (
        f"profiled {count} seeds as {len(records)} rows in {time.time() - start:.2f}s",
        records,
        count,
    )


def _harnesses(project, corpora: pathlib.Path):
    return [
        (f"{project}/{path.name[: -len(SUFFIX)]}", path)
        for path in sorted((corpora / project).rglob(f"*{SUFFIX}"))
    ]


def _nonempty_corpus(path: pathlib.Path) -> bool:
    """True if the zip has at least one seed with non-zero size."""
    try:
        with zipfile.ZipFile(path) as zf:
            return any(i.file_size > 0 for i in zf.infolist() if not i.is_dir())
    except zipfile.BadZipFile:
        return False


def _print_stats(n_projects: int, work: list) -> None:
    nonempty = sum(1 for _, path in work if _nonempty_corpus(path))
    print(
        f"{n_projects} projects, {len(work)} harnesses, "
        f"{nonempty} with non-empty seed corpora"
    )


def download(project, corpora: pathlib.Path):
    """Download seed-corpus zips for one project, retrying the whole attempt on error."""
    start = time.time()
    project_dir = corpora / project
    harnesses = _harnesses(project, corpora)
    if project_dir.is_dir():
        return (
            (
                f"{project}: {len(harnesses)} cached in {time.time() - start:.2f}s",
                harnesses,
            )
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
                        with RemoteZip(
                            f"{BASE}/{bucket}/{project}/{ver.text.strip()}"
                        ) as z:
                            for name in z.namelist():
                                if name.endswith(SUFFIX):
                                    z.extract(name, project_dir)
                        harnesses = _harnesses(project, corpora)
                        label = f"{len(harnesses)} seeds" if harnesses else "0 seeds"
                        return (
                            f"{project}: {label} in {time.time() - start:.2f}s",
                            harnesses,
                        )
            project_dir.mkdir(parents=True, exist_ok=True)
            return f"{project}: no build in {time.time() - start:.2f}s", []
        except Exception as exc:
            last_exc = exc
            if attempt < DOWNLOAD_RETRIES:
                time.sleep(min(2 ** (attempt - 1), 8))
    return f"{project}: error ({last_exc}) after {DOWNLOAD_RETRIES} tries", []


def discover(projects, corpora: pathlib.Path):
    """Find already-downloaded seed-corpus zips on disk."""
    work = []
    for project in sorted(set(projects)):
        work.extend(_harnesses(project, corpora))
    _print_stats(len(set(projects)), work)
    return work


# ---------------------------------------------------------------------------- observers

# Independent observers, in the order used to break ties. libmagic contributes its MIME type
# only. Its prose description is recorded in the profile but deliberately unused: measured as
# a fifth label it gains 145 confident verdicts and costs 12 points of precision, because
# `Composite Document File V2 Document, ...` describes the *container* and so fuses every
# OLE2-based format into one identity.
OBSERVERS = ("ext", "mime", "magika", "sf")

SOURCE = {
    "ext": "filename",
    "mime": "libmagic",
    "magika": "magika",
    "sf": "siegfried",
}

# Per observer, the outputs that mean "I have nothing to say". This is a null list, not a
# format mapping: it says which outputs are silence, not what any format is.
SILENT = {
    "ext": {""},
    "mime": {
        "",
        "application/octet-stream",
        "application/x-empty",
        "inode/x-empty",
        "text/plain",
        "(timeout)",
    },
    "magika": {"", "unknown", "undefined", "empty", "txt"},
    "sf": {"", "UNKNOWN", "Plain Text File", "Binary File", "Data File"},
}

# ---------------------------------------------------------------------------- thresholds
# Values fixed by measurement; ALGORITHM.md records what each one was measured against.

THETA = 0.40  # how strongly two labels must predict each other to be one format
MIN_PAIR = 3  # ...over at least this many seeds carrying both
MIN_PROJ = 1  # ...seen in at least this many projects
NAME_FLOOR = 0.50  # fraction of a label's appearances that must co-occur with its strongest linked partner before it may name that format
PURITY = 0.80  # dominant share among a harness's confirmed seeds
MIN_CONFIRMED = 2  # confirmed seeds needed to claim a format
MIN_SHARE = 0.05  # ...covering this share of the corpus
MULTI_FLOOR = 0.15  # minority share needed to count as a second format
MULTI_MIN_SEEDS = 2  # ...and this many seeds
MULTI_MASS = 0.50  # confirmed share of the corpus before "several formats" is a claim
MIN_SEEDS_MULTI = 8  # below this, "several formats" is not a claim the data supports
UNVERIFIED_MASS = (
    0.50  # corpus a lone observer must have seen before its word is reported
)


# ---------------------------------------------------------------------------- loading


def ingest(
    record: dict,
    per: dict[str, collections.Counter],
    seeds: collections.Counter,
) -> None:
    """Fold one profile record into the per-harness evidence counters."""
    key = record["key"]
    n = record.get("count", 1)
    per[key][tuple(record.get(o, "") for o in OBSERVERS)] += n
    seeds[key] += n


def load(
    path: pathlib.Path,
) -> tuple[dict[str, collections.Counter], collections.Counter]:
    """Read the profile into per-harness counts of distinct evidence tuples.

    Records may carry a ``count``, since identical evidence recurs across a corpus and
    the profile step collapses it. A record without one describes one seed.

    Returns a tuple of two dictionaries:
    - per: a dictionary of harnesses, each with a counter of evidence tuples
    - seeds: a counter of seeds by harness
    """
    per: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    seeds: collections.Counter = collections.Counter()
    with open(path) as fh:
        for line in fh:
            ingest(json.loads(line), per, seeds)
    return dict(per), seeds


def spoken(evidence: tuple[str, ...]) -> list[tuple[str, str]]:
    """The labels this seed actually carries, as (observer, output) pairs.

    Drops signals from observers reporting an "I have nothing to say" signal.
    """
    return [
        (o, value) for o, value in zip(OBSERVERS, evidence) if value not in SILENT[o]
    ]


# ---------------------------------------------------------------------------- identities


def link_labels(
    per: dict[str, collections.Counter[tuple[str, ...]]],
) -> tuple[
    dict[tuple[str, str], set[tuple[str, str]]],
    dict[tuple[str, str], int],
    dict[int, list[tuple[str, str]]],
    dict[int, tuple[str, str]],
]:
    """Group labels that denote the same format, using only where they land.

    Individual identifications are often wrong, so no single seed is trusted. What is
    trusted is that a *systematic* relationship shows up across the corpus: if ``.tif``
    and ``image/tiff`` name one format, then among the seeds where both the filename and
    libmagic spoke, nearly every ``.tif`` is ``image/tiff`` and nearly every
    ``image/tiff`` is ``.tif``. Random misidentifications scatter and never reach that
    bar; only a real alias does.

    Conditioning on "both observers spoke" is what makes this work. Most ``.xml`` seeds
    are plain text to libmagic, so an unconditional rate would reject the pair; among the
    seeds libmagic did recognise, the agreement is overwhelming.

    Note what is *not* needed. Genericness is derived rather than listed: ``.bin`` links
    to nothing because it predicts no single format, so it drops out on its own.
    """
    pair: collections.Counter = collections.Counter()
    # Seeds where this label appeared and some other observer also spoke. The denominator
    # has to be per other-observer, or a tool that is often silent looks like a mismatch.
    cospoke: collections.Counter = collections.Counter()
    projects: dict[tuple, set[str]] = collections.defaultdict(set)
    total: collections.Counter = collections.Counter()

    for key, evidence in per.items():
        project = key.split("/")[0]
        for tuple_, n in evidence.items():
            labels = spoken(tuple_)
            for label in labels:
                total[label] += n
            for i, a in enumerate(labels):
                for j, b in enumerate(labels):
                    if i != j:
                        cospoke[(a, b[0])] += n
                for b in labels[i + 1 :]:
                    edge = (a, b) if a < b else (b, a)
                    pair[edge] += n
                    if MIN_PROJ > 1:
                        projects[edge].add(project)

    candidates: dict[tuple, float] = {}
    for (a, b), n in pair.items():
        if n < MIN_PAIR or (MIN_PROJ > 1 and len(projects[(a, b)]) < MIN_PROJ):
            continue
        seen_a, seen_b = cospoke[(a, b[0])], cospoke[(b, a[0])]
        if not seen_a or not seen_b:
            continue
        strength = min(n / seen_a, n / seen_b)
        if strength >= THETA:
            candidates[(a, b)] = strength

    # A label may keep only its strongest partner within each other observer. Without this,
    # one systematically wrong tool bridges two real formats: libmagic calls Solidity
    # sources JavaScript often enough (0.42) to clear the threshold, which would fuse
    # `.sol`/solidity into `.js`/javascript. `application/javascript` prefers `.js` by a
    # wide margin, so requiring the preference to be mutual drops that edge and keeps the
    # correct `.sol`~solidity one. It also makes THETA far less critical.
    best: dict[tuple, dict[str, tuple[float, tuple]]] = collections.defaultdict(dict)
    for (a, b), strength in candidates.items():
        for label, other in ((a, b), (b, a)):
            if strength > best[label].get(other[0], (0.0, None))[0]:
                best[label][other[0]] = (strength, other)

    links: dict[tuple, set[tuple]] = collections.defaultdict(set)
    for a, b in candidates:
        if best[a][b[0]][1] == b and best[b][a[0]][1] == a:
            links[a].add(b)
            links[b].add(a)

    # Components. Single linkage is safe only because the relation above is that strict:
    # measured on the corpus it yields 320 small near-cliques of 2 to 6 labels.
    identity: dict[tuple, int] = {}
    members: dict[int, list[tuple]] = {}
    for start in links:
        if start in identity:
            continue
        cid = len(members)
        group: list[tuple] = []
        stack = [start]
        while stack:
            label = stack.pop()
            if label in identity:
                continue
            identity[label] = cid
            group.append(label)
            stack.extend(l for l in links[label] if l not in identity)
        members[cid] = sorted(group)

    # Name each identity. The component *is* the identity, so any member would serve, but
    # the commonest one alone picks bad names: magika calls FBX files AutoHotkey, and
    # `autohotkey` outnumbers every other member of that class. A label earns the right to
    # name a class by tightly tracking at least one linked partner — the share of its
    # appearances that co-occur with its strongest neighbour. That rejects scattershot
    # labels without rewarding polysemous hubs that touch many members of a bridged
    # component. Among those that clear the floor, the commonest wins, which keeps
    # `application/json` from being named after glTF.
    def specificity(label):
        inside = max(
            pair[(label, other) if label < other else (other, label)]
            for other in links[label]
        )
        return inside / total[label]

    naming = {}
    for cid, group in members.items():
        specific = [l for l in group if specificity(l) >= NAME_FLOOR] or group
        naming[cid] = max(specific, key=lambda l: (total[l], l))
    return links, identity, members, naming


# ---------------------------------------------------------------------------- the algorithm


def confirmed_counts(evidence, links, identity):
    """Count, per format identity, the seeds two observers independently agree on.

    Agreement is required *on the same seed*. Comparing one observer's majority with
    another's is what lets a tool's false positives on a few dozen seeds corroborate an
    unrelated majority elsewhere in the corpus.
    """
    confirmed: collections.Counter = collections.Counter()
    for tuple_, n in evidence.items():
        labels = spoken(tuple_)
        # Two outputs of one tool are not two opinions: they fail together.
        found = {
            identity[a]
            for i, a in enumerate(labels)
            for b in labels[i + 1 :]
            if SOURCE[a[0]] != SOURCE[b[0]] and b in links.get(a, ())
        }
        # More than one identity on a single seed means the relation was too conservative
        # (`.o` against `.so`, `.xlsm` against `.xlsx`); such seeds carry no clear vote.
        if len(found) == 1:
            confirmed[found.pop()] += n
    return confirmed


def observer_views(evidence):
    """Per observer, what it said and how much of the corpus it saw. Fallback evidence
    only: this is one tool's unchecked word."""
    views: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    for tuple_, n in evidence.items():
        for label in spoken(tuple_):
            views[label[0]][label] += n
    return views


def decide(evidence, n, links, identity, members, naming):
    """Classify one harness: single / multi / single_unverified / ambiguous / unknown."""
    if not n:
        return {"verdict": "unknown", "format": None, "reason": "empty corpus", "n": 0}

    confirmed = confirmed_counts(evidence, links, identity)
    identified = sum(confirmed.values())

    if identified:
        top, count = confirmed.most_common(1)[0]

        # Several formats? A sample-size question, and one that only the confirmed seeds
        # can answer, so it is asked before any single-format claim.
        rivals = [
            cid
            for cid, c in confirmed.items()
            if c >= MULTI_MIN_SEEDS and c / identified >= MULTI_FLOOR
        ]
        if n >= MIN_SEEDS_MULTI and len(rivals) >= 2 and identified / n >= MULTI_MASS:
            rivals.sort(key=lambda cid: -confirmed[cid])
            return {
                "verdict": "multi",
                "format": None,
                "formats": [naming[cid][1] for cid in rivals],
                "reason": f"{len(rivals)} formats each ≥{MULTI_FLOOR:.0%} of confirmed seeds",
                "n": n,
            }

        if (
            count / identified >= PURITY
            and count >= min(MIN_CONFIRMED, n)
            and count / n >= MIN_SHARE
        ):
            observer, label = naming[top]
            return {
                "verdict": "single",
                "format": label,
                "observer": observer,
                "aliases": [f"{o}:{l}" for o, l in members[top]],
                "sources": sorted({SOURCE[o] for o, _ in members[top]}),
                "reason": "two observers agree on the same seeds",
                "confirmed": count,
                "purity": round(count / identified, 3),
                "share": round(count / n, 3),
                "n": n,
            }

        # Confirmed seeds exist but neither multi nor single clears its bar. Do not fall
        # through to a one-observer claim: that path is only for corpora with no
        # corroboration at all.
        return {
            "verdict": "ambiguous",
            "format": None,
            "reason": "no format dominates the confirmed seeds",
            "n": n,
        }

    # Nothing corroborated. One observer may still be worth reporting, but only if what it
    # said is a label the corpus recognises elsewhere: a label that never links to
    # anything is a tool's private noise, not a format.
    views = observer_views(evidence)
    for observer in OBSERVERS:
        counts = views.get(observer)
        if not counts:
            continue
        seen = sum(counts.values())
        label, count = counts.most_common(1)[0]
        if count / seen >= PURITY and seen / n >= UNVERIFIED_MASS and label in identity:
            cid = identity[label]
            return {
                "verdict": "single_unverified",
                "format": label[1],
                "observer": observer,
                "aliases": [f"{o}:{l}" for o, l in members[cid]],
                "sources": [SOURCE[observer]],
                "reason": f"only {SOURCE[observer]} identified it",
                "purity": round(count / seen, 3),
                "mass": round(seen / n, 3),
                "n": n,
            }

    return {
        "verdict": "unknown",
        "format": None,
        "reason": "no two observers agree on any seed",
        "n": n,
    }


def identify(
    per: dict[str, collections.Counter],
    seeds: collections.Counter,
    outdir: pathlib.Path,
):
    """Decide the input format of each harness from its profiled seed corpus.

    Writes ``identified.json``, ``formats.json``, and ``mapped_formats.json`` under
    ``outdir``. See ``ALGORITHM.md`` for the reasoning.
    """

    start = time.time()
    links, identity, members, naming = link_labels(per)
    print(
        f"related {len(identity)} labels into {len(members)} format identities "
        f"in {time.time() - start:.1f}s"
    )

    start = time.time()
    identified = {
        key: decide(evidence, seeds[key], links, identity, members, naming)
        for key, evidence in sorted(per.items())
    }
    print(f"classified {len(identified)} harnesses in {time.time() - start:.1f}s")

    formats = [
        {
            "format": naming[cid][1],
            "observer": naming[cid][0],
            "aliases": [f"{o}:{l}" for o, l in members[cid]],
        }
        for cid in sorted(members, key=lambda c: (naming[c][1], naming[c][0]))
    ]
    # Identities claimed by at least one single / single_unverified harness.
    # Match via aliases: single_unverified stores the observer's own label as
    # ``format``, which may differ from the identity's canonical name.
    alias_to_cid = {f"{o}:{l}": cid for cid, mems in members.items() for o, l in mems}
    mapped_cids = set()
    for v in identified.values():
        if v.get("verdict") not in ("single", "single_unverified"):
            continue
        for alias in v.get("aliases") or ():
            cid = alias_to_cid.get(alias)
            if cid is not None:
                mapped_cids.add(cid)
                break
    mapped_formats = [
        {
            "format": naming[cid][1],
            "observer": naming[cid][0],
            "aliases": [f"{o}:{l}" for o, l in members[cid]],
        }
        for cid in sorted(mapped_cids, key=lambda c: (naming[c][1], naming[c][0]))
    ]
    (outdir / "identified.json").write_text(json.dumps(identified, indent=2))
    (outdir / "formats.json").write_text(json.dumps(formats, indent=2))
    (outdir / "mapped_formats.json").write_text(json.dumps(mapped_formats, indent=2))

    counts = collections.Counter(v["verdict"] for v in identified.values())
    total = max(1, len(identified))
    for verdict in ("single", "multi", "single_unverified", "ambiguous", "unknown"):
        print(f"  {verdict:<18}{counts[verdict]:>6} ({counts[verdict] / total:>4.0%})")
    print(
        f"wrote {outdir / 'identified.json'}, {outdir / 'formats.json'}, "
        f"{outdir / 'mapped_formats.json'} ({len(mapped_formats)} mapped)"
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--max-projects", type=int, default=None)
    parser.add_argument(
        "--outdir",
        type=pathlib.Path,
        default=ROOT / "data",
        help="directory for seed_corpora/, raw_seeds.jsonl, and results",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=max(1, (os.cpu_count() or 8) // 8),
        help="parallel harnesses (each one drives several tool subprocesses)",
    )
    parser.add_argument(
        "--steps",
        nargs="+",
        default=["download", "profile", "identify"],
        choices=["download", "profile", "identify"],
    )
    args = parser.parse_args()

    outdir = args.outdir.resolve()
    outdir.mkdir(parents=True, exist_ok=True)
    corpora = outdir / "seed_corpora"
    raw = outdir / "raw_seeds.jsonl"
    corpora.mkdir(parents=True, exist_ok=True)

    projects = sorted(
        p.name for p in (ROOT / "oss-fuzz" / "projects").iterdir() if p.is_dir()
    )
    if args.max_projects is not None:
        projects = projects[: args.max_projects]

    work = []
    if "download" in args.steps:
        print(f"downloading seed corpora for {len(projects)} projects...")
        start = time.time()
        skipped = 0
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(os.cpu_count(), 32) or 8
        ) as pool:
            futures = {pool.submit(download, p, corpora): p for p in projects}
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

    if not work:
        work = discover(projects, corpora)
    else:
        _print_stats(len(projects), work)

    per = None
    seeds = None
    if "profile" in args.steps:
        if not MAGIKA:
            sys.exit("magika not installed")
        if not SF:
            sys.exit("siegfried not installed")
        print("profiling with file, magika, siegfried")
        start, n_seeds = time.time(), 0
        per = collections.defaultdict(collections.Counter)
        seeds = collections.Counter()
        with (
            raw.open("w") as raw_f,
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
                raw_f.writelines(json.dumps(r) + "\n" for r in records)
                for r in records:
                    ingest(r, per, seeds)
                n_seeds += count
                print(f"[{done}/{len(work)}] {key}: {line}")
        print(
            f"profiled {n_seeds} seeds from {len(work)} harnesses in {time.time() - start:.2f}s"
        )
        print(f"wrote {raw}")
        per = dict(per)

    if "identify" in args.steps:
        start = time.time()
        if per is None or seeds is None:
            if not raw.exists():
                raise SystemExit(f"{raw} not found; run the profile step first")
            per, seeds = load(raw)
            print(
                f"loaded {sum(seeds.values())} seeds from {len(per)} harnesses "
                f"in {time.time() - start:.1f}s"
            )
        else:
            print(
                f"using {sum(seeds.values())} seeds from {len(per)} harnesses "
                f"(in memory)"
            )
        identify(per, seeds, outdir)


if __name__ == "__main__":
    main()
