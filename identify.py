#!/usr/bin/env python3
"""Decide the input format of each fuzz harness from its profiled seed corpus.

Reads ``raw_seeds.jsonl`` (produced by ``extract_seed_corpora.py``) and writes
``identified.json`` plus ``formats.json``. See ``ALGORITHM.md`` for the reasoning; in short:

  * Every tool output is an opaque symbol. The code never inspects, splits or rewrites a
    label, and contains no table of formats. The only knowledge it holds is which outputs
    mean "I have nothing to say".
  * Two labels denote the same format when they land on the same seeds: restricted to the
    seeds where both observers spoke, each label predicts the other. Connected components
    of that relation are the format identities.
  * A seed is confirmed when two independent observers put linked labels on *it*, not on
    some other seed. A harness is confident when one identity dominates its confirmed
    seeds.

Usage: python3 identify.py [--raw PATH]
"""

from __future__ import annotations

import argparse
import collections
import json
import pathlib
import time

ROOT = pathlib.Path(__file__).resolve().parent
RAW = ROOT / "raw_seeds.jsonl"

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


def load(
    path: pathlib.Path,
) -> tuple[dict[str, collections.Counter], collections.Counter]:
    """Read the profile into per-harness counts of distinct evidence tuples.

    Records may carry a ``count``, since identical evidence recurs across a corpus and
    ``extract_seed_corpora.py`` collapses it. A record without one describes one seed.

    Returns a tuple of two dictionaries:
    - per: a dictionary of harnesses, each with a counter of evidence tuples
    - seeds: a counter of seeds by harness
    """
    per: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    seeds: collections.Counter = collections.Counter()
    with open(path) as fh:
        for line in fh:
            r = json.loads(line)
            key = r["key"]
            n = r.get("count", 1)
            per[key][tuple(r.get(o, "") for o in OBSERVERS)] += n
            seeds[key] += n
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


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--raw", type=pathlib.Path, default=RAW)
    args = parser.parse_args()
    if not args.raw.exists():
        raise SystemExit(f"{args.raw} not found; run extract_seed_corpora.py first")

    start = time.time()
    per, seeds = load(args.raw)
    print(
        f"loaded {sum(seeds.values())} seeds from {len(per)} harnesses "
        f"in {time.time() - start:.1f}s"
    )

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

    confident = sorted(
        {v["format"] for v in identified.values() if v["verdict"] == "single"}
    )
    formats = [
        {
            "format": naming[cid][1],
            "observer": naming[cid][0],
            "aliases": [f"{o}:{l}" for o, l in members[cid]],
        }
        for cid in sorted(members, key=lambda c: (naming[c][1], naming[c][0]))
    ]
    (ROOT / "identified.json").write_text(json.dumps(identified, indent=2))
    (ROOT / "formats.json").write_text(json.dumps(formats, indent=2))

    counts = collections.Counter(v["verdict"] for v in identified.values())
    total = max(1, len(identified))
    for verdict in ("single", "multi", "single_unverified", "ambiguous", "unknown"):
        print(f"  {verdict:<18}{counts[verdict]:>6} ({counts[verdict] / total:>4.0%})")
    print(f"{len(confident)} distinct formats in the confident list")
    print("wrote identified.json, formats.json")


if __name__ == "__main__":
    main()
