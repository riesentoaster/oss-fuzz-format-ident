"""
  python3 export_format_harnesses.py mapping-deep.yaml \
      data/identified.json manual_identified.json -o harnesses-deep.yaml
"""

import argparse
import json
import sys

import yaml

ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
ap.add_argument("mapping", help="YAML: list of {ext, format?, cluster_name?} entries")
ap.add_argument("identified", nargs="+", help="identified / manual JSON files")
ap.add_argument("-o", "--output", help="write YAML here (default: stdout)")
args = ap.parse_args()

with open(args.mapping) as file:
    mapping = yaml.safe_load(file)
merged = {}
for path in args.identified:
    with open(path) as file:
        merged.update(json.load(file))

# Build alias → canonical format from identified entries.
# single: ``format`` is the identity name. single_unverified: ``format`` is the
# observer's own label — only use it when no single already named the identity.
alias_to_cluster = {}
by_ext = {}
for e in merged.values():
    if e.get("verdict") != "single":
        continue
    cluster = e["format"]
    for a in e.get("aliases") or ():
        alias_to_cluster[a] = cluster
        if a.startswith("ext:"):
            by_ext.setdefault(a, set()).add(cluster)
for e in merged.values():
    if e.get("verdict") != "single_unverified":
        continue
    als = e.get("aliases") or ()
    cluster = next((alias_to_cluster[a] for a in als if a in alias_to_cluster), None)
    if cluster is None:
        cluster = e["format"]
    for a in als:
        alias_to_cluster.setdefault(a, cluster)
        if a.startswith("ext:"):
            by_ext.setdefault(a, set()).add(cluster)

cluster_to_fmt = {}
grouped = {}
for m in mapping:
    ext = m["ext"]
    if isinstance(ext, float):  # YAML ``.7`` → 0.7
        name = str(ext).split(".", 1)[1]  # → "7"
        ext = None
    else:
        name = str(ext).lstrip(".")
        ext = name
    hits = by_ext.get(f"ext:{ext}", set()) if ext else set()
    if len(hits) > 1:
        sys.exit(f"{name!r} maps to multiple clusters: {sorted(hits)}")
    if len(hits) == 1:
        cluster = next(iter(hits))
    elif "cluster_name" in m:
        cn = json.loads(m["cluster_name"])
        cluster = cn["format"]
        for a in cn.get("aliases") or ():
            alias_to_cluster[a] = cluster
    else:
        sys.exit(f"cannot map {name!r}")
    cluster_to_fmt[cluster] = name
    grouped[name] = []

for key, entry in sorted(merged.items()):
    if entry.get("verdict") not in ("single", "single_unverified"):
        continue
    cluster = None
    for alias in entry.get("aliases") or ():
        cluster = alias_to_cluster.get(alias)
        if cluster is not None:
            break
    if cluster is None:
        cluster = entry.get("format")  # manuals with no aliases
    fmt = cluster_to_fmt.get(cluster)
    if fmt is None:
        continue
    project, harness = key.split("/", 1)
    grouped[fmt].append((project, harness))


def q(s):
    return json.dumps(s) if any(c in s for c in " :#{}[]&*?|>!'\"%@`") else s


lines = ["formats:"]
for fmt, entries in grouped.items():
    lines.append(f"  {q(fmt)}:")
    for project, harness in entries:
        lines.append(f"    - project: {q(project)}")
        lines.append(f"      harness: {q(harness)}")
    lines.append("")
text = "\n".join(lines)

if args.output:
    with open(args.output, "w") as file:
        file.write(text)
else:
    sys.stdout.write(text)
